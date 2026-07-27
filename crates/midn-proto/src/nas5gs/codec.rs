// crates/midn-proto/src/nas5gs/codec.rs
//! NAS-5GS message binary encoder/decoder — 3GPP TS 24.501.
//!
//! Implements the wire format for the registration procedure's critical
//! path — the 5G equivalent of `nas::codec`'s LTE attach procedure:
//!
//! ```text
//! UE  → AMF : RegistrationRequest
//! AMF → UE  : IdentityRequest
//! UE  → AMF : IdentityResponse        (SUCI)
//! AMF → UE  : AuthenticationRequest
//! UE  → AMF : AuthenticationResponse
//! AMF → UE  : SecurityModeCommand
//! UE  → AMF : SecurityModeComplete
//! AMF → UE  : RegistrationAccept
//! UE  → AMF : RegistrationComplete
//! UE→AMF / AMF→UE : DeregistrationRequest
//! AMF → UE  : DeregistrationAccept
//! ```
//!
//! ## Wire format — a real structural difference from NAS-EPS
//!
//! NAS-EPS (`nas::codec`) packs protocol discriminator + security header
//! type into ONE octet (4 bits each). NAS-5GS does **not** — TS 24.501 §9.7
//! gives the Extended Protocol Discriminator its own full octet. Confirmed
//! against real capture decodes (Wireshark `packet-nas_5gs.c` output), not
//! assumed from the NAS-EPS pattern:
//!
//! ```text
//! Octet 1     : Extended Protocol Discriminator (full octet) — 0x7E = 5GMM
//! Octet 2     : [spare (bits 5-8)] | [security header type (bits 1-4)]
//! Octet 3     : message type
//! Octets 4+   : IEs
//! ```
//!
//! Security-protected envelope — implemented below via `encode_protected`/
//! `decode_protected`, now that `nas5gs::security::Nas5gsSecurityContext`
//! exists:
//! ```text
//! Octet 1     : Extended Protocol Discriminator (0x7E)
//! Octet 2     : [spare] | [security header type, nonzero]
//! Octets 3-6  : MAC-I (4 bytes)
//! Octet 7     : NAS sequence number
//! Octets 8+   : inner plain 5GS NAS message (as above)
//! ```
//! One byte longer than NAS-EPS's equivalent 6-byte outer header — same
//! EPD-gets-its-own-octet reason as the plain-PDU header above. No
//! trailing "message type" octet in the OUTER header — that only appears
//! once, inside the inner plain message after decryption.
//!
//! `decode_nas5gs` still rejects anything with a nonzero security header
//! type — it only handles plain PDUs. Callers auto-detect a protected
//! envelope by security header type and route to `decode_protected`
//! instead, same pattern `nas::codec` uses.
//!
//! ## Message type octet values — confidence
//!
//! `MT_REGISTRATION_REQUEST` (0x41) and `MT_REGISTRATION_ACCEPT` (0x42) are
//! confirmed against real Wireshark packet decodes. The rest (identity,
//! authentication, security mode, deregistration, registration
//! complete/reject) are recalled from memory at moderate-high confidence —
//! same caveat `ngap::ie_ids` already carries in this codebase — verify
//! against TS 24.501 Table 9.7.1 or a real capture before this touches
//! anything beyond this crate's own self-consistent round-trip tests.
//!
//! ## IE encoding
//!
//! Reuses `nas::ie`'s generic LV primitives directly (TS 24.007 §11 — the
//! same byte-oriented IE convention 4G and 5G NAS both use; only NGAP/S1AP
//! use ASN.1 PER). Does NOT reuse `nas::ie::encode_imsi`/`decode_imsi` (5G
//! identity is SUCI/5G-GUTI, not BCD IMSI) or
//! `encode_security_algorithms`/`decode_security_algorithms` (those are
//! typed on `NasEeaAlgorithm`/`NasEiaAlgorithm`; `nas5gs::messages`
//! deliberately stores `nas_cipher_alg`/`nas_integrity_alg` as raw `u8`, so
//! this module packs/unpacks that byte itself — same bit layout, TS 33.501
//! §5.11 reuses the TS 33.401 algorithm identifier space).
//!
//! ## Modeled simplifications (documented, not silent)
//!
//! - **SUCI** encodes as a flat 15-byte concatenation
//!   (mcc‖mnc‖routing_indicator‖protection_scheme‖home_network_pki‖msin),
//!   not the real BCD-packed TS 23.003 §28.7.2 layout. `Suci` doesn't carry
//!   a SUPI-format bit either — always implies IMSI-format SUPI. That's a
//!   `nas5gs::messages::Suci` shape decision from the previous increment,
//!   not something this codec adds.
//! - **Mobile Identity type tag**: for GUTI, `[u8; 11]` already embeds its
//!   own leading `[spare(5b) | type(3b)]` byte per TS 24.501 (confirmed
//!   against capture: GUTI content is 10 bytes, the array is 11) — this
//!   codec treats those 11 bytes as opaque and doesn't decompose them
//!   further, same as `nas::codec`'s treatment of the LTE GUTI blob. SUCI
//!   and PEI aren't pre-tagged in their own struct fields, so this codec
//!   prepends the type-tag byte itself when building that IE's value.

use bytes::Bytes;
use crate::error::{ProtoError, Result};
use crate::nas::ie::{read_lv, write_lv};
use crate::nas5gs::messages::Suci;
use crate::nas5gs::security::Nas5gsSecurityContext;

// ── header constants ─────────────────────────────────────────────────────────

/// Extended Protocol Discriminator — 5GS Mobility Management (TS 24.007
/// §11.2.3.1a). Confirmed against real capture decodes.
pub const NAS5GS_MM_EPD: u8 = 0x7E;

// Security header type values (octet 2, low nibble) — TS 24.501 §9.7 reuses
// the same value space TS 24.301 §9.3.1 defines for NAS-EPS.
pub const NAS5GS_SHT_PLAIN: u8 = 0;
pub const NAS5GS_SHT_INTEGRITY: u8 = 1;
pub const NAS5GS_SHT_INTEGRITY_CIPHERED: u8 = 2;
pub const NAS5GS_SHT_INTEGRITY_NEW_CTX: u8 = 3;
pub const NAS5GS_SHT_INTEGRITY_CIPHERED_NEW_CTX: u8 = 4;

// ── message type constants (TS 24.501 Table 9.7.1) ───────────────────────────
// 0x41 / 0x42 confirmed against capture. Rest: moderate-high confidence,
// recalled from memory — see module doc.

pub const MT_REGISTRATION_REQUEST: u8 = 0x41; // confirmed
pub const MT_REGISTRATION_ACCEPT: u8 = 0x42; // confirmed
pub const MT_REGISTRATION_COMPLETE: u8 = 0x43;
pub const MT_REGISTRATION_REJECT: u8 = 0x44;
pub const MT_DEREGISTRATION_REQUEST: u8 = 0x45; // UE-originating — mirrors nas::codec's UE-only detach simplification
pub const MT_DEREGISTRATION_ACCEPT: u8 = 0x46; // UE-originating
pub const MT_AUTHENTICATION_REQUEST: u8 = 0x56;
pub const MT_AUTHENTICATION_RESPONSE: u8 = 0x57;
pub const MT_AUTHENTICATION_REJECT: u8 = 0x58;
pub const MT_IDENTITY_REQUEST: u8 = 0x5B;
pub const MT_IDENTITY_RESPONSE: u8 = 0x5C;
pub const MT_SECURITY_MODE_COMMAND: u8 = 0x5D;
pub const MT_SECURITY_MODE_COMPLETE: u8 = 0x5E;

/// Mobile Identity "type of identity" values (TS 24.501 Table 9.11.3.4.1) —
/// confirmed for SUCI/5G-GUTI against capture decode (see module doc). Made
/// `pub`, not just crate-internal — callers building an `IdentityRequest`
/// (e.g. `amf::registration`) need to reference these symbolically instead
/// of hardcoding magic numbers.
pub const IDTYPE_SUCI: u8 = 1;
pub const IDTYPE_5G_GUTI: u8 = 2;
pub const IDTYPE_PEI: u8 = 3; // catch-all for IMEI/IMEISV — see module doc

// ── top-level decode ──────────────────────────────────────────────────────────

/// Decoded NAS-5GS PDU. Mirrors `nas::codec::NasPdu`'s relationship to
/// `nas::messages::NasMessage` — kept separate from
/// `nas5gs::messages::Nas5gsMessage`'s shape structs rather than reusing
/// them directly, same precedent already established in this crate.
#[derive(Debug, Clone)]
pub enum Nas5gsPdu {
    RegistrationRequest(DecodedRegistrationRequest),
    IdentityRequest { identity_type: u8 },
    IdentityResponse(DecodedIdentityResponse),
    AuthenticationRequest(DecodedAuthenticationRequest),
    AuthenticationResponse(DecodedAuthenticationResponse),
    AuthenticationReject,
    SecurityModeCommand(DecodedSecurityModeCommand),
    SecurityModeComplete,
    RegistrationAccept(DecodedRegistrationAccept),
    RegistrationComplete,
    RegistrationReject { cause: u8 },
    DeregistrationRequest { switch_off: bool },
    DeregistrationAccept,
}

/// Parse a raw, PLAIN NAS-5GS PDU byte buffer (security header type 0).
///
/// Protected envelopes need `nas5gs::security` (not implemented yet) to
/// recover the inner plain bytes first — see module doc.
pub fn decode_nas5gs(buf: &[u8]) -> Result<Nas5gsPdu> {
    if buf.len() < 3 {
        return Err(ProtoError::TooShort { expected: 3, got: buf.len() });
    }
    let epd = buf[0];
    if epd != NAS5GS_MM_EPD {
        return Err(ProtoError::MalformedNas5gs {
            reason: "expected 5GS Mobility Management extended protocol discriminator 0x7E",
        });
    }
    let sht = buf[1] & 0x0F;
    if sht != NAS5GS_SHT_PLAIN {
        return Err(ProtoError::MalformedNas5gs {
            reason: "protected 5GS NAS not supported — nas5gs::security not implemented yet",
        });
    }
    let msg_type = buf[2];
    let body = &buf[3..];

    match msg_type {
        MT_REGISTRATION_REQUEST => decode_registration_request(body),
        MT_IDENTITY_REQUEST => decode_identity_request(body),
        MT_IDENTITY_RESPONSE => decode_identity_response(body),
        MT_AUTHENTICATION_REQUEST => decode_auth_request(body),
        MT_AUTHENTICATION_RESPONSE => decode_auth_response(body),
        MT_AUTHENTICATION_REJECT => Ok(Nas5gsPdu::AuthenticationReject),
        MT_SECURITY_MODE_COMMAND => decode_sec_mode_cmd(body),
        MT_SECURITY_MODE_COMPLETE => Ok(Nas5gsPdu::SecurityModeComplete),
        MT_REGISTRATION_ACCEPT => decode_registration_accept(body),
        MT_REGISTRATION_COMPLETE => Ok(Nas5gsPdu::RegistrationComplete),
        MT_REGISTRATION_REJECT => decode_registration_reject(body),
        MT_DEREGISTRATION_REQUEST => decode_deregistration_request(body),
        MT_DEREGISTRATION_ACCEPT => Ok(Nas5gsPdu::DeregistrationAccept),
        other => Err(ProtoError::UnknownGtpMsgType(other)),
    }
}

/// Build the 3-octet plain 5GS NAS header: EPD | [spare|SHT=plain] | msg type.
fn header(msg_type: u8) -> Vec<u8> {
    vec![NAS5GS_MM_EPD, NAS5GS_SHT_PLAIN, msg_type]
}

// ── Registration Request ──────────────────────────────────────────────────────

/// Decoded fields from a 5GS Registration Request.
#[derive(Debug, Clone)]
pub struct DecodedRegistrationRequest {
    pub registration_type: u8,
    pub ng_ksi: u8,
    /// 5G-GUTI, if the UE has one. This message shape models GUTI-based
    /// re-registration only; a fresh SUCI-based registration leaves this
    /// `None` and the SUCI travels via the follow-up `IdentityResponse`.
    pub guti: Option<[u8; 11]>,
    pub ue_security_cap: u16,
}

fn decode_registration_request(body: &[u8]) -> Result<Nas5gsPdu> {
    if body.is_empty() {
        return Err(ProtoError::TooShort { expected: 1, got: 0 });
    }
    // Octet: [ngKSI (bits 5-8, high nibble)] | [5GS registration type (bits 1-4, low nibble)]
    let registration_type = body[0] & 0x07;
    let ng_ksi = (body[0] >> 4) & 0x07;
    let rest = &body[1..];

    // 5GS Mobile Identity — LV. Empty means "not provided" — see field doc.
    let (identity_bytes, rest) = read_lv(rest)
        .ok_or(ProtoError::MalformedNas5gs { reason: "missing 5GS mobile identity" })?;
    let guti = if identity_bytes.len() == 11 {
        let mut g = [0u8; 11];
        g.copy_from_slice(identity_bytes);
        Some(g)
    } else {
        None
    };

    // UE security capability — LV, 2 bytes.
    let ue_security_cap = if let Some((cap, _)) = read_lv(rest) {
        if cap.len() >= 2 { u16::from_be_bytes([cap[0], cap[1]]) } else { 0 }
    } else {
        0
    };

    Ok(Nas5gsPdu::RegistrationRequest(DecodedRegistrationRequest {
        registration_type, ng_ksi, guti, ue_security_cap,
    }))
}

/// Encode a 5GS Registration Request (used by mock UE in tests).
pub fn encode_registration_request(
    registration_type: u8,
    ng_ksi: u8,
    guti: Option<&[u8; 11]>,
    ue_security_cap: u16,
) -> Bytes {
    let mut buf = header(MT_REGISTRATION_REQUEST);
    buf.push(((ng_ksi & 0x07) << 4) | (registration_type & 0x07));
    match guti {
        Some(g) => write_lv(&mut buf, g),
        None => write_lv(&mut buf, &[]),
    }
    write_lv(&mut buf, &ue_security_cap.to_be_bytes());
    Bytes::from(buf)
}

// ── Identity Request / Response ───────────────────────────────────────────────

fn decode_identity_request(body: &[u8]) -> Result<Nas5gsPdu> {
    if body.is_empty() {
        return Err(ProtoError::TooShort { expected: 1, got: 0 });
    }
    // Octet: [spare (bits 5-8)] | [type of identity requested (bits 1-4)]
    let identity_type = body[0] & 0x0F;
    Ok(Nas5gsPdu::IdentityRequest { identity_type })
}

/// Encode a 5GS Identity Request (used by mock AMF in tests).
pub fn encode_identity_request(identity_type: u8) -> Bytes {
    let mut buf = header(MT_IDENTITY_REQUEST);
    buf.push(identity_type & 0x0F);
    Bytes::from(buf)
}

/// Decoded fields from a 5GS Identity Response — exactly one of
/// `suci`/`guti`/`pei` is `Some`, matching whichever identity type the
/// preceding `IdentityRequest` asked for.
#[derive(Debug, Clone)]
pub struct DecodedIdentityResponse {
    pub suci: Option<Suci>,
    pub guti: Option<[u8; 11]>,
    pub pei: Option<Bytes>,
}

fn decode_identity_response(body: &[u8]) -> Result<Nas5gsPdu> {
    let (identity_bytes, _) = read_lv(body)
        .ok_or(ProtoError::MalformedNas5gs { reason: "missing 5GS mobile identity" })?;
    if identity_bytes.is_empty() {
        return Err(ProtoError::MalformedNas5gs { reason: "empty 5GS mobile identity" });
    }
    let id_type = identity_bytes[0] & 0x07;
    let mut suci = None;
    let mut guti = None;
    let mut pei = None;

    match id_type {
        IDTYPE_SUCI => {
            // byte 0 = [spare|type], then the 15-byte flat SUCI payload — see module doc.
            if identity_bytes.len() < 16 {
                return Err(ProtoError::MalformedNas5gs { reason: "SUCI payload too short" });
            }
            let v = &identity_bytes[1..16];
            suci = Some(Suci {
                mcc: [v[0], v[1], v[2]],
                mnc: [v[3], v[4], v[5]],
                routing_indicator: u16::from_be_bytes([v[6], v[7]]),
                protection_scheme: v[8],
                home_network_pki: v[9],
                msin: [v[10], v[11], v[12], v[13], v[14]],
            });
        }
        IDTYPE_5G_GUTI => {
            if identity_bytes.len() != 11 {
                return Err(ProtoError::MalformedNas5gs { reason: "5G-GUTI must be exactly 11 bytes" });
            }
            let mut g = [0u8; 11];
            g.copy_from_slice(identity_bytes);
            guti = Some(g);
        }
        _ => {
            // PEI (IMEI/IMEISV), or anything else this codec doesn't
            // distinguish further — carry the raw payload through.
            pei = Some(Bytes::copy_from_slice(&identity_bytes[1..]));
        }
    }

    Ok(Nas5gsPdu::IdentityResponse(DecodedIdentityResponse { suci, guti, pei }))
}

/// Encode a 5GS Identity Response carrying a SUCI (used by mock UE in tests).
pub fn encode_identity_response_suci(suci: &Suci) -> Bytes {
    let mut buf = header(MT_IDENTITY_RESPONSE);
    let mut identity = Vec::with_capacity(16);
    identity.push(IDTYPE_SUCI);
    identity.extend_from_slice(&suci.mcc);
    identity.extend_from_slice(&suci.mnc);
    identity.extend_from_slice(&suci.routing_indicator.to_be_bytes());
    identity.push(suci.protection_scheme);
    identity.push(suci.home_network_pki);
    identity.extend_from_slice(&suci.msin);
    write_lv(&mut buf, &identity);
    Bytes::from(buf)
}

/// Encode a 5GS Identity Response carrying a 5G-GUTI. `guti` must already
/// carry its own leading `[spare|type=2]` byte — see module doc.
pub fn encode_identity_response_guti(guti: &[u8; 11]) -> Bytes {
    let mut buf = header(MT_IDENTITY_RESPONSE);
    write_lv(&mut buf, guti);
    Bytes::from(buf)
}

/// Encode a 5GS Identity Response carrying a PEI (IMEI/IMEISV).
pub fn encode_identity_response_pei(pei: &[u8]) -> Bytes {
    let mut buf = header(MT_IDENTITY_RESPONSE);
    let mut identity = Vec::with_capacity(1 + pei.len());
    identity.push(IDTYPE_PEI);
    identity.extend_from_slice(pei);
    write_lv(&mut buf, &identity);
    Bytes::from(buf)
}

// ── Authentication Request / Response / Reject ────────────────────────────────

/// Decoded fields from a 5GS Authentication Request.
#[derive(Debug, Clone)]
pub struct DecodedAuthenticationRequest {
    pub ng_ksi: u8,
    pub rand: [u8; 16],
    pub autn: [u8; 16],
}

fn decode_auth_request(body: &[u8]) -> Result<Nas5gsPdu> {
    if body.is_empty() {
        return Err(ProtoError::TooShort { expected: 33, got: 0 });
    }
    let ng_ksi = (body[0] >> 4) & 0x07;
    let rest = &body[1..];

    let (rand_bytes, rest) = read_lv(rest)
        .ok_or(ProtoError::MalformedNas5gs { reason: "missing RAND" })?;
    if rand_bytes.len() != 16 {
        return Err(ProtoError::MalformedNas5gs { reason: "RAND must be exactly 16 bytes" });
    }
    let rand: [u8; 16] = rand_bytes.try_into().unwrap();

    let (autn_bytes, _) = read_lv(rest)
        .ok_or(ProtoError::MalformedNas5gs { reason: "missing AUTN" })?;
    if autn_bytes.len() != 16 {
        return Err(ProtoError::MalformedNas5gs { reason: "AUTN must be exactly 16 bytes" });
    }
    let autn: [u8; 16] = autn_bytes.try_into().unwrap();

    Ok(Nas5gsPdu::AuthenticationRequest(DecodedAuthenticationRequest { ng_ksi, rand, autn }))
}

/// Encode a 5GS Authentication Request (used by mock AMF in tests).
pub fn encode_auth_request(ng_ksi: u8, rand: &[u8; 16], autn: &[u8; 16]) -> Bytes {
    let mut buf = header(MT_AUTHENTICATION_REQUEST);
    buf.push((ng_ksi & 0x07) << 4);
    write_lv(&mut buf, rand);
    write_lv(&mut buf, autn);
    Bytes::from(buf)
}

/// Decoded fields from a 5GS Authentication Response. `res_star` is 16
/// bytes — see `nas5gs::messages` module doc for why this differs from
/// NAS-EPS's 8-byte RES.
#[derive(Debug, Clone)]
pub struct DecodedAuthenticationResponse {
    pub res_star: [u8; 16],
}

fn decode_auth_response(body: &[u8]) -> Result<Nas5gsPdu> {
    let (res_bytes, _) = read_lv(body)
        .ok_or(ProtoError::MalformedNas5gs { reason: "missing RES*" })?;
    if res_bytes.len() != 16 {
        return Err(ProtoError::MalformedNas5gs { reason: "RES* must be exactly 16 bytes" });
    }
    let res_star: [u8; 16] = res_bytes.try_into().unwrap();
    Ok(Nas5gsPdu::AuthenticationResponse(DecodedAuthenticationResponse { res_star }))
}

/// Encode a 5GS Authentication Response (used by mock UE in tests).
pub fn encode_auth_response(res_star: &[u8; 16]) -> Bytes {
    let mut buf = header(MT_AUTHENTICATION_RESPONSE);
    write_lv(&mut buf, res_star);
    Bytes::from(buf)
}

/// Encode a 5GS Authentication Reject (used by mock AMF in tests). No IEs —
/// header only, matching `Nas5gsMessage::AuthenticationReject`'s bare shape.
pub fn encode_auth_reject() -> Bytes {
    Bytes::from(header(MT_AUTHENTICATION_REJECT))
}

// ── Security Mode Command / Complete ──────────────────────────────────────────

/// Decoded fields from a 5GS Security Mode Command.
#[derive(Debug, Clone)]
pub struct DecodedSecurityModeCommand {
    pub nas_cipher_alg: u8,
    pub nas_integrity_alg: u8,
    pub replayed_ue_sec_cap: u16,
}

fn decode_sec_mode_cmd(body: &[u8]) -> Result<Nas5gsPdu> {
    if body.is_empty() {
        return Err(ProtoError::TooShort { expected: 1, got: 0 });
    }
    let nas_cipher_alg = (body[0] >> 4) & 0x0F;
    let nas_integrity_alg = body[0] & 0x0F;
    let rest = &body[1..];

    let replayed_ue_sec_cap = if let Some((cap, _)) = read_lv(rest) {
        if cap.len() >= 2 { u16::from_be_bytes([cap[0], cap[1]]) } else { 0 }
    } else {
        0
    };

    Ok(Nas5gsPdu::SecurityModeCommand(DecodedSecurityModeCommand {
        nas_cipher_alg, nas_integrity_alg, replayed_ue_sec_cap,
    }))
}

/// Encode a 5GS Security Mode Command (used by mock AMF in tests).
pub fn encode_sec_mode_cmd(nas_cipher_alg: u8, nas_integrity_alg: u8, replayed_ue_sec_cap: u16) -> Bytes {
    let mut buf = header(MT_SECURITY_MODE_COMMAND);
    buf.push(((nas_cipher_alg & 0x0F) << 4) | (nas_integrity_alg & 0x0F));
    write_lv(&mut buf, &replayed_ue_sec_cap.to_be_bytes());
    Bytes::from(buf)
}

/// Encode a 5GS Security Mode Complete (used by mock UE in tests).
pub fn encode_sec_mode_complete() -> Bytes {
    Bytes::from(header(MT_SECURITY_MODE_COMPLETE))
}

// ── Registration Accept / Complete / Reject ───────────────────────────────────

/// Decoded fields from a 5GS Registration Accept.
#[derive(Debug, Clone)]
pub struct DecodedRegistrationAccept {
    pub registration_result: u8,
    pub guti: [u8; 11],
    pub tai_list: Vec<[u8; 6]>,
}

fn decode_registration_accept(body: &[u8]) -> Result<Nas5gsPdu> {
    if body.is_empty() {
        return Err(ProtoError::TooShort { expected: 1, got: 0 });
    }
    let registration_result = body[0] & 0x07;
    let rest = &body[1..];

    let (guti_bytes, rest) = read_lv(rest)
        .ok_or(ProtoError::MalformedNas5gs { reason: "missing 5G-GUTI" })?;
    if guti_bytes.len() != 11 {
        return Err(ProtoError::MalformedNas5gs { reason: "5G-GUTI must be exactly 11 bytes" });
    }
    let mut guti = [0u8; 11];
    guti.copy_from_slice(guti_bytes);

    let (tai_bytes, _) = read_lv(rest)
        .ok_or(ProtoError::MalformedNas5gs { reason: "missing TAI list" })?;
    let mut tai_list = Vec::new();
    if !tai_bytes.is_empty() {
        // Octet 0: list type + count (mirrors nas::codec's attach_accept TAI
        // list encoding, 6-byte entries instead of 5 — see the 5G TAC width
        // note in nas5gs::messages).
        let mut rest = &tai_bytes[1..];
        while rest.len() >= 6 {
            let mut tai = [0u8; 6];
            tai.copy_from_slice(&rest[..6]);
            tai_list.push(tai);
            rest = &rest[6..];
        }
    }

    Ok(Nas5gsPdu::RegistrationAccept(DecodedRegistrationAccept {
        registration_result, guti, tai_list,
    }))
}

/// Encode a 5GS Registration Accept (used by mock AMF in tests).
pub fn encode_registration_accept(registration_result: u8, guti: &[u8; 11], tai_list: &[[u8; 6]]) -> Bytes {
    let mut buf = header(MT_REGISTRATION_ACCEPT);
    buf.push(registration_result & 0x07);
    write_lv(&mut buf, guti);

    if tai_list.is_empty() {
        write_lv(&mut buf, &[]);
    } else {
        let mut tai_bytes = vec![(tai_list.len() as u8).saturating_sub(1) | 0x18];
        for tai in tai_list { tai_bytes.extend_from_slice(tai); }
        write_lv(&mut buf, &tai_bytes);
    }

    Bytes::from(buf)
}

/// Encode a 5GS Registration Complete (used by mock UE in tests).
pub fn encode_registration_complete() -> Bytes {
    Bytes::from(header(MT_REGISTRATION_COMPLETE))
}

fn decode_registration_reject(body: &[u8]) -> Result<Nas5gsPdu> {
    if body.is_empty() {
        return Err(ProtoError::TooShort { expected: 1, got: 0 });
    }
    Ok(Nas5gsPdu::RegistrationReject { cause: body[0] })
}

/// Encode a 5GS Registration Reject (used by mock AMF in tests).
pub fn encode_registration_reject(cause: u8) -> Bytes {
    let mut buf = header(MT_REGISTRATION_REJECT);
    buf.push(cause);
    Bytes::from(buf)
}

// ── Deregistration Request / Accept ───────────────────────────────────────────
//
// Models the UE-originating direction only — same simplification
// `nas::codec` already makes for LTE detach (see that module's doc
// comment). Network-initiated deregistration would need distinct message
// type constants this codebase doesn't model yet.

fn decode_deregistration_request(body: &[u8]) -> Result<Nas5gsPdu> {
    if body.is_empty() {
        return Err(ProtoError::TooShort { expected: 1, got: 0 });
    }
    let switch_off = (body[0] & 0x01) != 0;
    Ok(Nas5gsPdu::DeregistrationRequest { switch_off })
}

/// Encode a 5GS Deregistration Request (used by mock UE in tests).
pub fn encode_deregistration_request(switch_off: bool) -> Bytes {
    let mut buf = header(MT_DEREGISTRATION_REQUEST);
    buf.push(switch_off as u8);
    Bytes::from(buf)
}

/// Encode a 5GS Deregistration Accept (used by mock AMF in tests).
pub fn encode_deregistration_accept() -> Bytes {
    Bytes::from(header(MT_DEREGISTRATION_ACCEPT))
}

// ── Security-protected envelope ───────────────────────────────────────────────

/// Wrap an already-built plain 5GS NAS message in a protected envelope
/// (AMF → UE direction — uses `Nas5gsSecurityContext::protect_downlink`).
///
/// `sht` should normally be [`NAS5GS_SHT_INTEGRITY_CIPHERED`]; use one of
/// the `*_NEW_CTX` variants for the first protected message sent
/// immediately after a new security context is established (mirrors TS
/// 24.301 §4.4.3's convention, which TS 24.501 §4.4.5 reuses).
pub fn encode_protected(ctx: &mut Nas5gsSecurityContext, sht: u8, inner_plain: &[u8]) -> Bytes {
    let protected = ctx.protect_downlink(inner_plain);
    let mut buf = Vec::with_capacity(7 + protected.payload.len());
    buf.push(NAS5GS_MM_EPD);
    buf.push(sht & 0x0F); // spare high nibble = 0
    buf.extend_from_slice(&protected.mac_i);
    buf.push((protected.count & 0xFF) as u8);
    buf.extend_from_slice(&protected.payload);
    Bytes::from(buf)
}

/// Unwrap a protected 5GS NAS envelope (UE → AMF direction — uses
/// `Nas5gsSecurityContext::unprotect_uplink`).
///
/// Returns the inner plain NAS bytes on success — feed those to
/// [`decode_nas5gs`] to get the actual `Nas5gsPdu`. Returns `None` on
/// integrity failure or a malformed/too-short buffer; never panics on
/// attacker input.
pub fn decode_protected(ctx: &mut Nas5gsSecurityContext, buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 7 { return None; }
    if buf[0] != NAS5GS_MM_EPD { return None; }
    let sht = buf[1] & 0x0F;
    if sht == NAS5GS_SHT_PLAIN { return None; } // plain — caller should use decode_nas5gs directly
    let mut mac_i = [0u8; 4];
    mac_i.copy_from_slice(&buf[2..6]);
    let seq_byte = buf[6];
    let ciphertext = &buf[7..];
    ctx.unprotect_uplink(seq_byte, mac_i, ciphertext)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// An 11-byte GUTI blob whose leading byte already carries the
    /// [spare|type=5G-GUTI] tag, matching what real wire bytes look like.
    fn test_guti() -> [u8; 11] {
        let mut g = [0xABu8; 11];
        g[0] = (g[0] & 0xF8) | IDTYPE_5G_GUTI;
        g
    }

    #[test]
    fn registration_request_round_trip_with_guti() {
        let guti = test_guti();
        let encoded = encode_registration_request(1, 3, Some(&guti), 0xF0F0);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::RegistrationRequest(d) => {
                assert_eq!(d.registration_type, 1);
                assert_eq!(d.ng_ksi, 3);
                assert_eq!(d.guti, Some(guti));
                assert_eq!(d.ue_security_cap, 0xF0F0);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn registration_request_round_trip_without_guti() {
        let encoded = encode_registration_request(1, 0, None, 0x00C0);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::RegistrationRequest(d) => assert_eq!(d.guti, None),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn identity_request_round_trip() {
        let encoded = encode_identity_request(IDTYPE_SUCI);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::IdentityRequest { identity_type } => assert_eq!(identity_type, IDTYPE_SUCI),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn identity_response_suci_round_trip() {
        let suci = Suci {
            mcc: [2, 3, 4],
            mnc: [1, 5, 0xF],
            routing_indicator: 0x1234,
            protection_scheme: 0,
            home_network_pki: 0,
            msin: [0x12, 0x34, 0x56, 0x78, 0x90],
        };
        let encoded = encode_identity_response_suci(&suci);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::IdentityResponse(d) => {
                assert_eq!(d.suci, Some(suci));
                assert_eq!(d.guti, None);
                assert!(d.pei.is_none());
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn identity_response_guti_round_trip() {
        let guti = test_guti();
        let encoded = encode_identity_response_guti(&guti);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::IdentityResponse(d) => assert_eq!(d.guti, Some(guti)),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn identity_response_pei_round_trip() {
        let pei = [0x35u8, 0x41, 0x03, 0x71, 0x76, 0x89, 0x02, 0x10];
        let encoded = encode_identity_response_pei(&pei);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::IdentityResponse(d) => assert_eq!(d.pei.as_deref(), Some(&pei[..])),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn auth_request_round_trip() {
        let rand = [0x11u8; 16];
        let autn = [0x22u8; 16];
        let encoded = encode_auth_request(5, &rand, &autn);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::AuthenticationRequest(d) => {
                assert_eq!(d.ng_ksi, 5);
                assert_eq!(d.rand, rand);
                assert_eq!(d.autn, autn);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn auth_response_round_trip_res_star_is_16_bytes() {
        let res_star = [0xAAu8; 16];
        let encoded = encode_auth_response(&res_star);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::AuthenticationResponse(d) => assert_eq!(d.res_star, res_star),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn auth_reject_decode() {
        let encoded = encode_auth_reject();
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        assert!(matches!(decoded, Nas5gsPdu::AuthenticationReject));
    }

    #[test]
    fn sec_mode_command_round_trip() {
        let encoded = encode_sec_mode_cmd(2, 2, 0xF0F0);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::SecurityModeCommand(d) => {
                assert_eq!(d.nas_cipher_alg, 2);
                assert_eq!(d.nas_integrity_alg, 2);
                assert_eq!(d.replayed_ue_sec_cap, 0xF0F0);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn sec_mode_complete_decode() {
        let encoded = encode_sec_mode_complete();
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        assert!(matches!(decoded, Nas5gsPdu::SecurityModeComplete));
    }

    #[test]
    fn registration_accept_round_trip_with_tai_list() {
        let guti = test_guti();
        let tai_list = [[0x00, 0x01, 0x02, 0x00, 0x10, 0x01], [0x00, 0x01, 0x02, 0x00, 0x10, 0x02]];
        let encoded = encode_registration_accept(1, &guti, &tai_list);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::RegistrationAccept(d) => {
                assert_eq!(d.registration_result, 1);
                assert_eq!(d.guti, guti);
                assert_eq!(d.tai_list, tai_list.to_vec());
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn registration_accept_round_trip_empty_tai_list() {
        let guti = test_guti();
        let encoded = encode_registration_accept(1, &guti, &[]);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::RegistrationAccept(d) => assert!(d.tai_list.is_empty()),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn registration_complete_decode() {
        let encoded = encode_registration_complete();
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        assert!(matches!(decoded, Nas5gsPdu::RegistrationComplete));
    }

    #[test]
    fn registration_reject_round_trip() {
        let encoded = encode_registration_reject(22);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::RegistrationReject { cause } => assert_eq!(cause, 22),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn deregistration_request_round_trip() {
        let encoded = encode_deregistration_request(true);
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        match decoded {
            Nas5gsPdu::DeregistrationRequest { switch_off } => assert!(switch_off),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn deregistration_accept_decode() {
        let encoded = encode_deregistration_accept();
        let decoded = decode_nas5gs(&encoded).expect("should decode");
        assert!(matches!(decoded, Nas5gsPdu::DeregistrationAccept));
    }

    #[test]
    fn decode_rejects_wrong_epd() {
        let bad = [0x02u8, 0x00, 0x41];
        assert!(decode_nas5gs(&bad).is_err());
    }

    #[test]
    fn decode_rejects_protected_sht() {
        let buf = [NAS5GS_MM_EPD, NAS5GS_SHT_INTEGRITY_CIPHERED, MT_REGISTRATION_REQUEST];
        assert!(decode_nas5gs(&buf).is_err());
    }

    #[test]
    fn decode_rejects_too_short() {
        assert!(decode_nas5gs(&[NAS5GS_MM_EPD, 0]).is_err());
    }

    // ── Protected envelope ──────────────────────────────────────────────────

    fn test_ctx() -> Nas5gsSecurityContext {
        Nas5gsSecurityContext::new_from_keys([0x2Bu8; 16], [0x2Bu8; 16], 2, 2)
    }

    #[test]
    fn protected_envelope_round_trip() {
        let mut amf_ctx = test_ctx();
        let mut ue_ctx = test_ctx();

        let plain = encode_registration_accept(1, &[0xABu8; 11], &[]);
        let envelope = encode_protected(&mut amf_ctx, NAS5GS_SHT_INTEGRITY_CIPHERED, &plain);

        assert_eq!(envelope[0], NAS5GS_MM_EPD);
        assert_eq!(envelope[1] & 0x0F, NAS5GS_SHT_INTEGRITY_CIPHERED);

        let recovered = decode_protected(&mut ue_ctx, &envelope).expect("valid MAC should verify");
        assert_eq!(recovered, plain.to_vec());

        match decode_nas5gs(&recovered) {
            Ok(Nas5gsPdu::RegistrationAccept(d)) => assert_eq!(d.registration_result, 1),
            other => panic!("wrong decoded variant: {other:?}"),
        }
    }

    #[test]
    fn protected_envelope_advances_counts_independently_per_direction() {
        let mut amf_ctx = test_ctx();
        let mut ue_ctx = test_ctx();

        let first = encode_protected(&mut amf_ctx, NAS5GS_SHT_INTEGRITY_CIPHERED, b"one");
        let second = encode_protected(&mut amf_ctx, NAS5GS_SHT_INTEGRITY_CIPHERED, b"two");
        assert_ne!(first, second, "COUNT must advance between messages");

        assert!(decode_protected(&mut ue_ctx, &first).is_some());
        assert!(decode_protected(&mut ue_ctx, &second).is_some());
    }

    #[test]
    fn decode_protected_rejects_tampered_envelope() {
        let mut amf_ctx = test_ctx();
        let mut ue_ctx = test_ctx();

        let mut envelope = encode_protected(&mut amf_ctx, NAS5GS_SHT_INTEGRITY_CIPHERED, b"hello").to_vec();
        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF; // flip a ciphertext bit

        assert!(decode_protected(&mut ue_ctx, &envelope).is_none());
    }

    #[test]
    fn decode_protected_rejects_plain_sht() {
        let mut ctx = test_ctx();
        let plain = encode_registration_complete();
        assert!(decode_protected(&mut ctx, &plain).is_none(), "plain SHT must route to decode_nas5gs, not decode_protected");
    }

    #[test]
    fn decode_protected_rejects_too_short() {
        let mut ctx = test_ctx();
        assert!(decode_protected(&mut ctx, &[NAS5GS_MM_EPD, NAS5GS_SHT_INTEGRITY_CIPHERED]).is_none());
    }
  }
