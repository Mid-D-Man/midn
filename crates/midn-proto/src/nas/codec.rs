// crates/midn-proto/src/nas/codec.rs
//! NAS message binary encoder/decoder for the LTE attach procedure.
//!
//! Implements the wire format of 3GPP TS 24.301 for the messages
//! required to complete a full UE attachment:
//!
//! ```text
//! UE → MME : AttachRequest
//! MME → UE : AuthenticationRequest
//! UE → MME : AuthenticationResponse
//! MME → UE : SecurityModeCommand
//! UE → MME : SecurityModeComplete
//! MME → UE : AttachAccept
//! UE → MME : AttachComplete
//! ```
//!
//! ## Wire format
//!
//! Plain (unsecured) NAS PDU:
//! ```text
//! Octet 1: 0x07  EPS Mobility Management, no security
//! Octet 2: message type
//! Octets 3+: IEs
//! ```
//!
//! ## Spec compliance note
//!
//! This implements the critical-path IEs needed for Phase 2. Optional IEs
//! and full bitfield packing per 3GPP TS 24.301 will be tightened in Phase 3
//! for real UE interop.

use bytes::Bytes;
use crate::error::{ProtoError, Result};
use crate::nas::ie::{
    decode_imsi, decode_security_algorithms, encode_imsi, encode_security_algorithms,
    find_tlv, read_lv, write_lv, write_tlv, NasEeaAlgorithm, NasEiaAlgorithm,
};

// ── NAS constants ─────────────────────────────────────────────────────────────

pub const NAS_EPS_MM_PD: u8     = 0x07; // Protocol Discriminator: EPS Mobility Management
pub const NAS_PLAIN_HEADER: u8  = 0x07; // First byte of unsecured EPS-MM PDU

// Message type identifiers (3GPP TS 24.301 Table 9.8.1)
pub const MT_ATTACH_REQUEST:          u8 = 0x41;
pub const MT_ATTACH_ACCEPT:           u8 = 0x42;
pub const MT_ATTACH_COMPLETE:         u8 = 0x43;
pub const MT_DETACH_REQUEST:          u8 = 0x45;
pub const MT_AUTHENTICATION_REQUEST:  u8 = 0x52;
pub const MT_AUTHENTICATION_RESPONSE: u8 = 0x53;
pub const MT_AUTHENTICATION_REJECT:   u8 = 0x54;
pub const MT_SECURITY_MODE_COMMAND:   u8 = 0x5D;
pub const MT_SECURITY_MODE_COMPLETE:  u8 = 0x5E;
pub const MT_SECURITY_MODE_REJECT:    u8 = 0x5F;

// IEI values for optional IEs in Attach Accept
const IEI_GUTI:     u8 = 0x50;
const IEI_APN:      u8 = 0x28;
const IEI_PDN_ADDR: u8 = 0x29;

// ── Top-level decode ──────────────────────────────────────────────────────────

/// Decoded NAS PDU — the parsed representation of a raw NAS byte buffer.
#[derive(Debug, Clone)]
pub enum NasPdu {
    AttachRequest(DecodedAttachRequest),
    AuthenticationRequest(DecodedAuthenticationRequest),
    AuthenticationResponse(DecodedAuthenticationResponse),
    SecurityModeCommand(DecodedSecurityModeCommand),
    SecurityModeComplete,
    AttachAccept(DecodedAttachAccept),
    AttachComplete,
}

/// Parse a raw NAS PDU byte buffer.
pub fn decode_nas(buf: &[u8]) -> Result<NasPdu> {
    if buf.len() < 2 {
        return Err(ProtoError::TooShort { expected: 2, got: buf.len() });
    }
    // Octet 1: security header type (high nibble) | protocol discriminator (low nibble)
    let pd  = buf[0] & 0x0F;
    let sht = (buf[0] >> 4) & 0x0F;
    if pd != (NAS_EPS_MM_PD & 0x0F) {
        return Err(ProtoError::MalformedNas { reason: "expected EPS-MM protocol discriminator 0x7" });
    }
    if sht != 0 {
        return Err(ProtoError::MalformedNas { reason: "protected NAS not supported in Phase 2" });
    }
    let msg_type = buf[1];
    let body     = &buf[2..];

    match msg_type {
        MT_ATTACH_REQUEST          => decode_attach_request(body),
        MT_AUTHENTICATION_REQUEST  => decode_auth_request(body),
        MT_AUTHENTICATION_RESPONSE => decode_auth_response(body),
        MT_SECURITY_MODE_COMMAND   => decode_sec_mode_cmd(body),
        MT_SECURITY_MODE_COMPLETE  => Ok(NasPdu::SecurityModeComplete),
        MT_ATTACH_ACCEPT           => decode_attach_accept(body),
        MT_ATTACH_COMPLETE         => Ok(NasPdu::AttachComplete),
        other => Err(ProtoError::UnknownGtpMsgType(other)),
    }
}

// ── Attach Request ────────────────────────────────────────────────────────────

/// Decoded fields from a NAS Attach Request.
#[derive(Debug, Clone)]
pub struct DecodedAttachRequest {
    pub eps_attach_type: u8,
    pub nas_ksi:         u8,
    /// Subscriber identity — IMSI if provided, else None (GUTI attach)
    pub imsi:            Option<u64>,
    pub ue_network_cap:  Vec<u8>,
}

fn decode_attach_request(body: &[u8]) -> Result<NasPdu> {
    if body.is_empty() {
        return Err(ProtoError::TooShort { expected: 3, got: 0 });
    }
    // Octet 3: [EPS Attach Type (3b)] | [spare (1b)] | [NAS KSI (3b)] | [spare (1b)]
    // Simplified: high nibble = NAS KSI, low nibble = attach type + spare
    let eps_attach_type = body[0] & 0x07;
    let nas_ksi         = (body[0] >> 4) & 0x07;
    let rest            = &body[1..];

    // Mobile Identity (IMSI or GUTI) — LV encoded
    let (identity_bytes, rest) = read_lv(rest)
        .ok_or(ProtoError::MalformedNas { reason: "missing mobile identity" })?;

    let imsi = decode_imsi(identity_bytes); // None if GUTI

    // UE Network Capability — LV encoded
    let ue_network_cap = if let Some((cap, _)) = read_lv(rest) {
        cap.to_vec()
    } else {
        vec![]
    };

    Ok(NasPdu::AttachRequest(DecodedAttachRequest {
        eps_attach_type, nas_ksi, imsi, ue_network_cap,
    }))
}

/// Encode a NAS Attach Request (used by mock UE in tests).
pub fn encode_attach_request(imsi: u64, eps_attach_type: u8, nas_ksi: u8) -> Bytes {
    let mut buf = vec![NAS_PLAIN_HEADER, MT_ATTACH_REQUEST];

    // Octet 3: NAS KSI | attach type
    buf.push(((nas_ksi & 0x07) << 4) | (eps_attach_type & 0x07));

    // Mobile Identity: IMSI as LV
    let imsi_bytes = encode_imsi(imsi);
    write_lv(&mut buf, &imsi_bytes);

    // UE Network Capability (minimal — just EEA2+EIA2 support)
    write_lv(&mut buf, &[0x20, 0x40]); // EEA2, EIA2 capability bits

    Bytes::from(buf)
}

// ── Authentication Request ────────────────────────────────────────────────────

/// Decoded fields from a NAS Authentication Request.
#[derive(Debug, Clone)]
pub struct DecodedAuthenticationRequest {
    pub nas_ksi: u8,
    pub rand:    [u8; 16],
    pub autn:    [u8; 16],
}

fn decode_auth_request(body: &[u8]) -> Result<NasPdu> {
    if body.len() < 1 {
        return Err(ProtoError::TooShort { expected: 35, got: body.len() });
    }
    let nas_ksi = (body[0] >> 4) & 0x07;
    let rest    = &body[1..];

    // RAND: LV, length = 16
    let (rand_bytes, rest) = read_lv(rest)
        .ok_or(ProtoError::MalformedNas { reason: "missing RAND" })?;
    if rand_bytes.len() != 16 {
        return Err(ProtoError::MalformedNas { reason: "RAND must be exactly 16 bytes" });
    }
    let rand: [u8; 16] = rand_bytes.try_into().unwrap();

    // AUTN: LV, length = 16
    let (autn_bytes, _) = read_lv(rest)
        .ok_or(ProtoError::MalformedNas { reason: "missing AUTN" })?;
    if autn_bytes.len() != 16 {
        return Err(ProtoError::MalformedNas { reason: "AUTN must be exactly 16 bytes" });
    }
    let autn: [u8; 16] = autn_bytes.try_into().unwrap();

    Ok(NasPdu::AuthenticationRequest(DecodedAuthenticationRequest { nas_ksi, rand, autn }))
}

/// Encode a NAS Authentication Request.
pub fn encode_auth_request(nas_ksi: u8, rand: &[u8; 16], autn: &[u8; 16]) -> Bytes {
    let mut buf = vec![NAS_PLAIN_HEADER, MT_AUTHENTICATION_REQUEST];

    // NAS KSI in high nibble, spare in low nibble
    buf.push((nas_ksi & 0x07) << 4);

    write_lv(&mut buf, rand);   // RAND: LV
    write_lv(&mut buf, autn);   // AUTN: LV

    Bytes::from(buf)
}

// ── Authentication Response ───────────────────────────────────────────────────

/// Decoded fields from a NAS Authentication Response.
#[derive(Debug, Clone)]
pub struct DecodedAuthenticationResponse {
    pub res: [u8; 8],
}

fn decode_auth_response(body: &[u8]) -> Result<NasPdu> {
    let (res_bytes, _) = read_lv(body)
        .ok_or(ProtoError::MalformedNas { reason: "missing RES" })?;
    if res_bytes.len() != 8 {
        return Err(ProtoError::MalformedNas { reason: "RES must be exactly 8 bytes" });
    }
    let res: [u8; 8] = res_bytes.try_into().unwrap();
    Ok(NasPdu::AuthenticationResponse(DecodedAuthenticationResponse { res }))
}

/// Encode a NAS Authentication Response (used by mock UE in tests).
pub fn encode_auth_response(res: &[u8; 8]) -> Bytes {
    let mut buf = vec![NAS_PLAIN_HEADER, MT_AUTHENTICATION_RESPONSE];
    write_lv(&mut buf, res);    // RES: LV
    Bytes::from(buf)
}

// ── Security Mode Command ─────────────────────────────────────────────────────

/// Decoded fields from a NAS Security Mode Command.
#[derive(Debug, Clone)]
pub struct DecodedSecurityModeCommand {
    pub eea: NasEeaAlgorithm,
    pub eia: NasEiaAlgorithm,
    pub nas_ksi: u8,
}

fn decode_sec_mode_cmd(body: &[u8]) -> Result<NasPdu> {
    if body.len() < 2 {
        return Err(ProtoError::TooShort { expected: 2, got: body.len() });
    }
    let (eea, eia) = decode_security_algorithms(body[0]);
    let nas_ksi    = (body[1] >> 4) & 0x07;
    Ok(NasPdu::SecurityModeCommand(DecodedSecurityModeCommand { eea, eia, nas_ksi }))
}

/// Encode a NAS Security Mode Command.
pub fn encode_sec_mode_cmd(
    eea: NasEeaAlgorithm,
    eia: NasEiaAlgorithm,
    nas_ksi: u8,
    ue_cap: &[u8],
) -> Bytes {
    let mut buf = vec![NAS_PLAIN_HEADER, MT_SECURITY_MODE_COMMAND];
    buf.push(encode_security_algorithms(eea, eia));  // selected algorithms
    buf.push((nas_ksi & 0x07) << 4);                // NAS KSI
    write_lv(&mut buf, ue_cap);                      // replayed UE security capabilities
    Bytes::from(buf)
}

/// Encode a NAS Security Mode Complete (used by mock UE in tests).
pub fn encode_sec_mode_complete() -> Bytes {
    Bytes::from(vec![NAS_PLAIN_HEADER, MT_SECURITY_MODE_COMPLETE])
}

// ── Attach Accept ─────────────────────────────────────────────────────────────

/// Decoded fields from a NAS Attach Accept.
#[derive(Debug, Clone)]
pub struct DecodedAttachAccept {
    pub attach_result: u8,
    pub t3412_value:   u8,
    pub guti:          Option<[u8; 10]>,
    pub ip_address:    Option<[u8; 4]>,
    pub apn:           Option<String>,
}

fn decode_attach_accept(body: &[u8]) -> Result<NasPdu> {
    if body.len() < 2 {
        return Err(ProtoError::TooShort { expected: 2, got: body.len() });
    }
    let attach_result = body[0] & 0x07;
    let t3412_value   = body[1];
    let rest          = &body[2..];

    let mut guti       = None;
    let mut ip_address = None;
    let mut apn        = None;

    // TAI list (mandatory LV, skip it)
    let rest = if let Some((_, r)) = read_lv(rest) { r } else { rest };

    // Parse optional TLV IEs
    let mut remaining = rest;
    while remaining.len() >= 2 {
        match remaining[0] {
            IEI_GUTI => {
                if let Some((_, val, r)) = find_tlv(remaining, IEI_GUTI)
                    .and_then(|s| crate::nas::ie::read_tlv(s))
                {
                    if val.len() == 10 {
                        let mut g = [0u8; 10];
                        g.copy_from_slice(val);
                        guti = Some(g);
                    }
                    remaining = r;
                } else { break; }
            }
            IEI_PDN_ADDR => {
                if let Some((_, val, r)) = crate::nas::ie::read_tlv(remaining) {
                    // PDN address: first byte = address type, then IP
                    if val.len() >= 5 && val[0] == 0x01 { // IPv4
                        let mut ip = [0u8; 4];
                        ip.copy_from_slice(&val[1..5]);
                        ip_address = Some(ip);
                    }
                    remaining = r;
                } else { break; }
            }
            IEI_APN => {
                if let Some((_, val, r)) = crate::nas::ie::read_tlv(remaining) {
                    apn = String::from_utf8(val.to_vec()).ok();
                    remaining = r;
                } else { break; }
            }
            _ => {
                // Unknown TLV: skip
                if remaining.len() < 2 { break; }
                let skip = remaining[1] as usize + 2;
                if remaining.len() < skip { break; }
                remaining = &remaining[skip..];
            }
        }
    }

    Ok(NasPdu::AttachAccept(DecodedAttachAccept {
        attach_result, t3412_value, guti, ip_address, apn
    }))
}

/// Encode a NAS Attach Accept.
pub fn encode_attach_accept(
    attach_result: u8,
    t3412_value:   u8,
    tai_list:      &[[u8; 5]],
    ip_address:    Option<[u8; 4]>,
    apn:           Option<&str>,
) -> Bytes {
    let mut buf = vec![NAS_PLAIN_HEADER, MT_ATTACH_ACCEPT];
    buf.push(attach_result & 0x07);
    buf.push(t3412_value);

    // TAI list (mandatory LV — write empty if none)
    if tai_list.is_empty() {
        write_lv(&mut buf, &[]);
    } else {
        let mut tai_bytes = vec![(tai_list.len() as u8 - 1) | 0x18]; // list type + count
        for tai in tai_list { tai_bytes.extend_from_slice(tai); }
        write_lv(&mut buf, &tai_bytes);
    }

    // Optional: PDN address (TLV, IEI = 0x29)
    if let Some(ip) = ip_address {
        let mut addr = vec![0x01u8]; // IPv4 type
        addr.extend_from_slice(&ip);
        write_tlv(&mut buf, IEI_PDN_ADDR, &addr);
    }

    // Optional: APN (TLV, IEI = 0x28)
    if let Some(apn_str) = apn {
        write_tlv(&mut buf, IEI_APN, apn_str.as_bytes());
    }

    Bytes::from(buf)
}

/// Encode a NAS Attach Complete (used by mock UE in tests).
pub fn encode_attach_complete() -> Bytes {
    Bytes::from(vec![NAS_PLAIN_HEADER, MT_ATTACH_COMPLETE])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_request_round_trip() {
        let rand = [0x23u8; 16];
        let autn = [0xAAu8; 16];
        let encoded = encode_auth_request(7, &rand, &autn);
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::AuthenticationRequest(d) => {
                assert_eq!(d.nas_ksi, 7);
                assert_eq!(d.rand, rand);
                assert_eq!(d.autn, autn);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn auth_response_round_trip() {
        let res = [0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF];
        let encoded = encode_auth_response(&res);
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::AuthenticationResponse(d) => {
                assert_eq!(d.res, res);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn attach_request_imsi_round_trip() {
        let imsi = 234_15_1234567890_u64;
        let encoded = encode_attach_request(imsi, 1, 7);
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::AttachRequest(d) => {
                assert_eq!(d.imsi, Some(imsi), "IMSI should round-trip");
                assert_eq!(d.eps_attach_type, 1);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn sec_mode_command_round_trip() {
        let ue_cap = [0x20u8, 0x40];
        let encoded = encode_sec_mode_cmd(
            NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2, 7, &ue_cap
        );
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::SecurityModeCommand(d) => {
                assert_eq!(d.eea, NasEeaAlgorithm::Eea2);
                assert_eq!(d.eia, NasEiaAlgorithm::Eia2);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn security_mode_complete_decode() {
        let encoded = encode_sec_mode_complete();
        let decoded = decode_nas(&encoded).expect("should decode");
        assert!(matches!(decoded, NasPdu::SecurityModeComplete));
    }

    #[test]
    fn attach_accept_with_ip() {
        let ip = [10u8, 0, 0, 1];
        let encoded = encode_attach_accept(1, 0x54, &[], Some(ip), Some("internet"));
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::AttachAccept(d) => {
                assert_eq!(d.ip_address, Some(ip));
                assert_eq!(d.apn.as_deref(), Some("internet"));
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn attach_complete_decode() {
        let encoded = encode_attach_complete();
        let decoded = decode_nas(&encoded).expect("should decode");
        assert!(matches!(decoded, NasPdu::AttachComplete));
    }

    #[test]
    fn decode_rejects_wrong_pd() {
        // Protocol discriminator = 0x05 (MM, not EPS-MM)
        let bad = [0x05u8, 0x52, 0x00];
        assert!(decode_nas(&bad).is_err());
    }
}
