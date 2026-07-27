// crates/midn-core/src/amf/registration.rs
//! 5G Registration procedure — 3GPP TS 23.502 §4.2.2.
//!
//! Called by `Amf::process_ngap`; mirrors `mme::attach`'s per-step handler
//! shape exactly — same "free functions taking granular `&mut` refs, not
//! methods on the top-level struct" pattern, same step-by-step doc table.
//! Real differences from LTE attach, and where each one is modeled:
//!
//!   - SUCI instead of a plain IMSI on the wire — `resolve_suci_to_imsi`
//!     below, only the null-scheme (unprotected) case is de-concealed.
//!   - 5G-AKA instead of EPS-AKA — same Milenage f1-f5 primitives from
//!     `midn_auth` (via `Hss`, reused as-is — see "AUSF/UDM
//!     simplification" below), different KDF chain on top
//!     (`midn_core::kdf::{derive_kausf, derive_kseaf, derive_kamf}`
//!     instead of `derive_kasme`).
//!   - RES* (16 bytes) instead of RES (8 bytes) as the challenge response,
//!     with its own derivation step (`midn_core::kdf::derive_res_star`) —
//!     the network computes XRES* itself rather than trusting a value the
//!     UE never has to reproduce.
//!   - RegistrationAccept goes out via `DownlinkNasTransport`, not
//!     `InitialContextSetupRequest` — see "Phase A vs Phase B" below.
//!
//! ## AUSF/UDM simplification
//!
//! Real 5G splits authentication across three network functions (AMF/SEAF,
//! AUSF, UDM) talking over the Service-Based Interface — the AMF never
//! sees XRES* directly, it forwards HXRES* comparison and defers final
//! confirmation to the AUSF. This simulation collapses all three into the
//! AMF directly: one `Hss` (same subscriber DB a UE would use over 4G or
//! 5G, same K/OPc), no separate HXRES*/RES* forwarding hop. This is an
//! architectural topology simplification, not a fabricated cryptographic
//! constant — every KDF actually run is the real TS 33.501 Annex A
//! construction (see `midn_core::kdf` module doc for the confidence
//! breakdown on each one). Known consequence: `Amf` owns its own `Hss`,
//! separate from `Mme`'s — a subscriber has to be provisioned into both if
//! a scenario ever runs LTE and 5G side by side. Flagging this as a real
//! limitation, not glossing over it.
//!
//! ## Phase A vs Phase B
//!
//! `ngap::messages` module doc already flagged this split before this
//! increment existed: `InitialContextSetupRequest`/`Response` field names
//! were pre-shaped for "Phase B, next increment." This increment (Phase A)
//! sends RegistrationAccept via `DownlinkNasTransport` — no PDU session, no
//! TEID, no UPF interaction, matching this module's own doc ("PDU Session
//! Establishment is separate from Registration") and matching NGAP codec
//! support (`InitialContextSetupRequest` has no PER codec yet — see
//! `ngap::codec` module doc). Phase B adds the ICSR-based variant once
//! that codec support exists — same two-step sequencing `mme` itself went
//! through (Phase 2 `DownlinkNasTransport`-only, then Phase 3
//! `InitialContextSetupRequest` + TEID/UPF).
//!
//! ## Step mapping
//!
//! | Step | Trigger NAS/NGAP PDU               | Handler                         |
//! |------|-------------------------------------|----------------------------------|
//! | 1    | InitialUeMessage(RegistrationReq)  | `start_registration`            |
//! | 2    | UplinkNas(IdentityResponse)        | `handle_identity_response`      |
//! | 3    | UplinkNas(AuthenticationResponse)  | `handle_auth_response`          |
//! | 4    | UplinkNas(SecurityModeComplete)    | `handle_security_mode_complete` |
//! | 5    | UplinkNas(RegistrationComplete)    | `handle_registration_complete`  |
//!
//! Tests live in `amf::state_machine`, not here — same split `mme` uses
//! (drive the flow through `Amf::process_ngap`/`Mme::process_s1ap`, not by
//! calling these free functions in isolation).

use midn_proto::nas5gs::{
    decode_nas5gs, encode_auth_request, encode_identity_request, encode_protected,
    encode_registration_accept, encode_sec_mode_cmd, Nas5gsPdu, Nas5gsSecurityContext,
    IDTYPE_SUCI, NAS5GS_SHT_INTEGRITY_CIPHERED,
};
use midn_proto::ngap::messages::{NgapDownlinkNasTransport, NgapMessage};

use crate::hss::Hss;
use crate::kdf::{derive_kamf, derive_kausf, derive_kseaf, derive_res_star, serving_network_name};
use midn_ecs::{AuthFailReason, AuthState, IdentityComponent, ImsiRegistry, Nas5gsAkaContext, World};

// ── constants ────────────────────────────────────────────────────────────────

/// Milenage's 2-byte Authentication Management Field — NOT the Access and
/// Mobility Function this whole module implements. Unfortunate spec-level
/// name collision, not something introduced here; named verbosely to keep
/// the two apart at every call site in this file.
const MILENAGE_AMF_FIELD: [u8; 2] = [0x80, 0x00];

/// NAS algorithm pair this simulation always selects for SecurityModeCommand
/// — same simplification `mme::attach::SELECTED_EEA`/`SELECTED_EIA` makes
/// for LTE, same raw values (2 = *EA2/*IA2). Stored as `u8` here, not the
/// LTE enum — `nas5gs` deliberately keeps algorithm IDs raw (see
/// `nas5gs::codec` module doc).
const SELECTED_NAS_CIPHER_ALG: u8 = 2;
const SELECTED_NAS_INTEGRITY_ALG: u8 = 2;

/// Default ABBA parameter — TS 24.501/33.501's own default value, used
/// whenever there's no real anti-bidding-down feature set to bind.
const DEFAULT_ABBA: [u8; 2] = [0x00, 0x00];

// ── Error type (mirrors mme::attach::AttachError) ───────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("unknown subscriber IMSI {0}")]
    UnknownSubscriber(u64),
    #[error("no registration context for entity {0}")]
    NoContext(u32),
    #[error("RES* verification failed")]
    ResStarVerifyFailed,
    #[error("NAS decode failed")]
    NasDecode,
    #[error("protected SUCI de-concealment not implemented")]
    ProtectedSuciNotSupported,
}

// ── SUCI resolution ─────────────────────────────────────────────────────────

/// Resolve a null-scheme SUCI to the IMSI this simulation's `Hss` is keyed
/// by. Real de-concealment only applies to protected SUCIs (protection
/// scheme != 0) — a null-scheme SUCI already carries its SUPI/IMSI in the
/// clear (TS 33.501 §6.12.2), no ECIES needed. This project's `Suci`
/// fields are flat opaque bytes rather than real BCD-packed digits (see
/// `nas5gs::codec` module doc), so "in the clear" here means: MSIN's 5
/// bytes ARE the IMSI, big-endian, zero-extended to 64 bits. MCC/MNC are
/// carried but not folded in — this simulation's `Hss` is keyed on a flat
/// `u64` with no enforced MCC/MNC/MSIN substructure, same as everywhere
/// else IMSI appears in this codebase.
fn resolve_suci_to_imsi(suci: &midn_proto::nas5gs::Suci) -> Option<u64> {
    if suci.protection_scheme != 0 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf[3..8].copy_from_slice(&suci.msin);
    Some(u64::from_be_bytes(buf))
}

/// Constant-time 16-byte comparison for RES* verification. Small
/// self-contained helper rather than a new `subtle` crate dependency for
/// `midn-core` — `midn_auth::MilenageContext::verify_res` is fixed at 8
/// bytes (LTE's RES width) and can't be reused directly for 5G-AKA's
/// 16-byte RES*.
fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Build a placeholder 5G-GUTI to hand back in RegistrationAccept. Real
/// GUTI allocation (AMF Region ID / Set ID / Pointer, TS 23.003 §2.10) is
/// out of scope — same minimalism `mme::attach::handle_security_mode_complete`
/// already applies to LTE's GUTI (it just doesn't send one at all, passing
/// `None`; 5G's `encode_registration_accept` takes a mandatory `&[u8; 11]`
/// rather than `Option`, so this builds a deterministic stand-in instead of
/// leaving the field meaningless). Byte 0 carries the real
/// `[spare|type=5G-GUTI]` tag (see `nas5gs::codec` module doc on why that
/// matters for round-tripping); the entity id rides in the last 4 bytes so
/// different subscribers at least get visibly different GUTIs.
fn placeholder_guti(amf_ue_ngap_id: u32) -> [u8; 11] {
    let mut guti = [0u8; 11];
    guti[0] = midn_proto::nas5gs::IDTYPE_5G_GUTI;
    guti[7..11].copy_from_slice(&amf_ue_ngap_id.to_be_bytes());
    guti
}

// ── Step 1: RegistrationRequest ─────────────────────────────────────────────

/// Process an `InitialUeMessage` whose NAS PDU is a `RegistrationRequest`.
///
/// This message shape only carries a GUTI (optional) — no SUCI field (see
/// `nas5gs::messages::RegistrationRequest` doc). A fresh subscriber (no
/// GUTI — the only case this simulation resolves to an IMSI) always needs
/// an `IdentityRequest` round trip before authentication can start — same
/// "GUTI-based re-registration not supported" simplification
/// `mme::attach::start_attach` already makes for LTE's GUTI-attach case.
/// Unlike LTE (where IMSI arrives directly in AttachRequest), the IMSI
/// here isn't known until Step 2's SUCI resolves — so `ImsiRegistry`
/// registration happens in `handle_identity_response`, not here.
///
/// `tai` is the NGAP Tracking Area Identity (PLMN(3) ‖ 5GS-TAC(3) — 5G's
/// TAC is one octet wider than LTE's, see `nas5gs::messages` doc). The
/// first 3 bytes are the serving network PLMN, captured here and threaded
/// through every step up to `handle_security_mode_complete`.
pub fn start_registration(
    world: &mut World,
    ran_ue_ngap_id: u32,
    nas_pdu: &[u8],
    tai: [u8; 6],
) -> Vec<NgapMessage> {
    let plmn = [tai[0], tai[1], tai[2]];

    let guti = match decode_nas5gs(nas_pdu) {
        Ok(Nas5gsPdu::RegistrationRequest(inner)) => inner.guti,
        _ => {
            tracing::warn!("start_registration: NAS decode failed or wrong PDU type");
            return vec![];
        }
    };

    if guti.is_some() {
        tracing::warn!("start_registration: GUTI-based re-registration not supported (no SUCI on the wire)");
        return vec![];
    }

    // Spawn now — IMSI isn't known yet, but amf_ue_ngap_id (== the entity
    // id) needs to exist so the gNodeB has something to correlate the rest
    // of the procedure against.
    let amf_ue_ngap_id = world.spawn();
    world.insert_identity(amf_ue_ngap_id, IdentityComponent {
        imsi: 0, // filled in once IdentityResponse resolves a real SUCI
        enb_ue_s1ap_id: ran_ue_ngap_id, // see IdentityComponent doc — reused field, protocol-agnostic concept
        ue_ip: [0; 4],
    });

    // Stash PLMN now — the rest of Nas5gsAkaContext gets filled in once
    // real AKA material exists (handle_identity_response).
    let mut aka = Nas5gsAkaContext::new_empty();
    aka.plmn = plmn;
    world.insert_security5g(amf_ue_ngap_id, aka);

    let nas = encode_identity_request(IDTYPE_SUCI);
    let dl = NgapMessage::DownlinkNasTransport(NgapDownlinkNasTransport {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu: nas,
    });
    vec![dl]
}

// ── Step 2: IdentityResponse ─────────────────────────────────────────────────

/// Resolve the SUCI, pull a 5G-AKA vector from the (collapsed AUSF/UDM)
/// `Hss`, compute XRES*, and issue AuthenticationRequest.
pub fn handle_identity_response(
    world: &mut World,
    registry: &mut ImsiRegistry,
    hss: &mut Hss,
    ran_ue_ngap_id: u32,
    amf_ue_ngap_id: u32,
    nas_pdu: &[u8],
) -> Vec<NgapMessage> {
    let suci = match decode_nas5gs(nas_pdu) {
        Ok(Nas5gsPdu::IdentityResponse(inner)) => match inner.suci {
            Some(suci) => suci,
            None => {
                tracing::warn!("handle_identity_response: no SUCI in IdentityResponse (GUTI/PEI identity not supported here)");
                return vec![];
            }
        },
        _ => {
            tracing::warn!("handle_identity_response: NAS decode failed or wrong PDU type");
            return vec![];
        }
    };

    let imsi = match resolve_suci_to_imsi(&suci) {
        Some(imsi) => imsi,
        None => {
            tracing::warn!("handle_identity_response: protected SUCI de-concealment not implemented");
            return vec![];
        }
    };

    let auth_info = match hss.generate_auth_vector(imsi) {
        Some(info) => info,
        None => {
            tracing::warn!(imsi, "handle_identity_response: unknown subscriber");
            return vec![];
        }
    };

    let plmn = match world.security5g(amf_ue_ngap_id) {
        Some(aka) => aka.plmn,
        None => {
            tracing::warn!(amf_ue_ngap_id, "handle_identity_response: no 5G-AKA context (spawned in start_registration)");
            return vec![];
        }
    };

    // AUTN = (SQN ⊕ AK) ∥ AMF ∥ MAC-A (16 bytes) — same Milenage construction LTE uses.
    let autn = auth_info.vector.autn(&auth_info.sqn_used, &MILENAGE_AMF_FIELD);

    let snn = serving_network_name(&plmn);
    let xres_star = derive_res_star(&auth_info.vector.ck, &auth_info.vector.ik, &snn, &auth_info.rand, &auth_info.vector.res);

    // Now that IMSI is known: register in ImsiRegistry, and update the
    // IdentityComponent placeholder from start_registration with the real
    // value.
    registry.register(imsi, amf_ue_ngap_id);
    world.insert_identity(amf_ue_ngap_id, IdentityComponent {
        imsi,
        enb_ue_s1ap_id: ran_ue_ngap_id,
        ue_ip: [0; 4],
    });

    world.insert_security5g(amf_ue_ngap_id, Nas5gsAkaContext {
        pending_rand: auth_info.rand,
        pending_xres_star: xres_star,
        ck: auth_info.vector.ck,
        ik: auth_info.vector.ik,
        ak: auth_info.vector.ak,
        plmn,
        sqn_used: auth_info.sqn_used,
    });
    world.set_auth_state(amf_ue_ngap_id, AuthState::ChallengeIssued);

    let nas = encode_auth_request(0, &auth_info.rand, &autn); // ngKSI = 0 for simulation
    let dl = NgapMessage::DownlinkNasTransport(NgapDownlinkNasTransport {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu: nas,
    });
    vec![dl]
}

// ── Step 3: AuthenticationResponse ──────────────────────────────────────────

/// Verify the UE's RES* against the network-computed XRES* and issue
/// SecurityModeCommand. Sent PLAIN — NAS security activates one message
/// later, at SecurityModeComplete, same activation point LTE uses (see
/// `mme::attach` and `nas5gs::security` module docs).
pub fn handle_auth_response(
    world: &mut World,
    ran_ue_ngap_id: u32,
    amf_ue_ngap_id: u32,
    nas_pdu: &[u8],
) -> Vec<NgapMessage> {
    let res_star = match decode_nas5gs(nas_pdu) {
        Ok(Nas5gsPdu::AuthenticationResponse(inner)) => inner.res_star,
        _ => {
            tracing::warn!("handle_auth_response: bad NAS PDU");
            return vec![];
        }
    };

    let xres_star = match world.security5g(amf_ue_ngap_id) {
        Some(aka) => aka.pending_xres_star,
        None => {
            tracing::warn!(amf_ue_ngap_id, "handle_auth_response: no 5G-AKA context");
            return vec![];
        }
    };

    let matched = ct_eq_16(&xres_star, &res_star);

    if let Some(aka) = world.security5g_mut(amf_ue_ngap_id) {
        aka.clear_pending_challenge();
    }

    if !matched {
        world.set_auth_state(amf_ue_ngap_id, AuthState::Failed(AuthFailReason::ResMismatch));
        tracing::warn!(amf_ue_ngap_id, "handle_auth_response: RES* mismatch");
        return vec![];
    }
    world.set_auth_state(amf_ue_ngap_id, AuthState::Authenticated);

    let nas = encode_sec_mode_cmd(
        SELECTED_NAS_CIPHER_ALG,
        SELECTED_NAS_INTEGRITY_ALG,
        0x2040, // replayed UE security capabilities — same placeholder value mme::attach uses
    );
    let dl = NgapMessage::DownlinkNasTransport(NgapDownlinkNasTransport {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu: nas,
    });
    vec![dl]
}

// ── Step 4: SecurityModeComplete ────────────────────────────────────────────

/// On SecurityModeComplete, derive the KAUSF → KSEAF → KAMF chain, activate
/// NAS security, and send a ciphered RegistrationAccept.
///
/// This is where the AUSF/UDM simplification (module doc) becomes concrete:
/// a real network would have derived KAUSF/KSEAF back in `handle_identity_
/// response` (they're UDM/AUSF-side artifacts, not AMF-side), forwarding
/// only KSEAF-derived material to the SEAF/AMF. This simulation derives the
/// whole chain right here instead, since there's no separate AUSF/UDM
/// component to hold it earlier. Doesn't change any of the KDF math, just
/// where in the procedure it happens.
///
/// Sent via `DownlinkNasTransport`, not `InitialContextSetupRequest` — see
/// module doc "Phase A vs Phase B."
pub fn handle_security_mode_complete(
    world: &mut World,
    ran_ue_ngap_id: u32,
    amf_ue_ngap_id: u32,
) -> Vec<NgapMessage> {
    let imsi = match world.identity(amf_ue_ngap_id) {
        Some(i) => i.imsi,
        None => {
            tracing::warn!(amf_ue_ngap_id, "handle_security_mode_complete: no identity component");
            return vec![];
        }
    };

    let (ck, ik, ak, plmn, sqn_used) = match world.security5g(amf_ue_ngap_id) {
        Some(aka) => (aka.ck, aka.ik, aka.ak, aka.plmn, aka.sqn_used),
        None => {
            tracing::warn!(amf_ue_ngap_id, "handle_security_mode_complete: no 5G-AKA context");
            return vec![];
        }
    };

    let sqn_xor_ak: [u8; 6] = core::array::from_fn(|i| sqn_used[i] ^ ak[i]);

    let snn = serving_network_name(&plmn);
    let kausf = derive_kausf(&ck, &ik, &snn, &sqn_xor_ak);
    let kseaf = derive_kseaf(&kausf, &snn);
    let supi = imsi.to_string().into_bytes();
    let kamf = derive_kamf(&kseaf, &supi, &DEFAULT_ABBA);

    if let Some(aka) = world.security5g_mut(amf_ue_ngap_id) {
        aka.clear_post_kamf();
    }

    let mut nas_security = Nas5gsSecurityContext::new(&kamf, SELECTED_NAS_CIPHER_ALG, SELECTED_NAS_INTEGRITY_ALG);

    let guti = placeholder_guti(amf_ue_ngap_id);
    let registration_accept_plain = encode_registration_accept(1, &guti, &[]);
    let registration_accept_nas = encode_protected(
        &mut nas_security, NAS5GS_SHT_INTEGRITY_CIPHERED, &registration_accept_plain,
    );

    world.set_nas_security5g(amf_ue_ngap_id, nas_security);

    let dl = NgapMessage::DownlinkNasTransport(NgapDownlinkNasTransport {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu: registration_accept_nas,
    });
    vec![dl]
}

// ── Step 5: RegistrationComplete ────────────────────────────────────────────

/// UE confirms registration — subscriber is now online. No response
/// required, mirrors `mme::attach::handle_attach_complete` exactly.
pub fn handle_registration_complete(
    _world: &mut World,
    amf_ue_ngap_id: u32,
) -> Vec<NgapMessage> {
    tracing::info!(amf_ue_ngap_id, "RegistrationComplete — subscriber online");
    vec![]
}
