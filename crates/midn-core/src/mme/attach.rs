// crates/midn-core/src/mme/attach.rs
//! EPS-AKA attach procedure — per-step handlers.
//!
//! Called by `Mme::process_s1ap`; each function returns
//! `(Vec<S1apMessage>, Vec<UpfEvent>)` to keep state_machine.rs flat.
//!
//! ## Step mapping
//!
//! | Step | Trigger NAS/S1AP PDU        | Handler                   |
//! |------|-----------------------------|---------------------------|
//! | 1    | InitialUEMessage(AttachReq) | `start_attach`            |
//! | 2    | UplinkNas(AuthResponse)     | `handle_auth_response`    |
//! | 3    | UplinkNas(SecModeComplete)  | `handle_sec_mode_complete`|
//! | 8    | UplinkNas(AttachComplete)   | `handle_attach_complete`  |
//!
//! Teardown (Detach) lives in `mme::detach`, not here.
//!
//! ## NAS security activation
//!
//! `handle_security_mode_complete` is also where NAS security activates —
//! see [`SELECTED_EEA`]/[`SELECTED_EIA`] and `nas::security` module docs for
//! the simplification (SecurityModeCommand/Complete stay plain; AttachAccept
//! is the first protected message).

use midn_auth::MilenageContext;
use midn_proto::nas::{
    decode_nas, encode_attach_accept, encode_auth_request, encode_protected,
    encode_sec_mode_cmd, NasEeaAlgorithm, NasEiaAlgorithm, NasPdu, NasSecurityContext,
    NAS_BEARER, SHT_INTEGRITY_CIPHERED,
};
use midn_proto::s1ap::{
    DownlinkNasTransport, ErabToSetup, InitialContextSetupRequest, S1apMessage,
};

use crate::hss::Hss;
use crate::mme::state_machine::{
    AttachContext, ImsiRegistry, SessionState, TeidAllocator, TunnelComponent, UpfEvent, World,
};

// ── AMF constant ──────────────────────────────────────────────────────────────

/// Authentication Management Field: bit 0 = 1 signals UMTS AKA (TS 33.102).
const AMF: [u8; 2] = [0x80, 0x00];

/// NAS algorithm pair this simulation always selects for SecurityModeCommand.
/// Real MMEs negotiate against the UE's network capability IE
/// (`ue_network_cap` in `DecodedAttachRequest`); this simulation ignores it
/// and always picks 128-EEA2/128-EIA2. `handle_security_mode_complete` reads
/// these same constants when deriving the NAS security context, since the
/// algorithm pair has to match what was actually advertised.
const SELECTED_EEA: NasEeaAlgorithm = NasEeaAlgorithm::Eea2;
const SELECTED_EIA: NasEiaAlgorithm = NasEiaAlgorithm::Eia2;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AttachError {
    #[error("unknown subscriber IMSI {0}")]
    UnknownSubscriber(u64),
    #[error("no attach context for entity {0}")]
    NoContext(u32),
    #[error("RES verification failed")]
    ResVerifyFailed,
    #[error("NAS decode failed")]
    NasDecode,
    #[error("IMSI not registered")]
    ImsiNotFound,
}

// ── Step 1: AttachRequest ─────────────────────────────────────────────────────

/// Process an `InitialUeMessage` whose NAS PDU is an `AttachRequest`.
pub fn start_attach(
    world:          &mut World,
    registry:       &mut ImsiRegistry,
    hss:            &mut Hss,
    enb_ue_s1ap_id: u32,
    nas_pdu:        &[u8],
) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
    // Decode AttachRequest from the NAS PDU.
    let (imsi, ue_ip): (u64, Option<[u8; 4]>) = match decode_nas(nas_pdu) {
        Ok(NasPdu::AttachRequest(inner)) => match inner.imsi {
            Some(imsi) => (imsi, None),
            None => {
                tracing::warn!("start_attach: GUTI attach not supported (no IMSI)");
                return (vec![], vec![]);
            }
        },
        _ => {
            tracing::warn!("start_attach: NAS decode failed or wrong PDU type");
            return (vec![], vec![]);
        }
    };

    let auth_info = match hss.generate_auth_vector(imsi) {
        Some(info) => info,
        None => {
            tracing::warn!(imsi, "start_attach: unknown subscriber");
            return (vec![], vec![]);
        }
    };

    // AUTN = (SQN ⊕ AK) ∥ AMF ∥ MAC-A  (16 bytes).
    let autn = auth_info.vector.autn(&auth_info.sqn_used, &AMF);

    // Spawn ECS entity and record IMSI → entity mapping.
    let entity = world.spawn();
    registry.register(imsi, entity);

    // Store per-UE attach state as an ECS component.
    world.insert_attach_context(entity, AttachContext {
        imsi,
        enb_ue_s1ap_id,
        mme_ue_s1ap_id: entity,
        rand:         auth_info.rand,
        xres:         auth_info.vector.res,
        ck:           auth_info.vector.ck,
        ik:           auth_info.vector.ik,
        sqn_used:     auth_info.sqn_used,
        ue_ip:        ue_ip.unwrap_or([0; 4]),
        ul_teid:      None,
        nas_security: None,
    });

    // Encode NAS AuthenticationRequest PDU (NAS KSI = 0 for simulation).
    let nas = encode_auth_request(0, &auth_info.rand, &autn);

    let dl = S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
        enb_ue_s1ap_id,
        mme_ue_s1ap_id: entity,
        nas_pdu: nas,
    });
    (vec![dl], vec![])
}

// ── Step 2: AuthenticationResponse ───────────────────────────────────────────

/// Verify the UE's RES against the stored XRES and issue SecurityModeCommand.
pub fn handle_auth_response(
    world:          &mut World,
    _registry:      &ImsiRegistry,   // carried for future use (e.g. GUTI re-auth lookup)
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    nas_pdu:        &[u8],
) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
    // Decode the NAS PDU.
    let res_arr: [u8; 8] = match decode_nas(nas_pdu) {
        Ok(NasPdu::AuthenticationResponse(inner)) => inner.res,
        _ => {
            tracing::warn!("handle_auth_response: bad NAS PDU");
            return (vec![], vec![]);
        }
    };

    // Look up the attach context.
    let ctx = match world.get_attach_context(mme_ue_s1ap_id) {
        Some(c) => c,
        None => {
            tracing::warn!(mme_ue_s1ap_id, "handle_auth_response: no context");
            return (vec![], vec![]);
        }
    };

    // Constant-time RES verification (f2 output vs UE response).
    if !MilenageContext::verify_res(&ctx.xres, &res_arr) {
        tracing::warn!(mme_ue_s1ap_id, "handle_auth_response: RES mismatch");
        return (vec![], vec![]);
    }

    // RES verified — issue SecurityModeCommand, proposing the algorithm pair
    // this simulation always selects. Sent PLAIN: NAS security activates one
    // message later, at SecurityModeComplete (see nas::security module docs
    // and handle_security_mode_complete below).
    let nas = encode_sec_mode_cmd(
        SELECTED_EEA,
        SELECTED_EIA,
        0,                // NAS KSI
        &[0x20, 0x40],    // replayed UE security capabilities
    );
    let dl = S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
        enb_ue_s1ap_id,
        mme_ue_s1ap_id,
        nas_pdu: nas,
    });
    (vec![dl], vec![])
}

// ── Step 3: SecurityModeComplete ─────────────────────────────────────────────

/// On SecurityModeComplete, allocate bearer resources and send AttachAccept.
///
/// NAS security activates here: Kasme is derived from CK/IK, NAS session
/// keys are derived from Kasme for [`SELECTED_EEA`]/[`SELECTED_EIA`] (the
/// pair already advertised in SecurityModeCommand), and AttachAccept — the
/// first message sent after this point — goes out as a protected envelope
/// rather than plain NAS.
pub fn handle_security_mode_complete(
    world:           &mut World,
    enb_ue_s1ap_id:  u32,
    mme_ue_s1ap_id:  u32,
    phase3_upf:      Option<[u8; 4]>,
    teid_allocator:  &mut TeidAllocator,
) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
    let ctx = match world.get_attach_context(mme_ue_s1ap_id) {
        Some(c) => c,
        None => {
            tracing::warn!(mme_ue_s1ap_id, "handle_sec_mode_complete: no context");
            return (vec![], vec![]);
        }
    };
    let imsi  = ctx.imsi;
    let ue_ip = ctx.ue_ip;

    let kasme = derive_kasme(&ctx.ck, &ctx.ik);
    let mut nas_security = NasSecurityContext::new(&kasme, SELECTED_EEA, SELECTED_EIA);

    let attach_accept_plain = encode_attach_accept(1, 0x54, &[], Some(ue_ip), None);
    let attach_accept_nas = encode_protected(
        &mut nas_security, SHT_INTEGRITY_CIPHERED, NAS_BEARER, &attach_accept_plain,
    );

    if let Some(_upf_addr) = phase3_upf {
        let ul_teid = teid_allocator.alloc();

        world.insert_attach_context(mme_ue_s1ap_id, AttachContext {
            ul_teid:      Some(ul_teid),
            nas_security: Some(nas_security),
            ..ctx
        });
        world.insert_session_state(mme_ue_s1ap_id, SessionState { imsi, ul_teid });
        world.insert_tunnel(mme_ue_s1ap_id, TunnelComponent {
            ul_teid,
            dl_teid: 0,
            enb_addr: [0; 4],
        });

        let icsr = S1apMessage::InitialContextSetupRequest(InitialContextSetupRequest {
            enb_ue_s1ap_id,
            mme_ue_s1ap_id,
            e_rabs: vec![ErabToSetup {
                erab_id:              5,
                qci:                  9,
                gtp_teid:             ul_teid.to_be_bytes(),
                transport_layer_addr: _upf_addr,
            }],
            nas_pdu: Some(attach_accept_nas),
            ue_ambr: (50_000_000, 50_000_000),
            security_key: kasme,
        });

        let evt = UpfEvent::CreateSession {
            ul_teid,
            entity_id: mme_ue_s1ap_id,
            imsi,
            ue_ip,
            enb_addr: [0; 4],
            qci: 9,
        };
        (vec![icsr], vec![evt])

    } else {
        world.insert_attach_context(mme_ue_s1ap_id, AttachContext {
            nas_security: Some(nas_security),
            ..ctx
        });
        let dl = S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
            enb_ue_s1ap_id,
            mme_ue_s1ap_id,
            nas_pdu: attach_accept_nas,
        });
        (vec![dl], vec![])
    }
}

// ── Step 8: AttachComplete ────────────────────────────────────────────────────

/// UE confirms attach — subscriber is now online. No response required.
pub fn handle_attach_complete(
    _world:         &mut World,
    mme_ue_s1ap_id: u32,
) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
    tracing::info!(mme_ue_s1ap_id, "AttachComplete — subscriber online");
    (vec![], vec![])
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Minimal Kasme derivation placeholder (CK ∥ IK).
/// Replace with TS 33.401 §A.2 KDF when hardening security.
///
/// `pub(crate)`: also called from `mme::state_machine`'s tests to
/// independently re-derive Kasme when simulating a UE-side protected NAS
/// envelope (mirrors what a real UE does — both sides compute Kasme from
/// CK/IK, which AKA gives identically to UE and network).
pub(crate) fn derive_kasme(ck: &[u8; 16], ik: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    key
            }
