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
//!
//! ## Kasme derivation
//!
//! Kasme is derived via `crate::kdf::derive_kasme` (TS 33.401 Annex A.2),
//! which needs the serving network identity (PLMN) and SQN ⊕ AK as inputs
//! on top of CK/IK. PLMN comes from the S1AP `tai` field on
//! `InitialUeMessage` (TAI = PLMN(3) ‖ TAC(2)) — captured in `start_attach`
//! and stored on `AttachContext`. SQN ⊕ AK is computed in
//! `handle_security_mode_complete` from `ctx.sqn_used` and `ctx.ak`, both
//! also captured in `start_attach`.

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
use crate::kdf::derive_kasme;
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
///
/// `tai` is the S1AP Tracking Area Identity (PLMN(3) ‖ TAC(2)) — the first
/// 3 bytes are the serving network PLMN, stored on `AttachContext` for the
/// Kasme KDF call in `handle_security_mode_complete`.
pub fn start_attach(
    world:          &mut World,
    registry:       &mut ImsiRegistry,
    hss:            &mut Hss,
    enb_ue_s1ap_id: u32,
    nas_pdu:        &[u8],
    tai:            [u8; 5],
) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
    let plmn = [tai[0], tai[1], tai[2]];

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
        ak:           auth_info.vector.ak,
        plmn,
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
/// NAS security activates here: Kasme is derived from CK/IK + PLMN +
/// SQN ⊕ AK via `crate::kdf::derive_kasme` (TS 33.401 Annex A.2), NAS
/// session keys are derived from Kasme for [`SELECTED_EEA`]/[`SELECTED_EIA`]
/// (the pair already advertised in SecurityModeCommand), and AttachAccept —
/// the first message sent after this point — goes out as a protected
/// envelope rather than plain NAS.
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

    let mut sqn_xor_ak = [0u8; 6];
    for i in 0..6 {
        sqn_xor_ak[i] = ctx.sqn_used[i] ^ ctx.ak[i];
    }
    let kasme = derive_kasme(&ctx.ck, &ctx.ik, &ctx.plmn, &sqn_xor_ak);
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
