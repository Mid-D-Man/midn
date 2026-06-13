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

use midn_auth::MilenageContext;
use midn_proto::nas::{
    decode_nas_pdu, encode_attach_accept, encode_authentication_request,
    encode_security_mode_command, NasPdu,
};
use midn_proto::s1ap::{
    DownlinkNasTransport, ErabToSetup, InitialContextSetupRequest, S1apMessage,
};

use crate::hss::Hss;
use crate::mme::state_machine::{
    AttachContext, ImsiRegistry, SessionState, TunnelComponent, UpfEvent, World,
};

// ── AMF constant ──────────────────────────────────────────────────────────────

/// Authentication Management Field: bit 0 = 1 signals UMTS AKA (TS 33.102).
const AMF: [u8; 2] = [0x80, 0x00];

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

/// Process an `InitialUEMessage` whose NAS PDU is an `AttachRequest`.
///
/// Spawns an ECS entity, fetches a Milenage auth vector from the HSS
/// (which generates RAND internally), constructs AUTN, stores the context,
/// and returns a `DownlinkNasTransport` carrying the `AuthenticationRequest`.
pub fn start_attach(
    world:          &mut World,
    registry:       &mut ImsiRegistry,
    hss:            &mut Hss,
    enb_ue_s1ap_id: u32,
    nas_pdu:        &[u8],
) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
    // Decode AttachRequest from the NAS PDU.
    let pdu = match decode_nas_pdu(nas_pdu) {
        Some(NasPdu::AttachRequest { imsi, ue_ip }) => (imsi, ue_ip),
        _ => {
            tracing::warn!("start_attach: NAS decode failed or wrong PDU type");
            return (vec![], vec![]);
        }
    };
    let (imsi, ue_ip) = pdu;

    // Fixed: was hss.get_auth_vector(imsi) — renamed to generate_auth_vector.
    // generate_auth_vector produces RAND via OS entropy internally and returns
    // it in HssAuthInfo.rand, so we no longer need to generate it here.
    let auth_info = match hss.generate_auth_vector(imsi) {
        Some(info) => info,
        None => {
            tracing::warn!(imsi, "start_attach: unknown subscriber");
            return (vec![], vec![]);
        }
    };

    // AUTN = (SQN ⊕ AK) ∥ AMF ∥ MAC-A  (16 bytes).
    // sqn_used is [u8; 6] in the new HssAuthInfo (was Sqn newtype previously).
    let autn = auth_info.vector.autn(&auth_info.sqn_used, &AMF);

    // Spawn ECS entity and record IMSI → entity mapping.
    let entity = world.spawn();
    registry.register(imsi, entity);

    // Store per-UE attach state as an ECS component.
    world.insert_attach_context(entity, AttachContext {
        imsi,
        enb_ue_s1ap_id,
        mme_ue_s1ap_id: entity,
        rand:     auth_info.rand,       // new field — directly available
        xres:     auth_info.vector.res,
        ck:       auth_info.vector.ck,
        ik:       auth_info.vector.ik,
        sqn_used: auth_info.sqn_used,   // [u8;6] — no .0 dereference needed
        ue_ip:    ue_ip.unwrap_or([0; 4]),
        ul_teid:  None,
    });

    // Encode NAS AuthenticationRequest PDU.
    let nas = encode_authentication_request(&auth_info.rand, &autn);

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
    registry:       &ImsiRegistry,
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    nas_pdu:        &[u8],
) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
    // Decode the NAS PDU.
    let res = match decode_nas_pdu(nas_pdu) {
        Some(NasPdu::AuthenticationResponse { res }) => res,
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
    let res_arr: [u8; 8] = match res.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            tracing::warn!("handle_auth_response: RES wrong length");
            return (vec![], vec![]);
        }
    };
    if !MilenageContext::verify_res(&ctx.xres, &res_arr) {
        tracing::warn!(mme_ue_s1ap_id, "handle_auth_response: RES mismatch");
        return (vec![], vec![]);
    }

    // RES verified — issue SecurityModeCommand (EEA2 + EIA2).
    let nas = encode_security_mode_command(ctx.ck, ctx.ik);
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
/// Phase 2: wraps AttachAccept in `DownlinkNasTransport`.
/// Phase 3: wraps AttachAccept in `InitialContextSetupRequest` with embedded
///          NAS PDU, and emits `UpfEvent::CreateSession`.
pub fn handle_security_mode_complete(
    world:           &mut World,
    enb_ue_s1ap_id:  u32,
    mme_ue_s1ap_id:  u32,
    phase3_upf:      Option<[u8; 4]>,
    teid_counter:    &mut u32,
) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
    let ctx = match world.get_attach_context(mme_ue_s1ap_id) {
        Some(c) => c,
        None => {
            tracing::warn!(mme_ue_s1ap_id, "handle_sec_mode_complete: no context");
            return (vec![], vec![]);
        }
    };
    let imsi   = ctx.imsi;
    let ue_ip  = ctx.ue_ip;

    // Encode AttachAccept NAS PDU (EPS bearer 5, default PDN address).
    let attach_accept_nas = encode_attach_accept(5, &ue_ip);

    if let Some(_upf_addr) = phase3_upf {
        // Phase 3: allocate UL TEID, create tunnel component, emit CreateSession.
        let ul_teid = *teid_counter;
        *teid_counter = teid_counter.wrapping_add(1);

        world.insert_attach_context(mme_ue_s1ap_id, AttachContext {
            ul_teid: Some(ul_teid),
            ..ctx
        });
        world.insert_session_state(mme_ue_s1ap_id, SessionState { imsi, ul_teid });
        world.insert_tunnel(mme_ue_s1ap_id, TunnelComponent {
            ul_teid,
            dl_teid: 0,           // placeholder; filled by handle_icsrsp
            enb_addr: [0; 4],     // placeholder; filled by handle_icsrsp
        });

        // Build InitialContextSetupRequest with AttachAccept embedded as nas_pdu.
        let icsr = S1apMessage::InitialContextSetupRequest(InitialContextSetupRequest {
            enb_ue_s1ap_id,
            mme_ue_s1ap_id,
            e_rabs: vec![ErabToSetup {
                erab_id:               5,
                qci:                   9,
                gtp_teid:              ul_teid.to_be_bytes(),
                transport_layer_addr:  _upf_addr,
            }],
            nas_pdu: Some(attach_accept_nas),
            ue_ambr: (50_000_000, 50_000_000),
            security_key: derive_kasme(&ctx.ck, &ctx.ik),
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
        // Phase 2: wrap AttachAccept in DownlinkNasTransport.
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
    _world:          &mut World,
    mme_ue_s1ap_id:  u32,
) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
    tracing::info!(mme_ue_s1ap_id, "AttachComplete — subscriber online");
    (vec![], vec![])
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Minimal KeNB / K_ASME derivation placeholder.
/// Replace with TS 33.401 §A.2 KDF when hardening security.
fn derive_kasme(ck: &[u8; 16], ik: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    key
        }
