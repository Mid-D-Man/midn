// crates/midn-core/src/mme/attach.rs
//! LTE Attach procedure — 3GPP TS 23.401 Section 5.3.2
//!
//! ## Sequence diagram
//!
//! ```text
//! UE       eNodeB              MME                    midn-auth
//!  |         |                  |                         |
//!  |--RRC--->|                  |                         |
//!  |--NAS AttachReq------------>|                         |
//!  |         |--S1AP InitialUeMsg->                       |
//!  |         |                  |--generate_vector(Ki,OPc)->|
//!  |         |                  |<-- AuthVector (RAND/AUTN/XRES/CK/IK)
//!  |         |<--S1AP DL NAS----| (AuthRequest: RAND, AUTN)
//!  |<--NAS AuthReq--------------|                         |
//!  |--NAS AuthResp (RES)------->|                         |
//!  |         |--S1AP UL NAS---->|                         |
//!  |         |                  | verify_res(XRES, RES)   |
//!  |<--NAS SecurityModeCmd------|                         |
//!  |--NAS SecurityModeComplete->|                         |
//!  |         |--S1AP InitCtxSetup->                       |
//!  |<--RRC SecurityMode---------|                         |
//!  |<--NAS AttachAccept---------|                         |
//!  |--NAS AttachComplete------->|                         |
//!  |         |                  | → data plane active     |
//! ```
//!
//! ## Phase 2 implementation plan
//!
//! 1. `AttachProcedure::start` — create entity, issue auth challenge
//! 2. `AttachProcedure::handle_auth_response` — verify RES, activate security
//! 3. `AttachProcedure::handle_security_mode_complete` — create session
//! 4. `AttachProcedure::handle_attach_complete` — open data plane

use crate::ecs::components::{AuthFailReason, AuthState};
use crate::ecs::world::{CoreWorld, EntityId};

/// Per-subscriber attach procedure state.
///
/// Tracks where in the attach sequence a particular UE is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachProcedureState {
    /// Initial state: Attach Request received, not yet authenticated.
    AwaitingAuthentication {
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
    },
    /// Auth challenge sent (RAND, AUTN) — awaiting UE's RES.
    AwaitingAuthResponse {
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
    },
    /// Auth successful — Security Mode Command sent.
    AwaitingSecurityModeComplete {
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
    },
    /// Security mode active — Attach Accept sent, awaiting Attach Complete.
    AwaitingAttachComplete {
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
    },
    /// Attach complete — subscriber online.
    Attached,
    /// Procedure failed.
    Failed(AttachFailReason),
}

/// Reason for attach failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachFailReason {
    AuthFailed(AuthFailReason),
    ImsiNotFound,
    InternalError,
}

// TODO Phase 2: implement AttachProcedure struct with handle_* methods.
// Each method takes &mut CoreWorld and returns the next S1AP/NAS messages to send.
