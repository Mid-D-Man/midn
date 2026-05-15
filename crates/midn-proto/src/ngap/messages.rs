// crates/midn-proto/src/ngap/messages.rs
//! NGAP message types — 3GPP TS 38.413
//!
//! Phase 3 stub — expand after S1AP is complete.

use bytes::Bytes;

/// NGAP message discriminant.
#[derive(Debug, Clone)]
pub enum NgapMessage {
    // ── Connection management ──────────────────────────────────────────────
    /// gNodeB → AMF: register gNodeB on startup.
    NgSetupRequest,
    /// AMF → gNodeB: accept registration.
    NgSetupResponse,

    // ── UE context management ─────────────────────────────────────────────
    /// gNodeB → AMF: first NAS message from a new UE.
    InitialUeMessage(NgapInitialUeMessage),
    /// AMF → gNodeB: send NAS PDU down to UE.
    DownlinkNasTransport { ran_ue_ngap_id: u32, nas_pdu: Bytes },
    /// gNodeB → AMF: send NAS PDU up to AMF.
    UplinkNasTransport { ran_ue_ngap_id: u32, nas_pdu: Bytes },

    // ── PDU Session ───────────────────────────────────────────────────────
    /// AMF → gNodeB: establish PDU session resource.
    PduSessionResourceSetupRequest,
    /// gNodeB → AMF: PDU session resource established.
    PduSessionResourceSetupResponse,
    /// gNodeB → AMF: PDU session resource establishment failed.
    PduSessionResourceSetupFailure,

    // ── Release ───────────────────────────────────────────────────────────
    /// AMF → gNodeB: release UE context.
    UeContextReleaseCommand,
    /// gNodeB → AMF: context released.
    UeContextReleaseComplete,
}

/// Initial UE Message IEs (5G NR).
#[derive(Debug, Clone)]
pub struct NgapInitialUeMessage {
    pub ran_ue_ngap_id:    u32,
    pub nas_pdu:           Bytes,
    /// NR Cell Global Identity
    pub nr_cgi:            [u8; 9],
    pub rrc_establishment_cause: u8,
}
