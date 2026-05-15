// crates/midn-proto/src/s1ap/messages.rs
//! S1AP message definitions — 3GPP TS 36.413.

use bytes::Bytes;

/// S1AP message discriminant.
///
/// NAS PDUs inside S1AP are carried as opaque `Bytes` — the MME
/// decodes them after extracting from the S1AP wrapper.
#[derive(Debug, Clone)]
pub enum S1apMessage {
    // ── Connection management ──────────────────────────────────────────────
    /// eNodeB → MME: register eNodeB on startup.
    S1SetupRequest(S1SetupRequest),
    /// MME → eNodeB: accept registration.
    S1SetupResponse(S1SetupResponse),
    /// MME → eNodeB: reject registration.
    S1SetupFailure { cause: S1apCause },

    // ── UE context management ─────────────────────────────────────────────
    /// eNodeB → MME: first NAS message from a new UE.
    InitialUeMessage(InitialUeMessage),
    /// MME → eNodeB: send NAS PDU down to UE.
    DownlinkNasTransport(DownlinkNasTransport),
    /// eNodeB → MME: send NAS PDU up to MME.
    UplinkNasTransport(UplinkNasTransport),

    // ── Bearer establishment ───────────────────────────────────────────────
    /// MME → eNodeB: create default EPS bearer.
    InitialContextSetupRequest(InitialContextSetupRequest),
    /// eNodeB → MME: bearer established.
    InitialContextSetupResponse,
    /// eNodeB → MME: bearer establishment failed.
    InitialContextSetupFailure { cause: S1apCause },

    // ── Release ───────────────────────────────────────────────────────────
    /// MME → eNodeB: release UE context.
    UeContextReleaseCommand { cause: S1apCause },
    /// eNodeB → MME: context released.
    UeContextReleaseComplete { mme_ue_s1ap_id: u32, enb_ue_s1ap_id: u32 },
}

/// S1 Setup Request IEs.
#[derive(Debug, Clone)]
pub struct S1SetupRequest {
    /// eNodeB global identity (PLMN + eNB-ID)
    pub global_enb_id:    [u8; 8],
    /// Human-readable eNodeB name
    pub enb_name:         Option<String>,
    /// Supported Tracking Area Codes
    pub supported_tas:    Vec<SupportedTa>,
    /// Paging DRX cycle
    pub default_paging_drx: u8,
}

/// Supported Tracking Area in S1 Setup.
#[derive(Debug, Clone)]
pub struct SupportedTa {
    pub tac:   [u8; 2],
    pub plmns: Vec<[u8; 3]>,
}

/// S1 Setup Response IEs.
#[derive(Debug, Clone)]
pub struct S1SetupResponse {
    pub mme_name:          Option<String>,
    pub served_gummeis:    Vec<Gummei>,
    pub relative_mme_cap:  u8,
}

/// GUMMEI — Globally Unique MME Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gummei {
    pub plmn:    [u8; 3],
    pub mme_gid: u16,
    pub mme_code: u8,
}

/// Initial UE Message IEs — carries the first NAS PDU from a new UE.
#[derive(Debug, Clone)]
pub struct InitialUeMessage {
    pub enb_ue_s1ap_id: u32,
    /// Opaque NAS PDU — decode with NasMessage::decode()
    pub nas_pdu:        Bytes,
    /// TAI (Tracking Area Identity) where UE attached
    pub tai:            [u8; 5],
    /// EUTRAN CGI (Cell Global Identity)
    pub eutran_cgi:     [u8; 7],
    pub rrc_cause:      u8,
}

/// Downlink NAS Transport IEs.
#[derive(Debug, Clone)]
pub struct DownlinkNasTransport {
    pub mme_ue_s1ap_id: u32,
    pub enb_ue_s1ap_id: u32,
    /// Opaque NAS PDU — encode with NasMessage::encode()
    pub nas_pdu:        Bytes,
}

/// Uplink NAS Transport IEs.
#[derive(Debug, Clone)]
pub struct UplinkNasTransport {
    pub mme_ue_s1ap_id: u32,
    pub enb_ue_s1ap_id: u32,
    pub nas_pdu:        Bytes,
    pub tai:            [u8; 5],
    pub eutran_cgi:     [u8; 7],
}

/// Initial Context Setup Request IEs — establishes default EPS bearer.
#[derive(Debug, Clone)]
pub struct InitialContextSetupRequest {
    pub mme_ue_s1ap_id:      u32,
    pub enb_ue_s1ap_id:      u32,
    /// Aggregate Maximum Bit Rate
    pub ue_ambr_dl:          u64,
    pub ue_ambr_ul:          u64,
    /// E-RABs to set up (at minimum: default bearer EPS bearer ID 5)
    pub e_rabs_to_setup:     Vec<ErabToSetup>,
    /// NAS PDU to deliver (Attach Accept)
    pub nas_pdu:             Option<Bytes>,
    /// Security context for the UE
    pub security_key:        [u8; 32],
}

/// E-RAB to establish.
#[derive(Debug, Clone)]
pub struct ErabToSetup {
    pub e_rab_id:           u8,
    pub qci:                u8,
    pub alloc_retention_prio: u8,
    /// S-GW transport layer address (IP + TEID for GTP-U)
    pub transport_addr:     [u8; 4],
    pub gtp_teid:           u32,
}

/// S1AP cause code (simplified).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S1apCause {
    RadioNetworkUnspecified,
    TransportUnspecified,
    NasNormalRelease,
    NasDetach,
    NasAuthFailure,
    ProtocolUnspecified,
    MiscUnspecified,
}
