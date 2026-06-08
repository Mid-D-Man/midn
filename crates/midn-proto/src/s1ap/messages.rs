// crates/midn-proto/src/s1ap/messages.rs
//! S1AP message definitions — 3GPP TS 36.413.

use bytes::Bytes;

/// S1AP message discriminant.
#[derive(Debug, Clone)]
pub enum S1apMessage {
    // ── Connection management ──────────────────────────────────────────────
    S1SetupRequest(S1SetupRequest),
    S1SetupResponse(S1SetupResponse),
    S1SetupFailure { cause: S1apCause },

    // ── UE context management ─────────────────────────────────────────────
    InitialUeMessage(InitialUeMessage),
    DownlinkNasTransport(DownlinkNasTransport),
    UplinkNasTransport(UplinkNasTransport),

    // ── Bearer establishment ───────────────────────────────────────────────
    InitialContextSetupRequest(InitialContextSetupRequest),
    /// eNodeB → MME: radio bearer established, contains eNodeB-assigned DL TEID.
    InitialContextSetupResponse(InitialContextSetupResponse),
    InitialContextSetupFailure { cause: S1apCause },

    // ── Release ───────────────────────────────────────────────────────────
    UeContextReleaseCommand { cause: S1apCause },
    UeContextReleaseComplete { mme_ue_s1ap_id: u32, enb_ue_s1ap_id: u32 },
}

/// S1 Setup Request IEs.
#[derive(Debug, Clone)]
pub struct S1SetupRequest {
    pub global_enb_id:       [u8; 8],
    pub enb_name:            Option<String>,
    pub supported_tas:       Vec<SupportedTa>,
    pub default_paging_drx:  u8,
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
    pub mme_name:         Option<String>,
    pub served_gummeis:   Vec<Gummei>,
    pub relative_mme_cap: u8,
}

/// GUMMEI — Globally Unique MME Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gummei {
    pub plmn:     [u8; 3],
    pub mme_gid:  u16,
    pub mme_code: u8,
}

/// Initial UE Message IEs.
#[derive(Debug, Clone)]
pub struct InitialUeMessage {
    pub enb_ue_s1ap_id: u32,
    pub nas_pdu:        Bytes,
    pub tai:            [u8; 5],
    pub eutran_cgi:     [u8; 7],
    pub rrc_cause:      u8,
}

/// Downlink NAS Transport IEs.
#[derive(Debug, Clone)]
pub struct DownlinkNasTransport {
    pub mme_ue_s1ap_id: u32,
    pub enb_ue_s1ap_id: u32,
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

/// Initial Context Setup Request IEs — sent by MME to establish EPS bearer.
///
/// Carries the AttachAccept NAS PDU (inside `nas_pdu`) and the UPF's UL TEID
/// (inside `e_rabs_to_setup[*].gtp_teid`). The eNodeB uses the TEID to know
/// where to send uplink GTP-U packets.
#[derive(Debug, Clone)]
pub struct InitialContextSetupRequest {
    pub mme_ue_s1ap_id:   u32,
    pub enb_ue_s1ap_id:   u32,
    /// Aggregate Maximum Bit Rate — DL
    pub ue_ambr_dl:       u64,
    /// Aggregate Maximum Bit Rate — UL
    pub ue_ambr_ul:       u64,
    /// E-RABs to establish. Index 0 = default bearer (EPS bearer ID 5).
    pub e_rabs_to_setup:  Vec<ErabToSetup>,
    /// NAS PDU to relay to UE (AttachAccept). eNodeB delivers via RRC.
    pub nas_pdu:          Option<Bytes>,
    /// Kasme — 256-bit anchor key for AS key derivation.
    pub security_key:     [u8; 32],
}

/// E-RAB to set up (included in InitialContextSetupRequest).
#[derive(Debug, Clone)]
pub struct ErabToSetup {
    pub e_rab_id:             u8,
    pub qci:                  u8,
    pub alloc_retention_prio: u8,
    /// UPF/S-GW IPv4 transport address — where eNodeB sends UL GTP-U packets.
    pub transport_addr:       [u8; 4],
    /// UPF/S-GW UL TEID — the TEID the UPF expects on incoming UL packets.
    pub gtp_teid:             u32,
}

/// Initial Context Setup Response IEs — sent by eNodeB after bearer established.
///
/// Contains the eNodeB-assigned DL TEID (`e_rabs_setup[*].gtp_teid`) which the
/// UPF needs to encapsulate downlink packets correctly.
#[derive(Debug, Clone)]
pub struct InitialContextSetupResponse {
    pub mme_ue_s1ap_id: u32,
    pub enb_ue_s1ap_id: u32,
    /// E-RABs successfully established.
    pub e_rabs_setup:   Vec<ErabSetupItem>,
    /// E-RABs that failed (empty in normal case).
    pub e_rabs_failed:  Vec<u8>,
}

/// E-RAB setup item in Initial Context Setup Response.
///
/// The critical field is `gtp_teid`: this is the DL TEID assigned by the
/// eNodeB. The UPF must use this TEID when encapsulating downlink packets
/// destined for this subscriber.
#[derive(Debug, Clone, Copy)]
pub struct ErabSetupItem {
    pub e_rab_id: u8,
    /// eNodeB S1-U IPv4 transport address.
    pub transport_addr: [u8; 4],
    /// eNodeB-assigned DL TEID — UPF inserts this in GTP-U DL headers.
    pub gtp_teid: u32,
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
