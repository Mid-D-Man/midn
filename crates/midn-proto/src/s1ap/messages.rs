// crates/midn-proto/src/s1ap/messages.rs
//! S1AP message definitions — 3GPP TS 36.413.

use bytes::Bytes;

/// S1AP message discriminant.
#[derive(Debug, Clone)]
pub enum S1apMessage {
    // ── Connection management ─────────────────────────────────────────────
    S1SetupRequest(S1SetupRequest),
    S1SetupResponse(S1SetupResponse),
    S1SetupFailure { cause: S1apCause },

    // ── UE context management ─────────────────────────────────────────────
    InitialUeMessage(InitialUeMessage),
    DownlinkNasTransport(DownlinkNasTransport),
    UplinkNasTransport(UplinkNasTransport),

    // ── Bearer establishment ──────────────────────────────────────────────
    InitialContextSetupRequest(InitialContextSetupRequest),
    /// eNodeB → MME: radio bearer established, contains eNodeB-assigned DL TEID.
    InitialContextSetupResponse(InitialContextSetupResponse),
    InitialContextSetupFailure { cause: S1apCause },

    // ── Release ───────────────────────────────────────────────────────────
    UeContextReleaseCommand { cause: S1apCause },
    /// Tuple variant so the handler can receive the struct by value.
    UeContextReleaseComplete(UeContextReleaseComplete),
}

// ── S1 Setup ──────────────────────────────────────────────────────────────────

/// S1 Setup Request IEs.
#[derive(Debug, Clone)]
pub struct S1SetupRequest {
    pub global_enb_id:      [u8; 8],
    pub enb_name:           Option<String>,
    pub supported_tas:      Vec<SupportedTa>,
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

// ── UE context management ─────────────────────────────────────────────────────

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

// ── Bearer establishment ──────────────────────────────────────────────────────

/// Initial Context Setup Request IEs — sent by MME to establish EPS bearer.
///
/// Carries the AttachAccept NAS PDU (in `nas_pdu`) and the UPF UL TEID
/// (in `e_rabs[*].gtp_teid` as big-endian bytes). The eNodeB uses the TEID
/// to know where to send uplink GTP-U packets.
#[derive(Debug, Clone)]
pub struct InitialContextSetupRequest {
    pub mme_ue_s1ap_id: u32,
    pub enb_ue_s1ap_id: u32,
    /// E-RABs to establish. Index 0 = default bearer (EPS bearer ID 5).
    pub e_rabs:         Vec<ErabToSetup>,
    /// NAS PDU to relay to UE (AttachAccept). eNodeB delivers via RRC.
    pub nas_pdu:        Option<Bytes>,
    /// Aggregate Maximum Bit Rate — (DL, UL) in bps.
    pub ue_ambr:        (u64, u64),
    /// Kasme / security key — 256-bit anchor for AS key derivation.
    pub security_key:   [u8; 32],
}

/// E-RAB to set up (included in InitialContextSetupRequest).
#[derive(Debug, Clone)]
pub struct ErabToSetup {
    /// EPS Bearer ID (5 = default bearer).
    pub erab_id:              u8,
    /// QoS Class Identifier.
    pub qci:                  u8,
    /// UPF/S-GW UL TEID as big-endian bytes — the TEID the UPF expects on
    /// incoming UL GTP-U packets. Encoded as `[u8; 4]` so eNodeB can read
    /// it directly from the S1AP PDU without a byte-swap.
    pub gtp_teid:             [u8; 4],
    /// UPF/S-GW IPv4 transport address — where eNodeB sends UL GTP-U packets.
    pub transport_layer_addr: [u8; 4],
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
/// The critical field is `gtp_teid`: the DL TEID assigned by the eNodeB.
/// The UPF inserts this TEID into GTP-U DL packet headers.
#[derive(Debug, Clone, Copy)]
pub struct ErabSetupItem {
    pub e_rab_id: u8,
    /// eNodeB S1-U IPv4 transport address.
    pub transport_layer_addr: [u8; 4],
    /// eNodeB-assigned DL TEID as big-endian bytes.
    pub gtp_teid: [u8; 4],
}

// ── Release ───────────────────────────────────────────────────────────────────

/// UE Context Release Complete — sent by eNodeB after context release.
#[derive(Debug, Clone)]
pub struct UeContextReleaseComplete {
    pub mme_ue_s1ap_id: u32,
    pub enb_ue_s1ap_id: u32,
}

// ── Cause ─────────────────────────────────────────────────────────────────────

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
