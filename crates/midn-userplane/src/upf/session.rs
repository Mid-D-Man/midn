// crates/midn-userplane/src/upf/session.rs
//! User plane session — per-subscriber UPF state.

/// A single user plane session.
#[derive(Debug, Clone)]
pub struct UserPlaneSession {
    /// Corresponds to ECS EntityId in midn-core (same u32 value).
    pub entity_id:    u32,
    /// Subscriber IMSI (for logging and metrics).
    pub imsi:         u64,
    /// Uplink TEID assigned by this UPF.
    pub ul_teid:      u32,
    /// Downlink TEID assigned by the eNodeB (0 until ICSRSP).
    pub dl_teid:      u32,
    /// Subscriber's IPv4 address in the PDN.
    pub ue_ip:        [u8; 4],
    /// eNodeB transport address ([0;4] until ICSRSP).
    pub enb_addr:     [u8; 4],
    /// Session is active and forwarding packets.
    pub active:       bool,
    /// Total bytes forwarded uplink (for billing/monitoring).
    pub bytes_ul:     u64,
    /// Total bytes forwarded downlink.
    pub bytes_dl:     u64,
    }
