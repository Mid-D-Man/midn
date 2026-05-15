// crates/midn-userplane/src/upf/session.rs
//! User plane session — per-subscriber UPF state.
//!
//! Links the control-plane subscriber entity (from midn-core's ECS)
//! to the data-plane tunnel and routing state in the UPF.
//!
//! ## Control plane ↔ User plane coordination
//!
//! When the MME establishes a bearer (InitialContextSetupResponse):
//!   1. midn-core creates a TunnelComponent on the ECS entity
//!   2. midn-userplane creates a UserPlaneSession here
//!   3. Phase 3: UserPlaneSession is mirrored to eBPF maps
//!
//! This separation means the control plane can fail without
//! affecting data plane routing for established sessions.

/// A single user plane session.
#[derive(Debug, Clone)]
pub struct UserPlaneSession {
    /// Corresponds to ECS EntityId in midn-core (same u32 value).
    pub entity_id:    u32,
    /// Subscriber IMSI (for logging and metrics).
    pub imsi:         u64,
    /// Uplink TEID assigned by this UPF.
    pub ul_teid:      u32,
    /// Downlink TEID assigned by the eNodeB.
    pub dl_teid:      u32,
    /// Subscriber's IPv4 address in the PDN.
    pub ue_ip:        [u8; 4],
    /// Session is active and forwarding packets.
    pub active:       bool,
    /// Total bytes forwarded uplink (for billing/monitoring).
    pub bytes_ul:     u64,
    /// Total bytes forwarded downlink.
    pub bytes_dl:     u64,
}

// TODO Phase 2: implement SessionManager that maps entity_id → UserPlaneSession
// TODO Phase 3: implement eBPF map synchronization in SessionManager
