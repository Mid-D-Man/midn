//! midn-userplane — User Plane Function (UPF)
//!
//! Responsibilities:
//!   - Terminate GTP-U tunnels from eNodeB/gNodeB
//!   - Route subscriber data packets to PDN (internet)
//!   - Enforce per-subscriber QoS policies
//!   - XDP/eBPF fast path for kernel-level steering
//!
//! Phase 3 target: line-rate packet steering via XDP.
//! Current phase: userspace GTP-U tunnel management.

pub mod upf;

#[cfg(target_os = "linux")]
pub mod ebpf;

pub use upf::routing::RoutingTable;
pub use upf::tunnel::TunnelManager;
