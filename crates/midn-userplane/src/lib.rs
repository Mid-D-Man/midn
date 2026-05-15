// crates/midn-userplane/src/lib.rs
//! midn-userplane — User Plane Function (UPF)
//!
//! Responsibilities:
//!   - Terminate GTP-U tunnels from eNodeB/gNodeB
//!   - Decapsulate inner IP packets and route to PDN (internet)
//!   - Encapsulate DL packets and send to eNodeB via GTP-U
//!   - Enforce per-subscriber QoS (Phase 3)
//!   - XDP/eBPF fast path for kernel-level packet steering (Phase 3)
//!
//! ## Data plane flow
//!
//! ```text
//! [UE] → [eNodeB] → GTP-U/UDP → [UPF: midn-userplane] → [Internet]
//!
//! UL path (UE → Internet):
//!   1. Receive UDP on port 2152
//!   2. Parse GTP-U header → extract TEID
//!   3. RoutingTable::lookup(teid) → RouteEntry
//!   4. Decapsulate: strip GTP-U, send inner IP to PDN
//!
//! DL path (Internet → UE):
//!   1. Receive IP packet destined for UE address
//!   2. RoutingTable::reverse_lookup(ue_ip) → RouteEntry
//!   3. Encapsulate: add GTP-U header with dl_teid
//!   4. Send UDP to enb_addr:enb_port
//! ```

pub mod upf;

#[cfg(target_os = "linux")]
pub mod ebpf;

pub use upf::routing::RoutingTable;
pub use upf::session::UserPlaneSession;
pub use upf::tunnel::TunnelManager;
