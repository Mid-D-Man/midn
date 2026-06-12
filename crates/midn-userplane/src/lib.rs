// crates/midn-userplane/src/lib.rs
//! midn-userplane — User Plane Function (UPF)
//!
//! Responsibilities:
//!   - Terminate GTP-U tunnels from eNodeB/gNodeB
//!   - Decapsulate inner IP packets and route to PDN (internet)
//!   - Encapsulate DL packets and send to eNodeB via GTP-U
//!   - Enforce per-subscriber QoS (Phase 3)
//!   - XDP/eBPF fast path for kernel-level packet steering (Phase 3.1)
//!
//! ## Data plane flow
//!
//! ```text
//! [UE] → [eNodeB] → GTP-U/UDP → [UPF] → [Internet]
//!
//! UL: recv UDP:2152 → GtpuParser → lookup_ul(TEID) → strip GTP-U → PDN
//! DL: recv IP → lookup_dl(UE IP) → prepend GTP-U → send UDP → eNodeB
//! ```
//!
//! ## Component hierarchy
//!
//! ```text
//! SessionManager  ← production entry point
//!   ├── Arc<Mutex<RoutingTable>>  ← shared with GtpForwarder
//!   └── HashMap<ul_teid, UserPlaneSession>
//!
//! GtpForwarder  ← owns the UDP socket on port 2152
//!   ├── Arc<Mutex<RoutingTable>>  ← same Arc as SessionManager
//!   ├── mpsc::Sender<UlPacket>   ← emits decapsulated UL packets
//!   └── mpsc::Receiver<DlPacket> ← receives DL packets to encapsulate
//!
//! TunnelManager  ← lower-level building block (bench suite)
//!
//! ebpf::loader::BpfHandle  ← Phase 3.1: kernel TEID_TO_ROUTE map management
//! ```

pub mod upf;

// ebpf is not Linux-gated here; loader.rs handles platform differences
// internally with #[cfg] blocks. load_xdp and BpfHandle exist on all
// platforms — on non-Linux, load_xdp returns an error immediately.
pub mod ebpf;

pub use upf::forwarder::{DlPacket, GtpForwarder, UlPacket, GTP_PORT};
pub use upf::routing::RoutingTable;
pub use upf::session::UserPlaneSession;
pub use upf::session_manager::SessionManager;
pub use upf::tunnel::TunnelManager;
pub use upf::xdp_types::XdpRouteEntry;
// load_xdp and BpfHandle reachable as midn_userplane::ebpf::loader::{load_xdp, BpfHandle}
