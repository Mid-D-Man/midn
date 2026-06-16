// crates/midn-userplane/src/lib.rs
//! midn-userplane — User Plane Function (UPF)
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
//!   ├── HashMap<ul_teid, UserPlaneSession>
//!   └── Option<BpfHandle>         ← wired via set_bpf_handle after load_xdp
//!
//! GtpForwarder  ← owns UDP socket on port 2152
//!   ├── Arc<Mutex<RoutingTable>>
//!   ├── mpsc::Sender<UlPacket>
//!   └── mpsc::Receiver<DlPacket>
//!
//! TunnelManager  ← lower-level building block (bench suite)
//!
//! ebpf::loader::{load_xdp, BpfHandle}  ← Phase 3.1 XDP fast path
//! ```
//!
//! ## Phase 3.1 startup sequence
//!
//! ```rust,ignore
//! let mut sm = SessionManager::new();
//! let routing = sm.routing_arc();
//! let (fwd, dl_tx) = GtpForwarder::bind(routing, ul_tx).await?;
//! tokio::spawn(fwd.run());
//!
//! // Activate XDP fast path (Linux only):
//! if let Ok(mut bpf) = load_xdp("eth0").await {
//!     bpf.set_pdn_gw_config(&PdnGwConfig::new(gw_mac, nic_mac))?;
//!     sm.set_bpf_handle(bpf);
//! }
//! ```

pub mod upf;
pub mod ebpf;

pub use upf::forwarder::{DlPacket, GtpForwarder, UlPacket, GTP_PORT};
pub use upf::routing::RoutingTable;
pub use upf::session::UserPlaneSession;
pub use upf::session_manager::SessionManager;
pub use upf::tunnel::TunnelManager;
pub use upf::xdp_types::{PdnGwConfig, XdpRouteEntry};
pub use ebpf::loader::{BpfHandle, load_xdp};
