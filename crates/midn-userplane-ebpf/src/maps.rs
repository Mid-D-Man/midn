// crates/midn-userplane-ebpf/src/maps.rs
//! BPF map declarations — shared between the kernel XDP program and the
//! userspace loader.
//!
//! ## Sync contract
//!
//! `XdpRouteEntry` here is the kernel-side definition. Its userspace mirror is
//! `midn_userplane::upf::xdp_types::XdpRouteEntry`. Both must remain identical:
//!   - `#[repr(C)]` layout, same field order and types
//!   - Size: 12 bytes (u32 + [u8;4] + u16 + [u8;2])
//!   - Alignment: 4 (natural — no hidden compiler padding)
//!
//! If either struct changes the other MUST change too.
//! The `xdp_route_entry_layout` test in `xdp_types.rs` catches size/align regressions.

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

/// Per-session routing entry stored in the kernel BPF hash map.
///
/// Written by userspace via `update_teid_map` in `loader.rs` when the MME
/// emits `UpfEvent::UpdateBearer` (i.e. after the eNodeB assigns a real DL
/// TEID in its `InitialContextSetupResponse`).
///
/// Read by the XDP program on every incoming UDP:2152 packet to determine
/// whether to fast-path the packet (Phase 3.1: XDP_TX) or fall through to
/// the userspace `GtpForwarder` (current: XDP_PASS).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct XdpRouteEntry {
    /// Downlink TEID — written into the GTP-U header for DL (PDN→UE) packets.
    pub dl_teid:  u32,
    /// eNodeB IPv4 transport address (DL GTP-U destination IP).
    pub enb_ip:   [u8; 4],
    /// eNodeB GTP-U port in host byte order (2152 in standard deployments).
    pub enb_port: u16,
    /// Explicit padding to 12 bytes — must be zero; keeps layout natural.
    pub _pad:     [u8; 2],
}

/// UL TEID → XdpRouteEntry
///
/// Key:   u32 — the uplink Tunnel Endpoint Identifier from the GTP-U header.
/// Value: XdpRouteEntry — DL TEID + eNodeB address needed for the response path.
///
/// Map type:    BPF_MAP_TYPE_HASH
/// Max entries: 65 536 (64k concurrent sessions)
/// Flags:       0 (standard pre-allocated hash table)
#[map]
pub static TEID_TO_ROUTE: HashMap<u32, XdpRouteEntry> =
    HashMap::with_max_entries(65_536, 0);
