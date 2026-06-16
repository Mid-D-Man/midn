// crates/midn-userplane-ebpf/src/maps.rs
//! BPF map declarations — shared between the kernel XDP program and the
//! userspace loader.
//!
//! ## Maps
//!
//! | Name            | Type  | Key        | Value          | Purpose                              |
//! |-----------------|-------|------------|----------------|--------------------------------------|
//! | TEID_TO_ROUTE   | Hash  | u32        | XdpRouteEntry  | UL TEID → DL route (per session)     |
//! | PDN_GW_CONFIG   | Array | u32 (0)    | PdnGwConfig    | NIC/GW MAC addresses for ETH rewrite |
//!
//! ## Sync contract
//!
//! `XdpRouteEntry` and `PdnGwConfig` here are the kernel-side definitions.
//! Their userspace mirrors live in `midn_userplane::upf::xdp_types`.
//! Both sides MUST remain byte-for-byte identical:
//!   - `#[repr(C)]` on both sides, same field order and types
//!   - Explicit padding — no implicit compiler padding
//!
//! The `xdp_route_entry_layout` and `pdn_gw_config_layout` tests in
//! `xdp_types.rs` catch regressions on the userspace side.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap};

// ── TEID routing map ──────────────────────────────────────────────────────────

/// Per-session routing entry stored in the kernel `TEID_TO_ROUTE` BPF hash map.
///
/// Written by userspace via `BpfHandle::insert_teid` when the MME emits
/// `UpfEvent::UpdateBearer` (after eNodeB ICSRSP assigns the real DL TEID).
/// Read by the XDP program on every incoming UDP:2152 packet.
///
/// ## Layout
///
/// Size: 12 bytes. Align: 4. No implicit padding.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct XdpRouteEntry {
    /// Downlink TEID — written into the GTP-U header for DL (PDN → UE) packets.
    pub dl_teid:  u32,
    /// eNodeB IPv4 transport address (DL GTP-U destination IP).
    pub enb_ip:   [u8; 4],
    /// eNodeB GTP-U port in host byte order (standard: 2152).
    pub enb_port: u16,
    /// Explicit zero padding — must be zero; matches userspace mirror.
    pub _pad:     [u8; 2],
}

/// UL TEID → XdpRouteEntry
///
/// Map type:    BPF_MAP_TYPE_HASH
/// Max entries: 65 536 (64k concurrent UE sessions)
/// Flags:       0 (standard pre-allocated hash table)
#[map]
pub static TEID_TO_ROUTE: HashMap<u32, XdpRouteEntry> =
    HashMap::with_max_entries(65_536, 0);

// ── PDN gateway config map ────────────────────────────────────────────────────

/// Ethernet header rewrite parameters for the XDP_TX fast path (Phase 3.1).
///
/// Written ONCE by userspace at UPF startup via `BpfHandle::set_pdn_gw_config`.
/// Read by the XDP program after stripping the outer GTP-U tunnel headers to
/// construct the new Ethernet header pointing toward the PDN gateway.
///
/// ## Why a BPF map instead of constants?
///
/// The NIC MAC address and next-hop gateway MAC are runtime values — they depend
/// on the network interface the UPF is attached to. Storing them here lets
/// userspace configure them at startup without recompiling the eBPF program.
///
/// ## Layout
///
/// Size: 16 bytes (6 + 6 + 4 pad). Align: 1. No implicit padding.
/// Must match `midn_userplane::upf::xdp_types::PdnGwConfig`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PdnGwConfig {
    /// Ethernet dst MAC — PDN gateway or next-hop router toward the internet.
    /// Obtained from `arp` / `ip neigh` for the default gateway at startup.
    pub gw_mac:  [u8; 6],
    /// Ethernet src MAC — the UPF NIC interface MAC.
    /// Obtained from `ip link show <iface>` at startup.
    pub nic_mac: [u8; 6],
    /// Explicit padding to 16 bytes — must be zero.
    pub _pad:    [u8; 4],
}

/// Singleton config array: index 0 is the only slot.
///
/// Map type: BPF_MAP_TYPE_ARRAY
///   - Pre-allocated: always exists, zero-initialized at load time.
///   - Kernel update: `BpfHandle::set_pdn_gw_config` overwrites index 0.
///   - XDP read: `PDN_GW_CONFIG.get(0)` — returns None until configured
///     (all-zero entry), which causes the XDP program to fall through to
///     userspace via XDP_PASS.
#[map]
pub static PDN_GW_CONFIG: Array<PdnGwConfig> =
    Array::with_max_entries(1, 0);
