// crates/midn-userplane-ebpf/src/maps.rs
//! BPF map declarations — shared between the kernel XDP program(s) and the
//! userspace loader.
//!
//! ## Maps
//!
//! | Name             | Type  | Key        | Value          | Purpose                              |
//! |-------------------|-------|------------|----------------|---------------------------------------|
//! | TEID_TO_ROUTE    | Hash  | u32        | XdpRouteEntry  | UL TEID → DL route (per session)     |
//! | PDN_GW_CONFIG    | Array | u32 (0)    | PdnGwConfig    | NIC/GW MAC addresses for ETH rewrite |
//! | UE_IP_TO_ROUTE   | Hash  | [u8; 4]    | XdpRouteEntry  | UE IP → DL route (Phase 3.2 DL path) |
//! | DL_TUNNEL_CONFIG | Array | u32 (0)    | DlTunnelConfig | ETH/IP/redirect params for DL tunnel  |
//!
//! ## Sync contract
//!
//! `XdpRouteEntry`, `PdnGwConfig`, and `DlTunnelConfig` here are the kernel-side
//! definitions. Their userspace mirrors live in `midn_userplane::upf::xdp_types`.
//! Both sides MUST remain byte-for-byte identical:
//!   - `#[repr(C)]` on both sides, same field order and types
//!   - Explicit padding — no implicit compiler padding
//!
//! The `*_layout` tests in `xdp_types.rs` catch regressions on the userspace side.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap};

// ── TEID routing map (UL) ──────────────────────────────────────────────────────

/// Per-session routing entry stored in the kernel `TEID_TO_ROUTE` BPF hash map.
///
/// Written by userspace via `BpfHandle::insert_teid` when the MME emits
/// `UpfEvent::UpdateBearer` (after eNodeB ICSRSP assigns the real DL TEID).
/// Read by the XDP program on every incoming UDP:2152 packet.
///
/// Also reused as the value type for `UE_IP_TO_ROUTE` (Phase 3.2 DL path) —
/// the fields needed to route a DL packet toward the eNodeB (dl_teid, enb_ip,
/// enb_port) are exactly the same fields already carried here.
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

// ── PDN gateway config map (UL) ────────────────────────────────────────────────

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

// ── UE IP routing map (DL — Phase 3.2) ────────────────────────────────────────

/// UE IPv4 address → XdpRouteEntry (reverse direction of `TEID_TO_ROUTE`).
///
/// Written by userspace via `BpfHandle::insert_ue_route` — mirrors
/// `SessionManager`'s `TEID_TO_ROUTE` writes exactly, keyed by `ue_ip` instead
/// of `ul_teid`:
///   CreateSession → placeholder (dl_teid = 0, enb_ip = [0;4]).
///   UpdateBearer  → real dl_teid + enb_ip (atomic BPF_ANY overwrite).
///   RemoveSession → entry deleted via `BpfHandle::remove_ue_route`.
///
/// Read by the second XDP program (`midn_gtp_dl_xdp`, attached to the
/// PDN-facing interface) for every incoming IPv4 packet whose destination
/// address matches a known UE.
///
/// ## Placeholder gate (DL-specific Rule 3 analogue)
///
/// Unlike the UL path — which only checks map *presence* — the DL path reads
/// `dl_teid` and `enb_ip` out of the entry to build a real GTP-U tunnel toward
/// the eNodeB, so a placeholder (`dl_teid == 0`) is NOT safe to fast-path:
/// tunneling toward `enb_ip = [0;4]` would misdirect traffic instead of merely
/// deferring it. `gtp_dl_xdp::process_dl` checks `dl_teid == 0` explicitly and
/// falls through to `XDP_PASS` (userspace handles it) until `UpdateBearer` fires.
///
/// Map type:    BPF_MAP_TYPE_HASH
/// Max entries: 65 536 (mirrors TEID_TO_ROUTE — one entry per session)
/// Flags:       0
#[map]
pub static UE_IP_TO_ROUTE: HashMap<[u8; 4], XdpRouteEntry> =
    HashMap::with_max_entries(65_536, 0);

// ── DL tunnel config map (Phase 3.2) ──────────────────────────────────────────

/// Ethernet + IP + redirect parameters for the DL GTP-U encapsulation fast path.
///
/// Written ONCE by userspace at UPF startup via `BpfHandle::set_dl_tunnel_config`,
/// after the second XDP program has been attached to the PDN-facing interface.
/// Read by `midn_gtp_dl_xdp` on every DL hit to build the new outer
/// ETH/IP/UDP/GTP-U headers and to know which interface to `bpf_redirect` into.
///
/// ## Fields
///
/// - `eth_dst_mac` / `eth_src_mac`: new Ethernet header for the packet as it
///   leaves toward the eNodeB — dst is the eNodeB (or next-hop router) MAC on
///   the eNodeB-facing side, src is that interface's own MAC. Same sourcing
///   method as `PdnGwConfig` (`ip neigh` / `ip link show`), just facing the
///   opposite direction.
/// - `upf_ip`: the UPF's own transport-plane IPv4 address — used as the outer
///   IP source for the newly-built GTP-U tunnel packet. There is no kernel IP
///   stack involved on this path (unlike the userspace `GtpForwarder`, which
///   gets this for free from a bound UDP socket), so it must be supplied
///   explicitly.
/// - `redirect_ifindex`: the eNodeB-facing interface's ifindex, passed to
///   `bpf_redirect(ifindex, 0)`. Obtained via `if_nametoindex()` at startup.
///
/// ## Layout
///
/// Size: 20 bytes (6 + 6 + 4 + 4). Align: 4. No implicit padding —
/// `eth_src_mac` ends at offset 12 (already 4-byte aligned), so `upf_ip`
/// and `redirect_ifindex` both fall on natural boundaries with no gaps.
/// Must match `midn_userplane::upf::xdp_types::DlTunnelConfig`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DlTunnelConfig {
    /// Ethernet dst MAC — eNodeB, or next-hop router toward the eNodeB.
    pub eth_dst_mac:      [u8; 6],
    /// Ethernet src MAC — the eNodeB-facing NIC interface MAC.
    pub eth_src_mac:      [u8; 6],
    /// UPF's own transport IPv4 address (outer IP src for the DL tunnel).
    pub upf_ip:           [u8; 4],
    /// ifindex of the eNodeB-facing interface, for `bpf_redirect`.
    pub redirect_ifindex: u32,
}

/// Singleton config array: index 0 is the only slot.
///
/// XDP read: `DL_TUNNEL_CONFIG.get(0)` — returns `None` until configured
/// (all-zero entry, redirect_ifindex = 0 is not a valid ifindex), which
/// causes `midn_gtp_dl_xdp` to fall through to `XDP_PASS` (safe default).
#[map]
pub static DL_TUNNEL_CONFIG: Array<DlTunnelConfig> =
    Array::with_max_entries(1, 0);
