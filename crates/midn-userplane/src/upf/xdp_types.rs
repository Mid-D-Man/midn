// crates/midn-userplane/src/upf/xdp_types.rs
//! Userspace mirrors of kernel-side BPF map value types.
//!
//! | Struct           | Kernel counterpart      | Map               | Size  |
//! |------------------|-------------------------|--------------------|-------|
//! | `XdpRouteEntry`  | `maps::XdpRouteEntry`   | `TEID_TO_ROUTE`,  | 12 B  |
//! |                  |                         | `UE_IP_TO_ROUTE`  |       |
//! | `PdnGwConfig`    | `maps::PdnGwConfig`     | `PDN_GW_CONFIG`   | 16 B  |
//! | `DlTunnelConfig` | `maps::DlTunnelConfig`  | `DL_TUNNEL_CONFIG`| 20 B  |
//!
//! All structs MUST remain byte-for-byte identical to their counterparts in
//! `crates/midn-userplane-ebpf/src/maps.rs`: `#[repr(C)]`, same field order,
//! explicit padding. The layout tests below catch regressions on the userspace
//! side (the ebpf crate has no_std and cannot run tests).

// ── XdpRouteEntry ─────────────────────────────────────────────────────────────

/// Per-session routing entry written into the kernel `TEID_TO_ROUTE` and
/// `UE_IP_TO_ROUTE` BPF maps.
///
/// Written by `BpfHandle::insert_teid` / `BpfHandle::insert_ue_route`:
///   - On `CreateSession`: dl_teid = 0 placeholder (map entry exists; XDP
///     passes until bearer confirmed, safe per Rule 3).
///   - On `UpdateBearer`: real dl_teid + enb_addr (atomic BPF_ANY overwrite).
///   - On `RemoveSession`: entry deleted via `BpfHandle::remove_teid` /
///     `BpfHandle::remove_ue_route`.
///
/// Size: 12 bytes. Align: 4 (natural alignment of u32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct XdpRouteEntry {
    /// Downlink TEID — written into the GTP-U header for DL (PDN → UE) packets.
    pub dl_teid:  u32,
    /// eNodeB IPv4 transport address (DL GTP-U destination IP).
    pub enb_ip:   [u8; 4],
    /// eNodeB GTP-U port in host byte order (standard: 2152).
    pub enb_port: u16,
    /// Explicit zero padding to 12 bytes — must be zero.
    /// Mirrors `_pad` in the kernel struct.
    pub _pad:     [u8; 2],
}

impl XdpRouteEntry {
    pub fn new(dl_teid: u32, enb_ip: [u8; 4], enb_port: u16) -> Self {
        Self { dl_teid, enb_ip, enb_port, _pad: [0; 2] }
    }
}

// Safety: #[repr(C)], no implicit padding, no pointers, valid for all bit
// patterns — aya::Pod requirements met.
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for XdpRouteEntry {}

// ── PdnGwConfig ───────────────────────────────────────────────────────────────

/// PDN gateway Ethernet rewrite parameters — written into the kernel
/// `PDN_GW_CONFIG` BPF array map at index 0 during UPF startup via
/// `BpfHandle::set_pdn_gw_config`.
///
/// The XDP program reads this once per G-PDU hit (after TEID map lookup) to
/// construct the new Ethernet header when forwarding the decapsulated inner IP
/// packet toward the PDN gateway (steps 7–8 of the XDP decision tree).
///
/// ## Initialization order
///
/// 1. `load_xdp(iface)` loads the program; map is zeroed.
/// 2. `BpfHandle::set_pdn_gw_config(cfg)` writes real MAC addresses.
/// 3. XDP program reads `PDN_GW_CONFIG.get(0)` — returns `None` until written,
///    which causes the XDP program to fall through to `XDP_PASS` (safe default).
///
/// ## How to get the values
///
/// ```bash
/// # gw_mac — ARP table for the default gateway
/// ip neigh show $(ip route show default | awk '/default/ {print $3}') \
///   | awk '{print $5}'
///
/// # nic_mac — UPF NIC MAC
/// ip link show eth0 | awk '/ether/ {print $2}'
/// ```
///
/// Size: 16 bytes. Align: 1 (all u8 fields).
/// Must match `PdnGwConfig` in `crates/midn-userplane-ebpf/src/maps.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PdnGwConfig {
    /// Ethernet dst MAC — PDN gateway or next-hop router toward the internet.
    pub gw_mac:  [u8; 6],
    /// Ethernet src MAC — the UPF NIC interface MAC address.
    pub nic_mac: [u8; 6],
    /// Explicit padding to 16 bytes — must be zero.
    /// Mirrors `_pad` in the kernel struct.
    pub _pad:    [u8; 4],
}

impl PdnGwConfig {
    pub fn new(gw_mac: [u8; 6], nic_mac: [u8; 6]) -> Self {
        Self { gw_mac, nic_mac, _pad: [0; 4] }
    }
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for PdnGwConfig {}

// ── DlTunnelConfig ────────────────────────────────────────────────────────────

/// Ethernet + IP + redirect parameters for the DL GTP-U encapsulation fast
/// path (Phase 3.2) — written into the kernel `DL_TUNNEL_CONFIG` BPF array
/// map at index 0 during UPF startup via `BpfHandle::set_dl_tunnel_config`.
///
/// The DL XDP program (`midn_gtp_dl_xdp`, attached to the PDN-facing
/// interface) reads this once per UE-IP hit to construct the new outer
/// ETH/IP headers and to know which interface to `bpf_redirect` into.
///
/// ## Initialization order
///
/// 1. `load_xdp(iface)` loads both programs; `DL_TUNNEL_CONFIG` map is zeroed.
/// 2. `BpfHandle::attach_dl(pdn_iface)` attaches `midn_gtp_dl_xdp`.
/// 3. `BpfHandle::set_dl_tunnel_config(cfg)` writes real MACs/IP/ifindex.
/// 4. DL XDP program reads `DL_TUNNEL_CONFIG.get(0)` — returns `None` until
///    written (all-zero, `redirect_ifindex = 0` is not a valid ifindex),
///    which causes the DL XDP program to fall through to `XDP_PASS`.
///
/// ## How to get the values
///
/// ```bash
/// # eth_dst_mac — eNodeB, or next-hop router toward it, from the
/// # PDN-facing side's perspective is irrelevant; this is looked up on
/// # whatever interface faces the eNodeB:
/// ip neigh show <enb_ip_or_next_hop>
///
/// # eth_src_mac — the eNodeB-facing NIC MAC
/// ip link show <enb_facing_iface> | awk '/ether/ {print $2}'
///
/// # upf_ip — the UPF's own transport IPv4 address on that interface
/// ip -4 addr show <enb_facing_iface> | awk '/inet /{print $2}' | cut -d/ -f1
///
/// # redirect_ifindex
/// ip link show <enb_facing_iface> | head -1 | cut -d: -f1
/// ```
///
/// Size: 20 bytes (6 + 6 + 4 + 4). Align: 4.
/// Must match `DlTunnelConfig` in `crates/midn-userplane-ebpf/src/maps.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl DlTunnelConfig {
    pub fn new(
        eth_dst_mac: [u8; 6],
        eth_src_mac: [u8; 6],
        upf_ip:      [u8; 4],
        redirect_ifindex: u32,
    ) -> Self {
        Self { eth_dst_mac, eth_src_mac, upf_ip, redirect_ifindex }
    }
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for DlTunnelConfig {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdp_route_entry_layout() {
        assert_eq!(
            core::mem::size_of::<XdpRouteEntry>(), 12,
            "XdpRouteEntry must be 12 bytes to match kernel struct"
        );
        assert_eq!(
            core::mem::align_of::<XdpRouteEntry>(), 4,
            "XdpRouteEntry must align to 4 bytes"
        );
    }

    #[test]
    fn xdp_route_entry_new_zeroes_pad() {
        let e = XdpRouteEntry::new(0xDEAD_BEEF, [192, 168, 1, 100], 2152);
        assert_eq!(e.dl_teid,  0xDEAD_BEEF);
        assert_eq!(e.enb_ip,   [192, 168, 1, 100]);
        assert_eq!(e.enb_port, 2152);
        assert_eq!(e._pad,     [0, 0], "padding must be zero on construction");
    }

    #[test]
    fn xdp_route_entry_copy() {
        let a = XdpRouteEntry::new(1, [10, 0, 0, 1], 2152);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn pdn_gw_config_layout() {
        assert_eq!(
            core::mem::size_of::<PdnGwConfig>(), 16,
            "PdnGwConfig must be 16 bytes to match kernel struct"
        );
        // All [u8; N] fields → align = 1
        assert_eq!(
            core::mem::align_of::<PdnGwConfig>(), 1,
            "PdnGwConfig must align to 1 byte"
        );
    }

    #[test]
    fn pdn_gw_config_new_zeroes_pad() {
        let c = PdnGwConfig::new(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        );
        assert_eq!(c.gw_mac,  [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(c.nic_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(c._pad,    [0; 4], "padding must be zero");
    }

    #[test]
    fn pdn_gw_config_copy() {
        let a = PdnGwConfig::new([1; 6], [2; 6]);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn xdp_route_entry_no_implicit_padding() {
        // u32(4) + [u8;4](4) + u16(2) + [u8;2](2) = 12 exactly
        // If padding were inserted between enb_port and _pad it would be 12 still
        // but the field offsets would differ from kernel. This is a belt-and-suspenders
        // check that `#[repr(C)]` doesn't sneak in any surprises.
        let e = XdpRouteEntry { dl_teid: 0, enb_ip: [0;4], enb_port: 0, _pad: [0;2] };
        assert_eq!(
            core::mem::size_of_val(&e), 12,
            "no hidden padding between fields"
        );
    }

    // ── DlTunnelConfig ────────────────────────────────────────────────────────

    #[test]
    fn dl_tunnel_config_layout() {
        assert_eq!(
            core::mem::size_of::<DlTunnelConfig>(), 20,
            "DlTunnelConfig must be 20 bytes to match kernel struct"
        );
        assert_eq!(
            core::mem::align_of::<DlTunnelConfig>(), 4,
            "DlTunnelConfig must align to 4 bytes (redirect_ifindex: u32)"
        );
    }

    #[test]
    fn dl_tunnel_config_field_offsets_have_no_gaps() {
        // eth_dst_mac(6) + eth_src_mac(6) = 12, already 4-byte aligned, so
        // upf_ip([u8;4], align 1) needs no padding before it, and
        // redirect_ifindex(u32, align 4) lands at offset 16 — also aligned.
        // Total: 12 + 4 + 4 = 20, matching size_of above with zero slack.
        let c = DlTunnelConfig::new([0; 6], [0; 6], [0; 4], 0);
        assert_eq!(core::mem::size_of_val(&c), 20, "no hidden padding between fields");
    }

    #[test]
    fn dl_tunnel_config_new_roundtrip() {
        let c = DlTunnelConfig::new(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [10, 0, 0, 1],
            3,
        );
        assert_eq!(c.eth_dst_mac,      [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(c.eth_src_mac,      [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(c.upf_ip,           [10, 0, 0, 1]);
        assert_eq!(c.redirect_ifindex, 3);
    }

    #[test]
    fn dl_tunnel_config_copy() {
        let a = DlTunnelConfig::new([1; 6], [2; 6], [10, 0, 0, 1], 2);
        let b = a;
        assert_eq!(a, b);
    }
    }
