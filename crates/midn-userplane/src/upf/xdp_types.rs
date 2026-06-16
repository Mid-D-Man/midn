// crates/midn-userplane/src/upf/xdp_types.rs
//! Userspace mirrors of kernel-side BPF map value types.
//!
//! | Struct          | Kernel counterpart     | Map             | Size  |
//! |-----------------|------------------------|-----------------|-------|
//! | `XdpRouteEntry` | `maps::XdpRouteEntry`  | `TEID_TO_ROUTE` | 12 B  |
//! | `PdnGwConfig`   | `maps::PdnGwConfig`    | `PDN_GW_CONFIG` | 16 B  |
//!
//! Both structs MUST remain byte-for-byte identical to their counterparts in
//! `crates/midn-userplane-ebpf/src/maps.rs`: `#[repr(C)]`, same field order,
//! explicit padding. The layout tests below catch regressions on the userspace
//! side (the ebpf crate has no_std and cannot run tests).

// ── XdpRouteEntry ─────────────────────────────────────────────────────────────

/// Per-session routing entry written into the kernel `TEID_TO_ROUTE` BPF map.
///
/// Written by `BpfHandle::insert_teid`:
///   - On `CreateSession`: dl_teid = 0 placeholder (map entry exists; XDP
///     passes until bearer is confirmed, safe per Rule 3).
///   - On `UpdateBearer`: real dl_teid + enb_addr (atomic BPF_ANY overwrite).
///   - On `RemoveSession`: entry deleted via `BpfHandle::remove_teid`.
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
    }
