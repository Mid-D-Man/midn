// crates/midn-userplane/src/upf/xdp_types.rs
//! Userspace mirror of the kernel-side `XdpRouteEntry` BPF map value.
//!
//! ## Layout contract
//!
//! This struct MUST remain byte-for-byte identical to `XdpRouteEntry` in
//! `crates/midn-userplane-ebpf/src/maps.rs`:
//!   - `#[repr(C)]` on both sides
//!   - Same field order, same types
//!   - Size: 12 bytes  (u32 + [u8;4] + u16 + [u8;2])
//!   - Align: 4        (natural alignment of u32)
//!
//! The `xdp_route_entry_layout` test below catches regressions on the
//! userspace side. The ebpf crate has no equivalent test (no_std), so
//! any struct change there requires a manual audit of this file.
//!
//! ## aya::Pod
//!
//! The `unsafe impl aya::Pod` on Linux tells aya it is safe to memcpy
//! this struct directly into/from the BPF hash map. Requirements:
//!   - `#[repr(C)]` with no implicit padding ✓
//!   - No pointers or references ✓
//!   - Valid for all bit patterns ✓

/// Per-session routing entry written into the kernel `TEID_TO_ROUTE` BPF map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct XdpRouteEntry {
    /// Downlink TEID — inserted into the GTP-U header for DL packets.
    pub dl_teid:  u32,
    /// eNodeB IPv4 transport address (DL GTP-U destination).
    pub enb_ip:   [u8; 4],
    /// eNodeB GTP-U port in host byte order (standard: 2152).
    pub enb_port: u16,
    /// Explicit zero padding to reach natural u32 alignment multiple.
    /// Must be zero; mirrors the `_pad` field in the kernel struct.
    pub _pad:     [u8; 2],
}

impl XdpRouteEntry {
    pub fn new(dl_teid: u32, enb_ip: [u8; 4], enb_port: u16) -> Self {
        Self { dl_teid, enb_ip, enb_port, _pad: [0; 2] }
    }
}

// Safety: XdpRouteEntry is #[repr(C)] with no implicit padding, no pointers,
// no references, and is valid for all bit patterns — aya::Pod requirements met.
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for XdpRouteEntry {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdp_route_entry_layout() {
        assert_eq!(
            core::mem::size_of::<XdpRouteEntry>(), 12,
            "XdpRouteEntry must be 12 bytes to match kernel struct layout"
        );
        assert_eq!(
            core::mem::align_of::<XdpRouteEntry>(), 4,
            "XdpRouteEntry must align to 4 bytes to match kernel struct"
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
      }
