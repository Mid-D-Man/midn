// crates/midn-userplane-ebpf/src/gtp_xdp.rs
//! GTP-U XDP fast path — 8-step decision tree.
//!
//! ## Decision tree (per incoming Ethernet frame)
//!
//! 1. Ethernet EtherType == 0x0800 (IPv4)?         No  → XDP_PASS
//! 2. IPv4 protocol == 17 (UDP)?                   No  → XDP_PASS
//! 3. UDP dst_port == 2152 (GTP-U port)?           No  → XDP_PASS
//! 4. Parse GTP-U mandatory header (8 bytes).
//! 5. GTP-U msg_type == 0xFF (G-PDU)?              No  → XDP_PASS
//! 6. TEID_TO_ROUTE.get(teid)?                     Miss → XDP_PASS
//! 7. Strip outer ETH/IP/UDP/GTP-U headers; prepend PDN-facing ETH header.
//! 8. XDP_TX.
//!
//! ## Phase 3.0 status
//!
//! Steps 1–6 are fully implemented and BPF-verifier clean.
//! Steps 7–8 fall through to `XDP_PASS` — the userspace `GtpForwarder`
//! handles actual packet forwarding until Phase 3.1 activates `XDP_TX`.
//!
//! ## Activating Phase 3.1 (XDP_TX header rewrite)
//!
//! 1. Compute total outer header length to strip:
//!    ```text
//!    outer_len = ETH(14) + IP(ihl) + UDP(8) + GTP(8) + GTP_OPT(4 if E|S|PN set)
//!    ```
//!
//! 2. Strip outer headers:
//!    ```rust
//!    unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.as_ptr(), outer_len as i32) };
//!    // data() now points at inner IPv4 header.
//!    ```
//!
//! 3. Make room for new Ethernet header and write it:
//!    ```rust
//!    unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.as_ptr(), -(14_i32)) };
//!    let new_eth = (ctx.data() as *mut EthHdr);
//!    (*new_eth).dst_mac    = PDN_GW_CONFIG[0].gw_mac;  // from a new BPF map
//!    (*new_eth).src_mac    = PDN_GW_CONFIG[0].nic_mac;
//!    (*new_eth).ether_type = ETH_P_IP.to_be();
//!    ```
//!
//! 4. Return `Ok(xdp_action::XDP_TX)`.
//!
//! Required additional BPF map (add to maps.rs):
//! ```rust
//! #[repr(C)]
//! pub struct PdnGwConfig { pub gw_mac: [u8; 6], pub nic_mac: [u8; 6] }
//! #[map]
//! pub static PDN_GW_CONFIG: aya_ebpf::maps::Array<u32, PdnGwConfig> =
//!     aya_ebpf::maps::Array::with_max_entries(1, 0);
//! ```
//!
//! ## BPF stack budget
//!
//! Local variables in `process`: ~48 bytes. BPF verifier limit: 512 bytes.

use aya_ebpf::{bindings::xdp_action, programs::XdpContext};

use crate::maps::{XdpRouteEntry, TEID_TO_ROUTE};

// ── Protocol constants ────────────────────────────────────────────────────────

const ETH_P_IP:     u16 = 0x0800;
const IPPROTO_UDP:  u8  = 17;
const GTP_PORT:     u16 = 2152;
const GTP_MSG_GPDU: u8  = 0xFF;

// ── Fixed byte offsets (relative to the start of each protocol header) ────────

const ETH_ETHERTYPE_OFF:   usize = 12; // 2 bytes, big-endian
const ETH_HDR_LEN:         usize = 14;

const IP_VERSION_IHL_OFF:  usize = 0;  // 1 byte
const IP_PROTOCOL_OFF:     usize = 9;  // 1 byte
const IPV4_MIN_HDR_LEN:    usize = 20;

const UDP_DST_PORT_OFF:    usize = 2;  // 2 bytes, big-endian
const UDP_HDR_LEN:         usize = 8;

const GTP_FLAGS_OFF:       usize = 0;  // 1 byte
const GTP_MSGTYPE_OFF:     usize = 1;  // 1 byte
const GTP_TEID_OFF:        usize = 4;  // 4 bytes, big-endian
const GTP_MANDATORY_LEN:   usize = 8;

/// Bits 0-2 of the GTP-U flags byte. If any are set, 4 optional bytes follow
/// the mandatory 8-byte header (seq-num 2B + N-PDU 1B + next-ext-type 1B).
const GTP_OPT_FLAGS_MASK:  u8 = 0x07;

// ── Bounds-checked packet readers ─────────────────────────────────────────────
//
// Pattern accepted by the BPF verifier:
//   1. Compute `ptr_end = data + offset + size`.
//   2. If `ptr_end > data_end` → return error (verifier sees the guard).
//   3. Subsequent reads within [ptr, ptr_end) are proven safe.
//
// All reads use single-byte `*const u8` pointers to avoid alignment UB —
// network headers are not guaranteed to be aligned to their field sizes.

/// Return a `*const u8` pointing to `offset` bytes from packet start, after
/// verifying that at least `size` bytes exist from that offset.
#[inline(always)]
fn bounds_check(ctx: &XdpContext, offset: usize, size: usize) -> Result<*const u8, ()> {
    let start    = ctx.data();
    let end      = ctx.data_end();
    let byte_end = start.saturating_add(offset).saturating_add(size);
    if byte_end > end {
        return Err(());
    }
    Ok((start + offset) as *const u8)
}

#[inline(always)]
fn read_u8(ctx: &XdpContext, offset: usize) -> Result<u8, ()> {
    let p = bounds_check(ctx, offset, 1)?;
    Ok(unsafe { *p })
}

#[inline(always)]
fn read_u16_be(ctx: &XdpContext, offset: usize) -> Result<u16, ()> {
    let p = bounds_check(ctx, offset, 2)?;
    Ok(u16::from_be_bytes(unsafe { [*p, *p.add(1)] }))
}

#[inline(always)]
fn read_u32_be(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let p = bounds_check(ctx, offset, 4)?;
    Ok(u32::from_be_bytes(unsafe { [*p, *p.add(1), *p.add(2), *p.add(3)] }))
}

// ── Main processing function ──────────────────────────────────────────────────

/// Process one incoming Ethernet frame.
///
/// Returns `Ok(XDP_PASS | XDP_TX)` or `Err(())`.
/// The entry point in `main.rs` converts `Err(())` → `XDP_PASS` so no packet
/// is ever dropped silently due to a parse error.
#[inline(always)]
pub fn process(ctx: XdpContext) -> Result<u32, ()> {

    // ── Step 1: Ethernet — check IPv4 ────────────────────────────────────────
    let ether_type = read_u16_be(&ctx, ETH_ETHERTYPE_OFF)?;
    if ether_type != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Step 2: IPv4 — check UDP and extract IHL ─────────────────────────────
    let ip_start    = ETH_HDR_LEN;
    let version_ihl = read_u8(&ctx, ip_start + IP_VERSION_IHL_OFF)?;
    let ihl         = ((version_ihl & 0x0F) as usize) * 4;
    if ihl < IPV4_MIN_HDR_LEN {
        return Ok(xdp_action::XDP_PASS); // malformed IP header
    }
    let protocol = read_u8(&ctx, ip_start + IP_PROTOCOL_OFF)?;
    if protocol != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Step 3: UDP — check GTP-U port ───────────────────────────────────────
    let udp_start = ip_start + ihl;
    let dst_port  = read_u16_be(&ctx, udp_start + UDP_DST_PORT_OFF)?;
    if dst_port != GTP_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Step 4: GTP-U — parse mandatory header ────────────────────────────────
    let gtp_start = udp_start + UDP_HDR_LEN;
    let gtp_flags = read_u8(&ctx, gtp_start + GTP_FLAGS_OFF)?;
    let msg_type  = read_u8(&ctx, gtp_start + GTP_MSGTYPE_OFF)?;
    let teid      = read_u32_be(&ctx, gtp_start + GTP_TEID_OFF)?;

    // ── Step 5: G-PDU check ───────────────────────────────────────────────────
    // Echo Request/Response and other GTP-U control messages fall to userspace.
    if msg_type != GTP_MSG_GPDU {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Step 6: TEID map lookup ───────────────────────────────────────────────
    let route: &XdpRouteEntry = match unsafe { TEID_TO_ROUTE.get(&teid) } {
        Some(r) => r,
        None    => return Ok(xdp_action::XDP_PASS), // unknown session → userspace
    };

    // ── Steps 7–8: Header rewrite + XDP_TX (Phase 3.1) ───────────────────────
    //
    // Pre-compute the outer header length the rewrite will need to strip.
    // GTP optional fields (E|S|PN bits) add 4 bytes after the mandatory 8.
    let gtp_hdr_len = GTP_MANDATORY_LEN
        + if gtp_flags & GTP_OPT_FLAGS_MASK != 0 { 4 } else { 0 };
    let _outer_len = ip_start + ihl + UDP_HDR_LEN + gtp_hdr_len;

    // Route fields available for the rewrite:
    //   route.dl_teid  — DL TEID for outbound GTP-U encapsulation
    //   route.enb_ip   — eNodeB IP for DL path
    //   route.enb_port — eNodeB GTP-U port
    // (used in Phase 3.1; suppress unused-variable lint with _ binding)
    let _ = route;

    // TODO Phase 3.1 — activate XDP_TX:
    //   unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.as_ptr(), _outer_len as i32) };
    //   unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.as_ptr(), -(14_i32)) };
    //   // write new EthHdr at ctx.data() using PDN_GW_CONFIG[0]
    //   return Ok(xdp_action::XDP_TX);

    Ok(xdp_action::XDP_PASS)
    }
