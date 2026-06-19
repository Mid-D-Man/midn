// crates/midn-userplane-ebpf/src/gtp_xdp.rs
//! GTP-U XDP fast path — 8-step decision tree.
//!
//! ## Decision tree (per incoming Ethernet frame)
//!
//! 1. Ethernet EtherType == 0x0800 (IPv4)?            No  → XDP_PASS
//! 2. IPv4 protocol == 17 (UDP)?                      No  → XDP_PASS
//! 3. UDP dst_port == 2152 (GTP-U port)?              No  → XDP_PASS
//! 4. Parse GTP-U mandatory header (8 bytes).
//! 5. GTP-U msg_type == 0xFF (G-PDU)?                 No  → XDP_PASS
//! 6. TEID_TO_ROUTE.get(teid)?                        Miss → XDP_PASS
//! 7. Strip outer ETH/IP/UDP/GTP-U, keep 14 bytes for new ETH header.
//!    Implemented as a single `bpf_xdp_adjust_head(+(outer_len - 14))` call.
//! 8. Write new Ethernet header from PDN_GW_CONFIG[0]; return XDP_TX.
//!
//! ## Phase 3.1 — all 8 steps active
//!
//! Steps 1–6: classify and validate (unchanged from Phase 3.0).
//! Steps 7–8: header rewrite + XDP_TX — active.
//!
//! The XDP_TX path is used for **UL packets only** (UE → internet):
//!   eNodeB → UPF NIC → [XDP strips GTP-U, rewrites ETH] → PDN router → internet
//!
//! DL packets (internet → UE) do not arrive on port 2152 and are passed by
//! step 3. They are handled by the userspace `GtpForwarder`.
//!
//! ## Single-call header rewrite (Steps 7–8)
//!
//! Rather than two `bpf_xdp_adjust_head` calls (strip-all then re-add ETH),
//! we use one call with `delta = outer_len - ETH_HDR_LEN`:
//!
//! ```text
//! Before: [ETH(14)][IP(ihl)][UDP(8)][GTP(8..12)][InnerIP...]
//!          ^                                                  ^
//!          data                                           data_end
//!
//! bpf_xdp_adjust_head(+(outer_len - 14)):
//!
//! After:  [14-byte write area][InnerIP...]
//!          ^                              ^
//!          data (new)               data_end
//! ```
//!
//! The 14-byte write area was the tail of the outer GTP-U header.
//! We overwrite it with the new Ethernet header pointing to the PDN gateway.
//! `outer_len - 14` is always ≥ 36 (min: ETH=14, IP=20, UDP=8, GTP=8 → 50 - 14 = 36).
//!
//! ## BPF stack budget
//!
//! Local variables in `process`: ~56 bytes. BPF verifier limit: 512 bytes.
//!
//! ## Activating Phase 3.2 (DL XDP_TX via XDP_REDIRECT)
//!
//! DL packets (from internet) arrive on a different port/NIC path.
//! A second XDP program on the PDN-facing interface could intercept them,
//! add GTP-U headers, and XDP_REDIRECT to the eNodeB-facing interface.
//! Out of scope until Phase 3.2.

// `EbpfContext` provides `.as_ptr()` / `.data()` / `.data_end()` on XdpContext.
// Without this import, the compiler can see the trait is implemented for
// XdpContext but won't let you call its methods (E0599).
use aya_ebpf::{bindings::xdp_action, programs::XdpContext, EbpfContext};

use crate::maps::{PdnGwConfig, XdpRouteEntry, PDN_GW_CONFIG, TEID_TO_ROUTE};

// ── Protocol constants ────────────────────────────────────────────────────────

const ETH_P_IP:     u16 = 0x0800;
const IPPROTO_UDP:  u8  = 17;
const GTP_PORT:     u16 = 2152;
const GTP_MSG_GPDU: u8  = 0xFF;

// ── Fixed byte offsets ────────────────────────────────────────────────────────

const ETH_ETHERTYPE_OFF:  usize = 12;
const ETH_HDR_LEN:        usize = 14;

const IP_VERSION_IHL_OFF: usize = 0;
const IP_PROTOCOL_OFF:    usize = 9;
const IPV4_MIN_HDR_LEN:   usize = 20;

const UDP_DST_PORT_OFF:   usize = 2;
const UDP_HDR_LEN:        usize = 8;

const GTP_FLAGS_OFF:      usize = 0;
const GTP_MSGTYPE_OFF:    usize = 1;
const GTP_TEID_OFF:       usize = 4;
const GTP_MANDATORY_LEN:  usize = 8;

/// GTP-U flags bits 0-2. If any are set, 4 optional bytes follow the mandatory 8.
const GTP_OPT_FLAGS_MASK: u8 = 0x07;

// ── Bounds-checked packet readers ─────────────────────────────────────────────
//
// Each helper re-derives the pointer from `ctx.data()` on every call so it
// remains valid across `bpf_xdp_adjust_head` boundaries. The BPF verifier
// requires that every packet access be guarded by a bounds check visible in
// the same IR basic block.

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
/// Returns `Ok(XDP_PASS | XDP_TX)` on clean classification.
/// Returns `Err(())` on any parse fault; the entry point converts this to
/// `XDP_PASS` so no packet is silently dropped due to a parse error.
#[inline(always)]
pub fn process(ctx: XdpContext) -> Result<u32, ()> {

    // ── Step 1: Ethernet — require IPv4 ──────────────────────────────────────
    let ether_type = read_u16_be(&ctx, ETH_ETHERTYPE_OFF)?;
    if ether_type != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Step 2: IPv4 — require UDP, extract IHL ───────────────────────────────
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

    // ── Step 3: UDP — require GTP-U port ─────────────────────────────────────
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
    // Miss = unknown session (not yet established, or session race) → userspace.
    let _route: &XdpRouteEntry = match unsafe { TEID_TO_ROUTE.get(&teid) } {
        Some(r) => r,
        None    => return Ok(xdp_action::XDP_PASS),
    };

    // ── Steps 7–8: Ethernet header rewrite + XDP_TX ───────────────────────────
    //
    // Fetch PDN gateway config BEFORE modifying the packet.
    // Map memory is not affected by bpf_xdp_adjust_head — `cfg` stays valid.
    let cfg: &PdnGwConfig = match unsafe { PDN_GW_CONFIG.get(0) } {
        Some(c) => c,
        None    => return Ok(xdp_action::XDP_PASS), // UPF startup not yet complete
    };

    // Compute the total outer tunnel header length to strip.
    // GTP optional fields (E|S|PN bits 0-2) add 4 bytes after the mandatory 8.
    let gtp_total = GTP_MANDATORY_LEN
        + if gtp_flags & GTP_OPT_FLAGS_MASK != 0 { 4 } else { 0 };
    let outer_len = ETH_HDR_LEN + ihl + UDP_HDR_LEN + gtp_total;

    // `strip` = outer_len - ETH_HDR_LEN:
    //   Moving data forward by `strip` bytes leaves ctx.data() pointing
    //   ETH_HDR_LEN (14) bytes before the inner IP packet.
    //   That 14-byte region (former tail of the outer GTP-U header) becomes
    //   our write area for the new Ethernet header.
    //
    //   outer_len ≥ 14 + 20 + 8 + 8 = 50  →  strip ≥ 36 > 0  (always positive)
    //
    // bpf_xdp_adjust_head with positive delta: moves data pointer forward
    // (shrinks packet from the front). Returns 0 on success, < 0 on failure.
    let strip = (outer_len - ETH_HDR_LEN) as i32;
    if unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.as_ptr(), strip) } < 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // After adjust_head, ALL previous packet pointer arithmetic is invalid.
    // Re-derive from ctx.data() / ctx.data_end() (these re-read xdp_md each call).
    //
    // ctx.data() now points at the 14-byte write area.
    // ctx.data() + 14 is the start of the inner IP packet.
    let eth_ptr = ctx.data() as *mut u8;
    if ctx.data() + ETH_HDR_LEN > ctx.data_end() {
        // Shouldn't happen: inner IP must still be there. Bail safely.
        return Ok(xdp_action::XDP_PASS);
    }

    // Write new Ethernet header: [dst_mac(6)][src_mac(6)][ethertype(2)]
    //
    // dst = PDN gateway / next-hop router MAC  (traffic toward internet)
    // src = UPF NIC MAC
    // EtherType = IPv4 (0x0800, big-endian)
    //
    // Safety: bounds check above establishes [eth_ptr, eth_ptr+14) is in packet.
    //         cfg is BPF map memory — always valid, not affected by adjust_head.
    //         copy_nonoverlapping: src (map) and dst (packet) are disjoint regions.
    unsafe {
        core::ptr::copy_nonoverlapping(cfg.gw_mac.as_ptr(),  eth_ptr,        6);
        core::ptr::copy_nonoverlapping(cfg.nic_mac.as_ptr(), eth_ptr.add(6), 6);
        eth_ptr.add(12).write(0x08_u8); // EtherType high byte
        eth_ptr.add(13).write(0x00_u8); // EtherType low byte
    }

    // Transmit back out the same NIC. The packet now looks like:
    //   [NewETH][InnerIP][InnerPayload]
    // The PDN gateway / router routes it toward the internet.
    Ok(xdp_action::XDP_TX)
}
