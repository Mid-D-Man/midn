// crates/midn-userplane-ebpf/src/gtp_dl_xdp.rs
//! GTP-U DL (downlink) XDP fast path — Phase 3.2.
//!
//! Reverse direction of `gtp_xdp.rs`. Attached to the **PDN-facing**
//! interface (not the eNodeB-facing one `midn_gtp_xdp` sits on). Intercepts
//! plain IPv4 packets arriving from the internet whose destination address
//! is a known UE, wraps them in a GTP-U tunnel, and `XDP_REDIRECT`s them out
//! the eNodeB-facing interface.
//!
//! ## Decision tree (per incoming Ethernet frame, PDN-facing side)
//!
//! 1. Ethernet EtherType == 0x0800 (IPv4)?              No  → XDP_PASS
//! 2. Read inner IP dst address (fixed offset — IHL doesn't matter here,
//!    we never touch inner IP options, only the dst field at a fixed offset).
//! 3. UE_IP_TO_ROUTE.get(dst_ip)?                        Miss → XDP_PASS
//! 4. route.dl_teid == 0 (placeholder, bearer not yet confirmed)? → XDP_PASS
//! 5. DL_TUNNEL_CONFIG.get(0)?                           Miss → XDP_PASS
//! 6. Grow headroom by 36 bytes via a single `bpf_xdp_adjust_head` call.
//! 7. Write new ETH(14)+IP(20)+UDP(8)+GTP(8) = 50-byte header block.
//! 8. `bpf_redirect(redirect_ifindex, 0)` toward the eNodeB-facing interface.
//!
//! Unlike the UL path (which only checks *presence* in `TEID_TO_ROUTE` — it
//! never reads `dl_teid` or `enb_ip`), this path reads both out of the route
//! entry to build the tunnel, so step 4's placeholder check is load-bearing:
//! without it, a session between `CreateSession` and `UpdateBearer` would
//! tunnel toward `enb_ip = [0;4]` instead of safely deferring to userspace.
//!
//! ## Why no L4 protocol filter (unlike the UL path's UDP:2152 check)
//!
//! The UL path only intercepts GTP-U-encapsulated traffic (always UDP:2152).
//! The DL path intercepts the UE's *own* traffic in its native protocol —
//! TCP, UDP, ICMP, whatever the UE's peer sent — so there is nothing to
//! filter on beyond "is this IPv4, and does the destination match a UE we
//! know about". The `UE_IP_TO_ROUTE` lookup itself is the filter: an unknown
//! destination IP (anything not a provisioned UE) misses and falls through.
//!
//! ## Single-call header growth (steps 6–7) — mirror image of the UL trick
//!
//! The UL path *shrinks* the packet with one `bpf_xdp_adjust_head` call by
//! reusing the tail of the stripped tunnel header as the new (smaller) write
//! area. The DL path *grows* the packet, and applies the same idea in
//! reverse: rather than growing by the full 50 new header bytes and leaving
//! the original 14-byte Ethernet header as an orphaned gap, we grow by only
//! `50 - 14 = 36` bytes and treat the *old* Ethernet header's 14 bytes as
//! part of the new 50-byte write area.
//!
//! ```text
//! Before: [ETH_orig(14)][InnerIP(ihl)...]
//!          ^                              ^
//!          data                      data_end
//!
//! bpf_xdp_adjust_head(-(50 - 14)) = bpf_xdp_adjust_head(-36):
//!
//! After:  [ 36 new bytes ][ETH_orig(14) — now fair game][InnerIP...]
//!          ^                                            ^
//!          data (new)                        data (new) + 50 == old InnerIP start
//! ```
//!
//! The combined 50-byte region `[data, data+50)` is what we overwrite with
//! the new ETH/IP/UDP/GTP-U headers. The original inner IP packet — which
//! never moved — becomes the GTP-U payload untouched.
//!
//! ## Headroom availability
//!
//! `bpf_xdp_adjust_head` with a negative delta requires that many bytes of
//! *headroom* before the current `data` pointer. Most NIC drivers reserve
//! `XDP_PACKET_HEADROOM` (256 bytes) by default, comfortably more than the
//! 36 bytes needed here. If headroom is insufficient (uncommon driver/MTU
//! configuration), the helper returns < 0 and we fall through to XDP_PASS —
//! same fail-safe convention as the UL path.
//!
//! ## Outer IP header checksum
//!
//! Computed in software (RFC 1071 one's-complement sum) over the 20-byte
//! outer IP header we just constructed. See `ip_header_checksum` below —
//! manually unrolled (no loop) so there's no dependency on the BPF verifier's
//! bounded-loop support for whatever kernel this ends up running on.
//!
//! ## Outer UDP checksum
//!
//! Set to `0` (no checksum) — valid per RFC 768 for IPv4, and standard
//! practice in high-performance GTP-U implementations to avoid computing a
//! checksum over the (potentially large) inner payload on every packet.
//! Revisit only if a real deployment's middleboxes reject zero-checksum UDP.
//!
//! ## BPF stack budget
//!
//! Local variables in `process_dl`: the 50-byte header-write buffer plus a
//! handful of small values (~90 bytes total). BPF verifier limit: 512 bytes.
//!
//! ## Calling raw helpers — typed pointer, not `as_ptr()`
//!
//! Same rule as `gtp_xdp.rs`: use `ctx.ctx` (the typed `*mut xdp_md`), not
//! `ctx.as_ptr()` (`*mut c_void`), when calling `bpf_xdp_adjust_head` directly.

use aya_ebpf::{bindings::xdp_action, programs::XdpContext};

use crate::maps::{DlTunnelConfig, XdpRouteEntry, DL_TUNNEL_CONFIG, UE_IP_TO_ROUTE};

// ── Protocol constants ────────────────────────────────────────────────────────

const ETH_P_IP:    u16 = 0x0800;
const GTP_PORT:    u16 = 2152;
const GTP_MSG_GPDU: u8 = 0xFF;
/// `GtpuHeader::FLAGS_STANDARD` in midn-proto: version=1, PT=1, no optional fields.
const GTP_FLAGS_STANDARD: u8 = 0x30;

// ── Fixed byte offsets ────────────────────────────────────────────────────────

const ETH_ETHERTYPE_OFF: usize = 12;
const ETH_HDR_LEN:       usize = 14;

/// Offset of the destination address field within any IPv4 header — fixed
/// regardless of IHL, since it precedes the variable-length options region.
const IP_DST_OFF: usize = 16;

const IP_OUTER_LEN: usize = 20;
const UDP_HDR_LEN:  usize = 8;
const GTP_HDR_LEN:  usize = 8;

/// Total new header block written per DL hit: ETH + IP + UDP + GTP.
const NEW_HDRS_LEN: usize = ETH_HDR_LEN + IP_OUTER_LEN + UDP_HDR_LEN + GTP_HDR_LEN; // 50

/// `bpf_xdp_adjust_head` delta magnitude — see module doc "Single-call header
/// growth". We only need to grow by the part of `NEW_HDRS_LEN` not already
/// covered by reusing the original 14-byte Ethernet header's space.
const ADJUST_HEAD_GROW: i32 = -((NEW_HDRS_LEN - ETH_HDR_LEN) as i32); // -36

// ── Bounds-checked packet readers ─────────────────────────────────────────────
//
// Duplicated from gtp_xdp.rs rather than shared: that file is Phase-3.1
// complete and verifier-clean, and this module has different bounds-check
// needs (reads a fixed IP field rather than walking a variable-length UDP
// prefix). Keeping each XDP entry point's helpers local keeps every file
// independently reviewable against the verifier without cross-module effects.

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
fn read_u16_be(ctx: &XdpContext, offset: usize) -> Result<u16, ()> {
    let p = bounds_check(ctx, offset, 2)?;
    Ok(u16::from_be_bytes(unsafe { [*p, *p.add(1)] }))
}

#[inline(always)]
fn read_ip4(ctx: &XdpContext, offset: usize) -> Result<[u8; 4], ()> {
    let p = bounds_check(ctx, offset, 4)?;
    Ok(unsafe { [*p, *p.add(1), *p.add(2), *p.add(3)] })
}

// ── IPv4 header checksum ──────────────────────────────────────────────────────

/// RFC 1071 one's-complement checksum over a 20-byte IPv4 header.
///
/// Manually unrolled into 10 fixed word additions — deliberately not a
/// `for`/`while` loop. This is pure stack-local computation (no packet
/// pointers), so it doesn't need the verifier's help either way, but keeping
/// it loop-free means there is zero ambiguity about verifier acceptance
/// across kernel versions with differing bounded-loop support.
///
/// Caller must have already zeroed the checksum field (bytes 10-11) in
/// `header` before calling this.
#[inline(always)]
fn ip_header_checksum(h: &[u8; 20]) -> u16 {
    let mut sum: u32 =
        (u16::from_be_bytes([h[0],  h[1]])  as u32) +
        (u16::from_be_bytes([h[2],  h[3]])  as u32) +
        (u16::from_be_bytes([h[4],  h[5]])  as u32) +
        (u16::from_be_bytes([h[6],  h[7]])  as u32) +
        (u16::from_be_bytes([h[8],  h[9]])  as u32) +
        (u16::from_be_bytes([h[10], h[11]]) as u32) +
        (u16::from_be_bytes([h[12], h[13]]) as u32) +
        (u16::from_be_bytes([h[14], h[15]]) as u32) +
        (u16::from_be_bytes([h[16], h[17]]) as u32) +
        (u16::from_be_bytes([h[18], h[19]]) as u32);
    // Fold carry bits back in. Two folds are always enough: summing ten
    // u16 values yields at most a 20-bit result, so the first fold's carry
    // is at most a few bits and the second fold fully absorbs it.
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    !(sum as u16)
}

// ── Main processing function ──────────────────────────────────────────────────

/// Process one incoming Ethernet frame on the PDN-facing interface.
///
/// Returns `Ok(XDP_PASS | XDP_REDIRECT)` on clean classification.
/// Returns `Err(())` on any parse fault; the entry point converts this to
/// `XDP_PASS` so no packet is silently dropped due to a parse error.
#[inline(always)]
pub fn process_dl(ctx: XdpContext) -> Result<u32, ()> {

    // ── Step 1: Ethernet — require IPv4 ──────────────────────────────────────
    let ether_type = read_u16_be(&ctx, ETH_ETHERTYPE_OFF)?;
    if ether_type != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Step 2: read inner IP destination address ────────────────────────────
    // Fixed offset regardless of IHL — dst address always precedes options.
    let ip_start = ETH_HDR_LEN;
    let dst_ip   = read_ip4(&ctx, ip_start + IP_DST_OFF)?;

    // ── Step 3: UE_IP_TO_ROUTE lookup ─────────────────────────────────────────
    // Miss = not a known UE destination (ordinary internet traffic passing
    // through this interface, or an unprovisioned/torn-down session) → kernel
    // stack / userspace handles it normally.
    let route: &XdpRouteEntry = match unsafe { UE_IP_TO_ROUTE.get(&dst_ip) } {
        Some(r) => r,
        None    => return Ok(xdp_action::XDP_PASS),
    };

    // ── Step 4: placeholder gate ───────────────────────────────────────────────
    // dl_teid == 0 means CreateSession ran but UpdateBearer hasn't fired yet —
    // enb_ip is still [0;4]. Tunneling now would misdirect the packet instead
    // of just deferring it, so this must XDP_PASS, not fast-path.
    if route.dl_teid == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Step 5: DL tunnel config ───────────────────────────────────────────────
    let cfg: &DlTunnelConfig = match unsafe { DL_TUNNEL_CONFIG.get(0) } {
        Some(c) => c,
        None    => return Ok(xdp_action::XDP_PASS), // UPF DL startup not yet complete
    };

    // Snapshot everything we need from map memory BEFORE adjust_head — map
    // reads stay valid afterward too (maps aren't packet memory), but reading
    // up front keeps the post-adjust code focused purely on packet writes.
    let dl_teid  = route.dl_teid;
    let enb_ip   = route.enb_ip;
    let enb_port = route.enb_port;
    let eth_dst  = cfg.eth_dst_mac;
    let eth_src  = cfg.eth_src_mac;
    let upf_ip   = cfg.upf_ip;
    let ifindex  = cfg.redirect_ifindex;

    // ── Step 6: grow headroom by 36 bytes (single call) ───────────────────────
    // See module doc "Single-call header growth" for why -36 and not -50.
    if unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.ctx, ADJUST_HEAD_GROW) } < 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // After adjust_head, ALL previous packet pointer arithmetic is invalid.
    // Re-derive from ctx.data() / ctx.data_end().
    //
    // ctx.data() now points at the start of the 50-byte write region;
    // ctx.data() + 50 is the start of the (unmoved) inner IP packet.
    if ctx.data() + NEW_HDRS_LEN > ctx.data_end() {
        // Shouldn't happen: the inner packet must still be there. Bail safely.
        return Ok(xdp_action::XDP_PASS);
    }

    // Inner payload length — computed from the actual buffer bounds rather
    // than re-parsing the inner IP header's own Total Length field, so it's
    // correct even if that field were ever wrong or the packet truncated.
    let inner_len = ctx.data_end() - ctx.data() - NEW_HDRS_LEN;
    if inner_len > (u16::MAX as usize - (IP_OUTER_LEN + UDP_HDR_LEN + GTP_HDR_LEN)) {
        // Absurdly large inner packet — would overflow the outer IP Total
        // Length / UDP Length fields. Never expected on real traffic; bail
        // safely rather than write a wrapped-around length field.
        return Ok(xdp_action::XDP_PASS);
    }
    let inner_len = inner_len as u16;

    let udp_len   = UDP_HDR_LEN as u16 + GTP_HDR_LEN as u16 + inner_len;       // 16 + inner
    let outer_len = IP_OUTER_LEN as u16 + udp_len;                            // 20 + udp_len

    // ── Step 7: build the 50-byte header block in a local buffer ─────────────
    // Assembled locally (not written field-by-field into packet memory)
    // because the IP checksum must be computed over the fully-formed
    // 20-byte IP header before it's written out.
    let mut hdrs = [0u8; NEW_HDRS_LEN];

    // Ethernet (14 bytes: offsets 0..14)
    hdrs[0..6].copy_from_slice(&eth_dst);
    hdrs[6..12].copy_from_slice(&eth_src);
    hdrs[12] = 0x08; // EtherType high byte
    hdrs[13] = 0x00; // EtherType low byte (0x0800 = IPv4)

    // Outer IPv4 (20 bytes: offsets 14..34)
    let ip = 14;
    hdrs[ip]      = 0x45; // version=4, IHL=5 (20 bytes, no options)
    hdrs[ip + 1]  = 0x00; // DSCP/ECN
    hdrs[ip + 2..ip + 4].copy_from_slice(&outer_len.to_be_bytes());
    hdrs[ip + 4..ip + 6].copy_from_slice(&0u16.to_be_bytes()); // identification
    hdrs[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, frag_off=0
    hdrs[ip + 8]  = 64;   // TTL
    hdrs[ip + 9]  = 17;   // protocol = UDP
    hdrs[ip + 10..ip + 12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    hdrs[ip + 12..ip + 16].copy_from_slice(&upf_ip);
    hdrs[ip + 16..ip + 20].copy_from_slice(&enb_ip);

    // Compute and fill in the real IP header checksum now that every other
    // field in the 20-byte header is final.
    let ip_hdr_bytes: [u8; 20] = hdrs[ip..ip + 20].try_into().unwrap_or([0u8; 20]);
    let ip_csum = ip_header_checksum(&ip_hdr_bytes);
    hdrs[ip + 10..ip + 12].copy_from_slice(&ip_csum.to_be_bytes());

    // Outer UDP (8 bytes: offsets 34..42)
    let udp = ip + IP_OUTER_LEN;
    hdrs[udp..udp + 2].copy_from_slice(&GTP_PORT.to_be_bytes());     // src port 2152
    hdrs[udp + 2..udp + 4].copy_from_slice(&enb_port.to_be_bytes()); // dst port (usually 2152)
    hdrs[udp + 4..udp + 6].copy_from_slice(&udp_len.to_be_bytes());
    hdrs[udp + 6..udp + 8].copy_from_slice(&0u16.to_be_bytes());     // checksum = 0 (optional, see module doc)

    // GTP-U mandatory header (8 bytes: offsets 42..50)
    let gtp = udp + UDP_HDR_LEN;
    hdrs[gtp]     = GTP_FLAGS_STANDARD;
    hdrs[gtp + 1] = GTP_MSG_GPDU;
    hdrs[gtp + 2..gtp + 4].copy_from_slice(&inner_len.to_be_bytes());
    hdrs[gtp + 4..gtp + 8].copy_from_slice(&dl_teid.to_be_bytes());

    // Single write into packet memory — bounds already established above.
    let write_ptr = ctx.data() as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(hdrs.as_ptr(), write_ptr, NEW_HDRS_LEN);
    }

    // ── Step 8: redirect toward the eNodeB-facing interface ──────────────────
    // For XDP, bpf_redirect() returns XDP_REDIRECT on success or XDP_ABORTED
    // on error — return its result directly rather than assuming success.
    let action = unsafe { aya_ebpf::helpers::bpf_redirect(ifindex, 0) };
    Ok(action as u32)
}
