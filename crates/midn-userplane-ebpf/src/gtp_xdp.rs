// crates/midn-userplane-ebpf/src/gtp_xdp.rs
//! GTP-U XDP fast path — kernel-space packet processing.
//!
//! ## Decision tree per packet (Phase 3 target)
//!
//! ```text
//! 1. Is this Ethernet + IPv4 + UDP?    No  → XDP_PASS
//! 2. Is UDP dst port 2152 (GTP-U)?     No  → XDP_PASS
//! 3. Parse GTP-U header (8 bytes)
//! 4. Is msg_type == 0xFF (G-PDU)?      No  → XDP_PASS (echo etc → userspace)
//! 5. Extract UL TEID from GTP header
//! 6. bpf_map_lookup_elem(teid_map, teid) → RouteEntry
//!                                      Miss → XDP_PASS (unknown → userspace)
//! 7. Rewrite outer Ethernet/IP/UDP headers with DL destination
//! 8. XDP_TX — retransmit out same NIC
//! ```
//!
//! ## BPF maps required (Phase 3)
//!
//! ```text
//! teid_to_route: BPF_MAP_TYPE_HASH
//!   key:   u32 (UL TEID)
//!   value: RouteEntry { dl_teid: u32, enb_ip: [u8;4], enb_port: u16, _pad: [u8;2] }
//!
//! ue_to_route: BPF_MAP_TYPE_HASH
//!   key:   [u8; 4] (UE IPv4 address)
//!   value: RouteEntry (same as above)
//! ```
//!
//! ## Stack discipline
//!
//! BPF stack ≤ 512 bytes. No local arrays larger than 64 bytes.
//! Packet data accessed only via ctx.data/data_end bounds-checked pointers.

use aya_ebpf::{bindings::xdp_action, programs::XdpContext};

// ── Wire format constants ─────────────────────────────────────────────────────

const ETH_P_IP:   u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
const GTP_PORT:   u16 = 2152;
const GTP_MSG_GPDU: u8 = 0xFF;
const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const GTP_HDR_LEN: usize = 8;

/// Process one incoming packet. Returns the XDP action.
///
/// Current implementation: always XDP_PASS (Phase 3 stub).
#[inline(always)]
pub fn process(_ctx: XdpContext) -> Result<u32, ()> {
    // TODO Phase 3: implement the full decision tree above.
    //
    // Step 1: bounds-check ETH header
    // let data     = ctx.data() as *const u8;
    // let data_end = ctx.data_end() as *const u8;
    // if (data as usize + ETH_HDR_LEN) > data_end as usize { return Ok(XDP_PASS); }
    //
    // Step 2: check EtherType == IPv4
    // let eth_type = u16::from_be_bytes([*data.add(12), *data.add(13)]);
    // if eth_type != ETH_P_IP { return Ok(XDP_PASS); }
    //
    // Step 3..8: parse IP/UDP/GTP, map lookup, header rewrite, XDP_TX
    //
    // Reference: samples/bpf/xdp_fwd_kern.c in the Linux kernel tree

    Ok(xdp_action::XDP_PASS)
}
