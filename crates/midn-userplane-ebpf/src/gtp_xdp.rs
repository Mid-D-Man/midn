//! GTP-U XDP fast path.
//!
//! Decision tree (per packet):
//!   1. Is this UDP on port 2152?
//!      No  → XDP_PASS (let kernel handle it)
//!   2. Parse GTP-U header — is it a G-PDU?
//!      No  → XDP_PASS (echo request etc, let userspace handle)
//!   3. Look up TEID in BPF hash map → Route entry
//!      Miss → XDP_PASS (unknown tunnel, userspace creates it)
//!   4. Rewrite outer IP/UDP headers with destination route
//!      → XDP_TX (send back out the same NIC, redirected)

use aya_ebpf::programs::XdpContext;
use aya_ebpf::bindings::xdp_action;

/// Process a single incoming packet.
/// Returns the XDP action to take.
pub fn process_packet(_ctx: XdpContext) -> Result<u32, ()> {
    // TODO Phase 3:
    // 1. Check Ethernet header → is IP?
    // 2. Check IP → is UDP?
    // 3. Check UDP dst port == 2152 (GTP-U)
    // 4. Parse 8-byte GTP-U header, extract TEID
    // 5. BPF map lookup: teid → route_entry
    // 6. Rewrite headers, XDP_TX
    Ok(xdp_action::XDP_PASS)
}
