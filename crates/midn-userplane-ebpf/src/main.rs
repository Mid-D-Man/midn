// crates/midn-userplane-ebpf/src/main.rs
//! midn-userplane-ebpf — XDP kernel program
//!
//! This code runs INSIDE the Linux kernel at the NIC driver hook point.
//! Constraints:
//!   - No standard library (`#![no_std]`)
//!   - No heap allocation (no alloc)
//!   - No system calls
//!   - All functions verified by the BPF verifier before loading
//!   - Stack size ≤ 512 bytes per BPF function call frame
//!
//! ## XDP action meanings
//!
//!   XDP_PASS    — hand packet to normal kernel networking stack
//!   XDP_DROP    — discard packet (fastest path)
//!   XDP_TX      — retransmit packet out the same NIC (with modified headers)
//!   XDP_REDIRECT — send to another NIC or CPU queue
//!
//! ## Current behavior (Phase 3 stub)
//!
//! All packets → XDP_PASS (kernel handles everything).
//! Phase 3 implements the GTP-U TEID lookup and header rewrite.

#![no_std]
#![no_main]

use aya_ebpf::{macros::xdp, programs::XdpContext};
use aya_ebpf::bindings::xdp_action;

mod gtp_xdp;

/// XDP hook — called for every incoming packet at NIC driver speed.
///
/// Returns an xdp_action constant to tell the kernel what to do.
/// Must never panic — the verifier ensures all paths return a valid action.
#[xdp]
pub fn midn_gtp_xdp(ctx: XdpContext) -> u32 {
    match gtp_xdp::process(ctx) {
        Ok(action) => action,
        // On any parse error, pass to kernel — never drop silently.
        Err(_)     => xdp_action::XDP_PASS,
    }
}

/// Panic handler — required for no_std binaries.
///
/// In BPF context this is unreachable if the verifier accepted the program.
/// The verifier checks all code paths; panics produce unverifiable code.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Safety: The BPF verifier ensures this is unreachable.
    loop {}
}
