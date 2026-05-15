//! midn-userplane-ebpf — XDP kernel program
//!
//! This runs INSIDE the Linux kernel at the NIC driver level.
//! No standard library. No heap allocation. No system calls.
//!
//! The XDP hook fires for every incoming packet BEFORE the kernel
//! networking stack processes it — lowest possible latency.

#![no_std]
#![no_main]

use aya_ebpf::{macros::xdp, programs::XdpContext};
use aya_ebpf::bindings::xdp_action;

mod gtp_xdp;

/// XDP entry point — called per-packet at NIC speed.
#[xdp]
pub fn midn_gtp_xdp(ctx: XdpContext) -> u32 {
    match gtp_xdp::process_packet(ctx) {
        Ok(action) => action,
        Err(_)     => xdp_action::XDP_PASS,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Kernel panics are fatal — but in BPF context we just loop.
    // The verifier ensures this is unreachable in practice.
    loop {}
}
