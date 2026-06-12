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
//! ## Current behaviour (Phase 3.0)
//!
//! Steps 1–6 of the GTP-U decision tree are active:
//!   ETH → IPv4 → UDP:2152 → GTP-U header → G-PDU check → TEID map lookup.
//! On a TEID hit, the packet still returns XDP_PASS so the userspace
//! `GtpForwarder` handles it. Phase 3.1 activates XDP_TX with header rewrite.
//!
//! ## Build (requires nightly + bpf-linker)
//!
//! ```bash
//! rustup toolchain install nightly --component rust-src
//! cargo install bpf-linker
//! cargo +nightly build -p midn-userplane-ebpf \
//!   --release \
//!   --target bpfel-unknown-none \
//!   -Z build-std=core
//! ```

#![no_std]
#![no_main]

use aya_ebpf::{macros::xdp, programs::XdpContext};
use aya_ebpf::bindings::xdp_action;

mod gtp_xdp;
mod maps;

/// XDP hook — called for every incoming packet at NIC driver speed.
///
/// Delegates to `gtp_xdp::process`. On any parse error the packet is
/// passed to the kernel — a parse failure never silently drops traffic.
#[xdp]
pub fn midn_gtp_xdp(ctx: XdpContext) -> u32 {
    match gtp_xdp::process(ctx) {
        Ok(action) => action,
        Err(_)     => xdp_action::XDP_PASS,
    }
}

/// Panic handler — required for `#![no_std]` binaries.
///
/// Unreachable in practice: the BPF verifier rejects programs where any
/// code path could panic before loading them into the kernel.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
