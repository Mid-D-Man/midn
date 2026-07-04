// crates/midn-userplane-ebpf/src/main.rs
//! midn-userplane-ebpf — XDP kernel program(s)
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
//!   XDP_PASS     — hand packet to normal kernel networking stack
//!   XDP_DROP     — discard packet (fastest path)
//!   XDP_TX       — retransmit packet out the same NIC (with modified headers)
//!   XDP_REDIRECT — send to another NIC or CPU queue
//!
//! ## Two independent programs, one compiled object
//!
//! `midn_gtp_xdp` (UL, `gtp_xdp.rs`) — attached to the eNodeB-facing interface.
//!   Strips GTP-U tunnel headers from UE→internet traffic and XDP_TX's the
//!   inner IP packet toward the PDN gateway. Phase 3.1 — complete.
//!
//! `midn_gtp_dl_xdp` (DL, `gtp_dl_xdp.rs`) — attached to the PDN-facing
//!   interface. Wraps internet→UE traffic in a new GTP-U tunnel and
//!   XDP_REDIRECTs it toward the eNodeB-facing interface. Phase 3.2 — active.
//!
//! Both live in this single `[[bin]]` — aya-build compiles one ELF object
//! with one section per `#[xdp]` function, and userspace loads each by name
//! independently (`BpfHandle::attach` for UL, `BpfHandle::attach_dl` for DL)
//! via `bpf.program_mut("midn_gtp_xdp")` / `bpf.program_mut("midn_gtp_dl_xdp")`
//! against the one loaded `aya::Ebpf` object. No build.rs or Cargo.toml
//! changes were needed to add the second program.
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

mod gtp_dl_xdp;
mod gtp_xdp;
mod maps;

/// UL XDP hook — eNodeB-facing interface. Called for every incoming packet
/// at NIC driver speed. Delegates to `gtp_xdp::process`.
///
/// On any parse error the packet is passed to the kernel — a parse failure
/// never silently drops traffic.
#[xdp]
pub fn midn_gtp_xdp(ctx: XdpContext) -> u32 {
    match gtp_xdp::process(ctx) {
        Ok(action) => action,
        Err(_)     => xdp_action::XDP_PASS,
    }
}

/// DL XDP hook — PDN-facing interface. Called for every incoming packet at
/// NIC driver speed. Delegates to `gtp_dl_xdp::process_dl`.
///
/// On any parse error, or if `bpf_redirect` itself fails, the packet is
/// passed to the kernel rather than dropped.
#[xdp]
pub fn midn_gtp_dl_xdp(ctx: XdpContext) -> u32 {
    match gtp_dl_xdp::process_dl(ctx) {
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
