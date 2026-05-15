// crates/midn-userplane/src/ebpf/loader.rs
//! XDP program loader using Aya.
//!
//! ## Phase 3 activation checklist
//!
//! 1. Uncomment aya-build in build-dependencies
//! 2. Uncomment BPF_OBJECT include_bytes!
//! 3. Install bpf-linker: `cargo install bpf-linker`
//! 4. Build eBPF crate: see docs/phase3-userplane.md
//! 5. Uncomment load_xdp body
//! 6. Wire loader into TunnelManager::start()

/// Embedded XDP program object (compiled from midn-userplane-ebpf).
/// Uncomment when Phase 3 build pipeline is ready.
// static BPF_OBJECT: &[u8] =
//     include_bytes!(concat!(env!("OUT_DIR"), "/midn_gtp_xdp.bpf.o"));

/// Load and attach the XDP program to a network interface.
///
/// # Arguments
/// * `iface` — Linux network interface name (e.g. `"eth0"`, `"ens3"`)
///
/// # Returns
/// An owned Bpf handle that keeps the program attached for its lifetime.
/// Drop it to detach.
pub async fn load_xdp(_iface: &str) -> Result<(), Box<dyn std::error::Error>> {
    // TODO Phase 3 — uncomment when aya-build pipeline is ready:
    //
    // let mut bpf = aya::Bpf::load(BPF_OBJECT)?;
    // aya_log::BpfLogger::init(&mut bpf)?;
    //
    // let program: &mut aya::programs::Xdp =
    //     bpf.program_mut("midn_gtp_xdp")
    //        .ok_or("XDP program not found")?
    //        .try_into()?;
    // program.load()?;
    // program.attach(_iface, aya::programs::XdpFlags::default())?;
    //
    // Ok(bpf)

    Err("Phase 3: eBPF XDP loader not yet implemented".into())
}
