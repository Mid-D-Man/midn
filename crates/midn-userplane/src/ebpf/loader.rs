//! eBPF program loader using Aya.
//!
//! Phase 3 target — loads the XDP program onto the NIC.

/// Embedded BPF object compiled from midn-userplane-ebpf.
/// Uncomment when Phase 3 eBPF work begins.
// static BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/midn_xdp.bpf.o"));

/// Load and attach the XDP program to a network interface.
///
/// # Arguments
/// * `iface` - Network interface name (e.g. "eth0", "ens3")
pub async fn load_xdp(_iface: &str) -> Result<(), Box<dyn std::error::Error>> {
    // TODO Phase 3:
    // let bpf = aya::Bpf::load(BPF_OBJECT)?;
    // let program: &mut aya::programs::Xdp = bpf.program_mut("gtp_xdp").unwrap().try_into()?;
    // program.load()?;
    // program.attach(iface, aya::programs::XdpFlags::default())?;
    todo!("Phase 3: eBPF XDP loader")
}
