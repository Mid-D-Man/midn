// crates/midn-userplane/src/ebpf/loader.rs
//! XDP program loader and kernel BPF map management.
//!
//! ## Activation matrix
//!
//! | Platform  | Feature | load_xdp result                           |
//! |-----------|---------|-------------------------------------------|
//! | non-Linux | any     | Err — platform not supported              |
//! | Linux     | —       | Err — rebuild with --features ebpf        |
//! | Linux     | ebpf    | Ok(BpfHandle) or Err (kernel/verifier)    |
//!
//! ## Phase 3.1 activation
//!
//! ```bash
//! rustup toolchain install nightly --component rust-src
//! cargo install bpf-linker
//! cargo build -p midn-userplane --features ebpf
//! ```
//!
//! UPF startup sequence:
//! ```rust,ignore
//! let mut bpf = load_xdp("eth0").await?;
//! bpf.set_pdn_gw_config(&PdnGwConfig::new(gw_mac, nic_mac))?;
//! session_manager.set_bpf_handle(bpf);
//! ```
//!
//! ## Rule 3 compliance
//!
//! BPF map entries are written in two phases:
//!   - `CreateSession` → `insert_teid(ul_teid, placeholder_dl_teid_zero)`:
//!     entry present; XDP passes until bearer confirmed.
//!   - `UpdateBearer`  → `insert_teid(ul_teid, real_entry)` atomic BPF_ANY.
//!     Fires from ICSRSP handler, before AttachAccept reaches UE via RRC.
//!     No UL packet can race the map entry.

use crate::upf::xdp_types::{PdnGwConfig, XdpRouteEntry};

// ── Error type ────────────────────────────────────────────────────────────────

pub type LoadXdpError = Box<dyn std::error::Error + Send + Sync + 'static>;

// ── Embedded BPF object (Linux + ebpf feature only) ───────────────────────────

/// Compiled XDP program embedded by aya-build.
/// Path: $OUT_DIR/midn_userplane_ebpf.bpf.o
/// (aya-build names by package name, hyphens replaced with underscores)
#[cfg(all(feature = "ebpf", target_os = "linux"))]
static BPF_OBJECT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/midn_userplane_ebpf.bpf.o"));

// ── BpfHandle ─────────────────────────────────────────────────────────────────

/// Owned handle to a loaded XDP program and its BPF maps.
///
/// Dropping detaches the XDP program from the NIC.
/// Keep alive for the lifetime of the UPF process.
#[cfg(target_os = "linux")]
pub struct BpfHandle {
    bpf: aya::Ebpf,
}

/// Non-Linux stub — zero-sized, never constructed (load_xdp always errors).
#[cfg(not(target_os = "linux"))]
pub struct BpfHandle;

// ── load_xdp ─────────────────────────────────────────────────────────────────

/// Load and attach the GTP-U XDP program to a network interface.
///
/// Errors on non-Linux or when built without `--features ebpf`.
pub async fn load_xdp(iface: &str) -> Result<BpfHandle, LoadXdpError> {
    load_xdp_impl(iface).await
}

#[cfg(not(target_os = "linux"))]
async fn load_xdp_impl(_iface: &str) -> Result<BpfHandle, LoadXdpError> {
    Err("eBPF/XDP requires Linux — not supported on this platform".into())
}

#[cfg(all(target_os = "linux", not(feature = "ebpf")))]
async fn load_xdp_impl(_iface: &str) -> Result<BpfHandle, LoadXdpError> {
    Err("XDP fast path not compiled in — rebuild with `--features ebpf` \
         (requires bpf-linker + nightly with rust-src)"
        .into())
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
async fn load_xdp_impl(iface: &str) -> Result<BpfHandle, LoadXdpError> {
    let mut bpf = aya::Ebpf::load(BPF_OBJECT)?;

    // Kernel-side eBPF logging. Non-fatal — some kernels/configs lack the
    // ring-buffer logging module; we just lose eBPF printk output.
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        tracing::warn!("BPF logger init failed (non-fatal): {e}");
    }

    let prog: &mut aya::programs::Xdp = bpf
        .program_mut("midn_gtp_xdp")
        .ok_or("XDP program 'midn_gtp_xdp' not found in BPF object \
                (check function name in midn-userplane-ebpf/src/main.rs)")?
        .try_into()?;
    prog.load()?;
    prog.attach(iface, aya::programs::XdpFlags::default())?;

    tracing::info!(iface = iface, "GTP-U XDP program attached — fast path active");
    Ok(BpfHandle { bpf })
}

// ── BpfHandle methods (Linux only) ───────────────────────────────────────────

#[cfg(target_os = "linux")]
impl BpfHandle {
    // ── TEID routing map ──────────────────────────────────────────────────────

    /// Insert or overwrite a TEID route in the kernel `TEID_TO_ROUTE` map.
    /// `flags = 0` → BPF_ANY (insert or replace, atomic).
    ///
    /// Lifecycle:
    ///   CreateSession → placeholder (dl_teid = 0); XDP_PASS until bearer confirmed.
    ///   UpdateBearer  → real entry; XDP_TX active for this TEID.
    pub fn insert_teid(
        &mut self,
        ul_teid: u32,
        entry:   &XdpRouteEntry,
    ) -> Result<(), LoadXdpError> {
        use aya::maps::HashMap;
        let map_data = self.bpf
            .map_mut("TEID_TO_ROUTE")
            .ok_or("TEID_TO_ROUTE map not found in BPF object")?;
        let mut map: HashMap<_, u32, XdpRouteEntry> = map_data.try_into()?;
        map.insert(&ul_teid, entry, 0)?;
        tracing::debug!(ul_teid, dl_teid = entry.dl_teid, "BPF TEID_TO_ROUTE insert");
        Ok(())
    }

    /// Remove a TEID entry. After removal, UL packets fall through to XDP_PASS
    /// and are handled (or dropped) by the userspace GtpForwarder.
    pub fn remove_teid(&mut self, ul_teid: u32) -> Result<(), LoadXdpError> {
        use aya::maps::HashMap;
        let map_data = self.bpf
            .map_mut("TEID_TO_ROUTE")
            .ok_or("TEID_TO_ROUTE map not found in BPF object")?;
        let mut map: HashMap<_, u32, XdpRouteEntry> = map_data.try_into()?;
        map.remove(&ul_teid)?;
        tracing::debug!(ul_teid, "BPF TEID_TO_ROUTE remove");
        Ok(())
    }

    // ── PDN gateway config map ────────────────────────────────────────────────

    /// Write Ethernet rewrite parameters into `PDN_GW_CONFIG[0]`.
    ///
    /// Call ONCE at startup after `load_xdp` succeeds, BEFORE any sessions
    /// are created. Until called, the XDP program reads all-zero MACs and
    /// falls through to XDP_PASS.
    ///
    /// How to get the values:
    /// ```bash
    /// # gw_mac — next-hop router toward internet
    /// ip neigh show $(ip route show default | awk '/default/ {print $3}')
    /// # nic_mac — UPF interface
    /// ip link show eth0 | awk '/ether/ {print $2}'
    /// ```
    pub fn set_pdn_gw_config(&mut self, config: &PdnGwConfig) -> Result<(), LoadXdpError> {
        use aya::maps::Array;
        let map_data = self.bpf
            .map_mut("PDN_GW_CONFIG")
            .ok_or("PDN_GW_CONFIG map not found in BPF object")?;
        let mut map: Array<_, PdnGwConfig> = map_data.try_into()?;
        map.set(0, config, 0)?;
        tracing::info!(
            gw_mac  = ?config.gw_mac,
            nic_mac = ?config.nic_mac,
            "PDN gateway config written to BPF PDN_GW_CONFIG[0]"
        );
        Ok(())
    }
}
