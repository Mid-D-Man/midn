// crates/midn-userplane/src/ebpf/loader.rs
//! XDP program loader and kernel BPF map management.
//!
//! ## Current state (Phase 3.1)
//!
//! `load_xdp` returns an error — the `aya-build` pipeline that compiles
//! the eBPF object and embeds it via `include_bytes!` is not yet activated.
//!
//! `BpfHandle::insert_teid`, `remove_teid`, and `set_pdn_gw_config` are fully
//! implemented and ready to wire into `SessionManager` once `load_xdp` succeeds.
//!
//! ## Phase 3.1 activation checklist
//!
//! 1. `cargo install bpf-linker`
//! 2. Uncomment `aya-build` in `Cargo.toml` `[build-dependencies]`
//! 3. Uncomment `aya_build::build_ebpf_programs` block in `build.rs`
//! 4. Uncomment `BPF_OBJECT` + body of `load_xdp` below
//! 5. At UPF startup:
//!    ```rust,ignore
//!    let mut bpf = load_xdp("eth0").await?;
//!    bpf.set_pdn_gw_config(&PdnGwConfig::new(gw_mac, nic_mac))?;
//!    session_manager.set_bpf_handle(bpf);
//!    ```
//!
//! ## Rule 3 compliance (docs/platform-optimization.md)
//!
//! BPF map entries are written in two phases:
//!   - `CreateSession` → `insert_teid(ul_teid, entry_with_zero_dl_teid)`:
//!     entry exists in map; XDP_PASS until bearer is confirmed.
//!   - `UpdateBearer`  → `insert_teid(ul_teid, real_entry)`:
//!     atomic BPF_ANY overwrite (flags=0). This fires from ICSRSP, which is
//!     processed BEFORE the eNodeB delivers AttachAccept to the UE via RRC.
//!     No packet can arrive for this TEID before the real entry exists.

use crate::upf::xdp_types::{PdnGwConfig, XdpRouteEntry};

// ── Error type ────────────────────────────────────────────────────────────────

pub type LoadXdpError = Box<dyn std::error::Error + Send + Sync + 'static>;

// ── BpfHandle ─────────────────────────────────────────────────────────────────

/// Owned handle to a loaded XDP program and its BPF maps.
///
/// Dropping this handle detaches the XDP program from the NIC (Aya Drop impl).
/// Keep it alive for the lifetime of the UPF process — typically store in
/// `SessionManager` via `set_bpf_handle`.
#[cfg(target_os = "linux")]
pub struct BpfHandle {
    // Keeps the XDP program attached; dropped on UPF shutdown.
    // aya::Bpf was renamed to aya::Ebpf in aya 0.13.
    bpf: aya::Ebpf,
}

/// Non-Linux stub — zero-sized, cannot be constructed; `load_xdp` always errors
/// on non-Linux so this type is never reachable in practice.
/// Exists only for uniform API surface across platforms.
#[cfg(not(target_os = "linux"))]
pub struct BpfHandle;

// ── load_xdp ─────────────────────────────────────────────────────────────────

/// Load and attach the GTP-U XDP program to a network interface.
///
/// Returns a `BpfHandle` that keeps the program and maps alive until dropped.
///
/// ## Phase 3.1 activation
///
/// Uncomment the blocks marked `Phase 3.1` once the aya-build pipeline is ready.
pub async fn load_xdp(_iface: &str) -> Result<BpfHandle, LoadXdpError> {
    // Phase 3.1 — uncomment when aya-build pipeline is set up:
    //
    // static BPF_OBJECT: &[u8] =
    //     include_bytes!(concat!(env!("OUT_DIR"), "/midn_gtp_xdp.bpf.o"));

    #[cfg(not(target_os = "linux"))]
    return Err("eBPF/XDP requires Linux — cannot load XDP program on this platform".into());

    #[cfg(target_os = "linux")]
    {
        // Phase 3.1 — uncomment:
        //
        // let mut bpf = aya::Ebpf::load(BPF_OBJECT)?;
        // aya_log::BpfLogger::init(&mut bpf)?;
        //
        // let prog: &mut aya::programs::Xdp =
        //     bpf.program_mut("midn_gtp_xdp")
        //        .ok_or("XDP program 'midn_gtp_xdp' not found in BPF object")?
        //        .try_into()?;
        // prog.load()?;
        // prog.attach(_iface, aya::programs::XdpFlags::default())?;
        //
        // tracing::info!(iface = _iface, "XDP program attached");
        // return Ok(BpfHandle { bpf });

        Err("Phase 3.1 pending: compile BPF object via aya-build before calling \
             load_xdp (see ebpf/loader.rs Phase 3.1 activation checklist)".into())
    }
}

// ── BpfHandle methods (Linux only) ───────────────────────────────────────────

#[cfg(target_os = "linux")]
impl BpfHandle {
    // ── TEID routing map ──────────────────────────────────────────────────────

    /// Write (or overwrite) a session route entry in the kernel `TEID_TO_ROUTE`
    /// BPF hash map. Uses `flags = 0` (BPF_ANY — insert or replace).
    ///
    /// Call sequence per session lifecycle:
    ///
    /// 1. `CreateSession` → `insert_teid(ul_teid, XdpRouteEntry::new(0, enb_addr, 2152))`
    ///    Placeholder entry with dl_teid = 0. XDP sees the TEID → XDP_PASS until
    ///    the real DL TEID arrives (safe: no packets arrive before bearer setup).
    ///
    /// 2. `UpdateBearer` → `insert_teid(ul_teid, XdpRouteEntry::new(dl_teid, enb_addr, 2152))`
    ///    Atomic overwrite with real DL TEID. XDP now fast-paths these packets.
    ///
    /// # Errors
    ///
    /// Returns an error if `TEID_TO_ROUTE` is not found (map name mismatch with
    /// `maps.rs`) or the kernel rejects the operation (map full, EPERM, etc.).
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
        tracing::debug!(ul_teid, dl_teid = entry.dl_teid, enb_port = entry.enb_port,
                        "BPF TEID_TO_ROUTE insert");
        Ok(())
    }

    /// Remove a session entry from the kernel `TEID_TO_ROUTE` BPF map.
    ///
    /// After removal, UL packets for this TEID return `XDP_PASS` and fall
    /// through to the userspace `GtpForwarder`, which logs an unknown TEID.
    ///
    /// Call inside `SessionManager::remove_session` when processing
    /// `UpfEvent::RemoveSession`.
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

    /// Write the PDN gateway Ethernet rewrite config into the kernel
    /// `PDN_GW_CONFIG` BPF array map at index 0.
    ///
    /// Call ONCE at UPF startup, immediately after `load_xdp` succeeds and
    /// BEFORE any subscriber sessions are created:
    ///
    /// ```rust,ignore
    /// let mut bpf = load_xdp("eth0").await?;
    /// bpf.set_pdn_gw_config(&PdnGwConfig::new(gw_mac, nic_mac))?;
    /// session_manager.set_bpf_handle(bpf);
    /// ```
    ///
    /// Until this is called, the XDP program reads all-zero MACs from the map
    /// and falls through to `XDP_PASS` (safe: packets handled by userspace).
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
