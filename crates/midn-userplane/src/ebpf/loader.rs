// crates/midn-userplane/src/ebpf/loader.rs
//! XDP program loader and kernel BPF map management.
//!
//! ## Current state (Phase 3.0)
//!
//! `load_xdp` returns an error — the `aya-build` pipeline that compiles
//! the eBPF object and embeds it via `include_bytes!` is not yet activated.
//! `BpfHandle::insert_teid` and `remove_teid` are fully implemented and ready
//! to be wired into `SessionManager` once `load_xdp` succeeds.
//!
//! ## Phase 3.1 session integration plan
//!
//! When `load_xdp` is activated:
//! 1. Call `load_xdp(iface)` at UPF startup → `BpfHandle`.
//! 2. Add `bpf: Option<BpfHandle>` to `SessionManager` + a `set_bpf_handle` method.
//! 3. In `create_session_with_teid`: if bpf is Some, call `insert_teid` with a
//!    zero `dl_teid` placeholder (map entry exists; XDP falls through until update).
//! 4. In `update_bearer_info`: call `insert_teid` again with the real `dl_teid`
//!    and `enb_addr` — BPF_ANY (flags=0) overwrites the placeholder atomically.
//! 5. In `remove_session`: call `remove_teid` so the XDP program stops matching.
//!
//! ## Rule 3 compliance
//!
//! Per `docs/platform-optimization.md` Rule 3, the BPF map entry MUST be
//! installed BEFORE sending AttachAccept. In practice this means calling
//! `insert_teid` inside `update_bearer_info` (step 4 above), which is triggered
//! by the MME's `UpfEvent::UpdateBearer` immediately before the eNodeB delivers
//! AttachAccept to the UE. No packet can arrive for this TEID before the map
//! entry exists because the radio bearer is not established until the ICSRSP
//! has been processed.

use crate::upf::xdp_types::XdpRouteEntry;

// ── Error type ────────────────────────────────────────────────────────────────

pub type LoadXdpError = Box<dyn std::error::Error + Send + Sync + 'static>;

// ── BpfHandle ─────────────────────────────────────────────────────────────────

/// Owned handle to a loaded XDP program.
///
/// Dropping this handle detaches the XDP program from the NIC (via Aya's Drop impl).
/// Keep it alive for the lifetime of the UPF process.
#[cfg(target_os = "linux")]
pub struct BpfHandle {
    // Keeps the XDP program attached via Aya's Drop implementation.
    bpf: aya::Bpf,
}

/// Non-Linux stub — cannot be constructed; present for uniform API surface.
#[cfg(not(target_os = "linux"))]
pub struct BpfHandle;

// ── load_xdp ──────────────────────────────────────────────────────────────────

/// Load and attach the XDP program to `iface`.
///
/// Returns a `BpfHandle` that keeps the program attached until dropped.
///
/// # Phase 3.1 activation
///
/// Uncomment the three blocks below once the aya-build pipeline is set up:
///
/// 1. The `BPF_OBJECT` static (embedded compiled BPF object).
/// 2. The `aya::Bpf::load(BPF_OBJECT)` call.
/// 3. The `BpfHandle { bpf }` return.
pub async fn load_xdp(_iface: &str) -> Result<BpfHandle, LoadXdpError> {
    // Phase 3.1 — uncomment when aya-build pipeline is ready:
    //
    // static BPF_OBJECT: &[u8] =
    //     include_bytes!(concat!(env!("OUT_DIR"), "/midn_gtp_xdp.bpf.o"));

    #[cfg(not(target_os = "linux"))]
    return Err("eBPF/XDP requires Linux".into());

    #[cfg(target_os = "linux")]
    {
        // Phase 3.1 — uncomment this block:
        //
        // let mut bpf = aya::Bpf::load(BPF_OBJECT)?;
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

        Err("Phase 3.1 pending: compile BPF object via aya-build before calling load_xdp \
             (see docs/phase3-userplane.md and ebpf/loader.rs Phase 3.1 checklist)".into())
    }
}

// ── BpfHandle methods (Linux only) ────────────────────────────────────────────

#[cfg(target_os = "linux")]
impl BpfHandle {
    /// Write a session route entry into the kernel `TEID_TO_ROUTE` BPF map.
    ///
    /// `flags = 0` → `BPF_ANY` (insert or overwrite). Call once with
    /// `dl_teid = 0` at `CreateSession` time, then again with the real
    /// `dl_teid` + `enb_addr` when `UpdateBearer` fires after ICSRSP.
    ///
    /// # Errors
    ///
    /// Returns an error if the `TEID_TO_ROUTE` map is not found in the
    /// loaded BPF object (name mismatch with `maps.rs`) or if the kernel
    /// map operation fails (map full, permission denied, etc.).
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
        tracing::debug!(ul_teid, dl_teid = entry.dl_teid, "BPF map insert");
        Ok(())
    }

    /// Remove a session from the kernel `TEID_TO_ROUTE` map.
    ///
    /// After this call, UL packets for this TEID return `XDP_PASS` and fall
    /// through to the userspace `GtpForwarder`, which logs an unknown TEID.
    ///
    /// Call this inside `SessionManager::remove_session` when processing
    /// `UpfEvent::RemoveSession`.
    pub fn remove_teid(&mut self, ul_teid: u32) -> Result<(), LoadXdpError> {
        use aya::maps::HashMap;
        let map_data = self.bpf
            .map_mut("TEID_TO_ROUTE")
            .ok_or("TEID_TO_ROUTE map not found in BPF object")?;
        let mut map: HashMap<_, u32, XdpRouteEntry> = map_data.try_into()?;
        map.remove(&ul_teid)?;
        tracing::debug!(ul_teid, "BPF map remove");
        Ok(())
    }
    }
