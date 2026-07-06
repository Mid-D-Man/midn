// crates/midn-userplane/src/upf/session_manager.rs
//! SessionManager — production user-plane session lifecycle.
//!
//! Owns the `Arc<Mutex<RoutingTable>>` shared with `GtpForwarder` so both
//! can operate concurrently: forwarder holds the lock only for a single O(1)
//! lookup, never across an `.await`.
//!
//! ## Two session-creation paths
//!
//! `create_session`           — allocates a new UL TEID internally.
//!                              Used by standalone UPF without MME coordination.
//!
//! `create_session_with_teid` — accepts an externally pre-allocated UL TEID.
//!                              Used when the MME allocates the TEID and embeds
//!                              it in `InitialContextSetupRequest`.
//!
//! ## UpfEvent mapping
//!
//! ```text
//! UpfEvent::CreateSession { ul_teid, entity_id, imsi, ue_ip, enb_addr, qci }
//!     → create_session_with_teid(ul_teid, entity_id, imsi, ue_ip, enb_addr, qci)
//!
//! UpfEvent::UpdateBearer { ul_teid, dl_teid, enb_addr }
//!     → update_bearer_info(ul_teid, dl_teid, enb_addr)
//!
//! UpfEvent::RemoveSession { ul_teid }
//!     → remove_session(ul_teid)
//! ```
//!
//! ## TEID free list
//!
//! `remove_session` pushes the freed `ul_teid` onto an internal free list;
//! `alloc_ul_teid` (used only by the internal `create_session` path) pops it
//! before advancing the counter. `create_session_with_teid` always uses the
//! externally-provided TEID regardless of free-list state — the MME owns
//! that allocator independently (see `midn_core::mme::state_machine::TeidAllocator`).
//! This free list only matters for standalone UPF operation without MME
//! coordination.
//!
//! ## BPF fast-path wiring
//!
//! Call `set_bpf_handle(bpf)` at UPF startup after `load_xdp` and
//! `set_pdn_gw_config` succeed (and, if the Phase 3.2 DL path is active,
//! after `attach_dl` and `set_dl_tunnel_config` too). All subsequent session
//! lifecycle calls automatically mirror state into BOTH kernel BPF maps —
//! `TEID_TO_ROUTE` (UL, keyed by `ul_teid`) and `UE_IP_TO_ROUTE` (DL, keyed
//! by `ue_ip`) — since both carry the exact same `XdpRouteEntry` shape for a
//! given session, just indexed differently for each direction's lookup:
//!
//! ```text
//! CreateSession   → insert_teid(ul_teid, placeholder)  + insert_ue_route(ue_ip, placeholder)
//! UpdateBearer    → insert_teid(ul_teid, real entry)   + insert_ue_route(ue_ip, real entry)  ← Rule 3
//! RemoveSession   → remove_teid(ul_teid)               + remove_ue_route(ue_ip)
//! ```
//!
//! With no BpfHandle set (`bpf = None`), all BPF calls are skipped silently —
//! the userspace `GtpForwarder` handles all packets. This is the default on
//! non-Linux and during Phase 3.1/3.2 bring-up before `load_xdp`/`attach_dl`
//! succeed.
//!
//! ## Rule 3 compliance
//!
//! `update_bearer_info` fires from `UpfEvent::UpdateBearer`, which the MME
//! emits from `handle_icsrsp`. This runs AFTER the eNodeB sends
//! `InitialContextSetupResponse` and BEFORE it delivers `AttachAccept` to
//! the UE via RRC. No UL or DL packet can arrive before both BPF map entries
//! exist — `TEID_TO_ROUTE` and `UE_IP_TO_ROUTE` are updated in the same call,
//! so there's no window where one map has the real entry and the other still
//! has the placeholder.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::ebpf::loader::BpfHandle;
use crate::upf::routing::{RouteEntry, RoutingTable};
use crate::upf::session::UserPlaneSession;
use crate::upf::xdp_types::XdpRouteEntry;

const INITIAL_UL_TEID: u32 = 0x0001_0000;

/// Manages all active user-plane sessions for one UPF instance.
pub struct SessionManager {
    next_ul_teid:  u32,
    /// TEIDs returned by `remove_session`, reused by `alloc_ul_teid` before
    /// the counter advances. Only affects the internal `create_session` path —
    /// `create_session_with_teid` always uses the externally-provided TEID
    /// regardless of free-list state.
    free_ul_teids: Vec<u32>,
    routing:       Arc<Mutex<RoutingTable>>,
    /// ul_teid → session record
    sessions:      HashMap<u32, UserPlaneSession>,
    /// Loaded XDP program + BPF map handle.
    /// None until `set_bpf_handle` is called (always None on non-Linux).
    bpf:           Option<BpfHandle>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            next_ul_teid:  INITIAL_UL_TEID,
            free_ul_teids: Vec::with_capacity(64),
            routing:       Arc::new(Mutex::new(RoutingTable::new())),
            sessions:      HashMap::with_capacity(1024),
            bpf:           None,
        }
    }

    /// Return an `Arc` handle to the shared routing table.
    /// Pass this into `GtpForwarder::bind_addr` so both share the same map.
    pub fn routing_arc(&self) -> Arc<Mutex<RoutingTable>> {
        Arc::clone(&self.routing)
    }

    // ── BPF handle management ─────────────────────────────────────────────────

    /// Wire a loaded XDP program and its BPF maps into this session manager.
    ///
    /// Call at UPF startup after `load_xdp(iface).await?` and
    /// `bpf.set_pdn_gw_config(cfg)?` have both succeeded. If the Phase 3.2 DL
    /// path is also in use, call `bpf.attach_dl(pdn_iface).await?` and
    /// `bpf.set_dl_tunnel_config(cfg)?` first too — this handle mirrors into
    /// both `TEID_TO_ROUTE` and `UE_IP_TO_ROUTE` unconditionally, so if the DL
    /// program was never attached, `UE_IP_TO_ROUTE` writes simply populate a
    /// map nothing reads yet (harmless):
    ///
    /// ```rust,ignore
    /// let mut bpf = load_xdp("eth0").await?;
    /// bpf.set_pdn_gw_config(&PdnGwConfig::new(gw_mac, nic_mac))?;
    /// bpf.attach_dl("eth1").await?;
    /// bpf.set_dl_tunnel_config(&DlTunnelConfig::new(enb_mac, pdn_nic_mac, upf_ip, ifindex))?;
    /// session_manager.set_bpf_handle(bpf);
    /// ```
    ///
    /// After this call, `create_session_with_teid`, `update_bearer_info`, and
    /// `remove_session` will automatically mirror session state into both
    /// kernel BPF hash maps, enabling XDP_TX (UL) and XDP_REDIRECT (DL)
    /// fast-path forwarding.
    pub fn set_bpf_handle(&mut self, bpf: BpfHandle) {
        self.bpf = Some(bpf);
        tracing::info!(
            "BPF handle wired — XDP TEID_TO_ROUTE and UE_IP_TO_ROUTE will be \
             populated for new sessions"
        );
    }

    /// Returns `true` if a BPF handle is active (XDP fast path enabled).
    pub fn has_bpf(&self) -> bool { self.bpf.is_some() }

    // ── Session creation ──────────────────────────────────────────────────────

    /// Create a session with an internally allocated UL TEID.
    ///
    /// Use for standalone UPF operation without MME TEID pre-allocation.
    /// Returns the allocated UL TEID.
    pub fn create_session(
        &mut self,
        entity_id: u32,
        imsi:      u64,
        ue_ip:     [u8; 4],
        dl_teid:   u32,
        enb_addr:  [u8; 4],
        qci:       u8,
    ) -> u32 {
        let ul_teid = self.alloc_ul_teid();
        self.install(ul_teid, entity_id, imsi, ue_ip, dl_teid, enb_addr, qci);
        ul_teid
    }

    /// Create a session using a UL TEID pre-allocated by the MME.
    ///
    /// Called when processing `UpfEvent::CreateSession`. The MME embeds the
    /// TEID in `InitialContextSetupRequest.e_rabs[*].gtp_teid` so the eNodeB
    /// knows where to send UL packets before this call completes.
    ///
    /// `dl_teid` and `enb_addr` are zero/placeholder at this point — they are
    /// updated to real values by `update_bearer_info` after ICSRSP arrives.
    ///
    /// BPF: inserts a placeholder entry (dl_teid = 0) into BOTH
    /// `TEID_TO_ROUTE` (keyed by `ul_teid`) and `UE_IP_TO_ROUTE` (keyed by
    /// `ue_ip`). The UL XDP program sees the TEID and XDP_PASSes (dl_teid
    /// unused for UL forwarding, but placeholder still gates correctly per
    /// Rule 3 doc). The DL XDP program explicitly checks `dl_teid == 0` and
    /// XDP_PASSes until `update_bearer_info` fires — see `gtp_dl_xdp.rs`
    /// module doc for why the DL side needs that explicit check where the UL
    /// side doesn't.
    pub fn create_session_with_teid(
        &mut self,
        ul_teid:   u32,
        entity_id: u32,
        imsi:      u64,
        ue_ip:     [u8; 4],
        enb_addr:  [u8; 4],
        qci:       u8,
    ) {
        self.install(ul_teid, entity_id, imsi, ue_ip, 0, enb_addr, qci);

        // Install placeholder BPF map entries — dl_teid = 0, enb_addr as
        // provided — into both the UL (TEID-keyed) and DL (UE-IP-keyed) maps.
        #[cfg(target_os = "linux")]
        if let Some(ref mut bpf) = self.bpf {
            let xdp_entry = XdpRouteEntry::new(0, enb_addr, 2152);

            if let Err(e) = bpf.insert_teid(ul_teid, &xdp_entry) {
                tracing::warn!(
                    ul_teid, error = %e,
                    "BPF TEID_TO_ROUTE placeholder insert failed (CreateSession)"
                );
            } else {
                tracing::debug!(ul_teid, "BPF TEID_TO_ROUTE placeholder inserted");
            }

            if let Err(e) = bpf.insert_ue_route(ue_ip, &xdp_entry) {
                tracing::warn!(
                    ul_teid, ue_ip = ?ue_ip, error = %e,
                    "BPF UE_IP_TO_ROUTE placeholder insert failed (CreateSession)"
                );
            } else {
                tracing::debug!(ul_teid, ue_ip = ?ue_ip, "BPF UE_IP_TO_ROUTE placeholder inserted");
            }
        }

        tracing::info!(
            imsi, ul_teid, ue_ip = ?ue_ip,
            "User-plane session created (MME-allocated TEID)"
        );
    }

    // ── Bearer update ─────────────────────────────────────────────────────────

    /// Update DL TEID only — backward-compat wrapper; prefer `update_bearer_info`.
    pub fn update_dl_teid(&mut self, ul_teid: u32, dl_teid: u32) -> bool {
        let current_enb_addr = {
            let rt = self.routing.lock().unwrap();
            rt.lookup_ul(ul_teid).map(|e| e.enb_addr)
        };
        match current_enb_addr {
            Some(enb_addr) => self.update_bearer_info(ul_teid, dl_teid, enb_addr),
            None           => false,
        }
    }

    /// Update DL TEID **and** eNodeB address after `InitialContextSetupResponse`.
    ///
    /// Called when processing `UpfEvent::UpdateBearer`. Atomically replaces the
    /// routing entry so `GtpForwarder` never observes a partial update.
    ///
    /// BPF (Rule 3): atomically overwrites the placeholder entries in BOTH
    /// `TEID_TO_ROUTE` and `UE_IP_TO_ROUTE` with the real `dl_teid` +
    /// `enb_addr` (BPF_ANY, flags=0). After this returns, the UL XDP program
    /// can fast-path via XDP_TX and the DL XDP program can fast-path via
    /// XDP_REDIRECT for this session. This fires before AttachAccept reaches
    /// the UE — no packet in either direction races the map entries.
    ///
    /// Returns `false` if no session exists for `ul_teid`.
    pub fn update_bearer_info(
        &mut self,
        ul_teid:  u32,
        dl_teid:  u32,
        enb_addr: [u8; 4],
    ) -> bool {
        // Snapshot the current entry to preserve ue_ip and qci.
        let current = {
            let rt = self.routing.lock().unwrap();
            match rt.lookup_ul(ul_teid).copied() {
                Some(e) => e,
                None    => return false,
            }
        };

        // Atomically replace both routing maps.
        {
            let mut rt = self.routing.lock().unwrap();
            rt.remove(ul_teid);
            let updated = RouteEntry::new(current.ue_ip, dl_teid, enb_addr, current.qci);
            rt.install(ul_teid, updated);
        }

        // Mirror into session record.
        if let Some(s) = self.sessions.get_mut(&ul_teid) {
            s.dl_teid  = dl_teid;
            s.enb_addr = enb_addr;
        }

        // Atomic BPF map overwrite — Rule 3: this fires before AttachAccept
        // delivery. Updates both maps with the same real entry.
        #[cfg(target_os = "linux")]
        if let Some(ref mut bpf) = self.bpf {
            let xdp_entry = XdpRouteEntry::new(dl_teid, enb_addr, 2152);

            if let Err(e) = bpf.insert_teid(ul_teid, &xdp_entry) {
                tracing::warn!(
                    ul_teid, dl_teid, error = %e,
                    "BPF TEID_TO_ROUTE real-entry insert failed (UpdateBearer)"
                );
            } else {
                tracing::debug!(
                    ul_teid, dl_teid, enb_addr = ?enb_addr,
                    "BPF TEID_TO_ROUTE updated — UL XDP fast path active for this session"
                );
            }

            if let Err(e) = bpf.insert_ue_route(current.ue_ip, &xdp_entry) {
                tracing::warn!(
                    ul_teid, dl_teid, ue_ip = ?current.ue_ip, error = %e,
                    "BPF UE_IP_TO_ROUTE real-entry insert failed (UpdateBearer)"
                );
            } else {
                tracing::debug!(
                    ul_teid, dl_teid, ue_ip = ?current.ue_ip, enb_addr = ?enb_addr,
                    "BPF UE_IP_TO_ROUTE updated — DL XDP fast path active for this session"
                );
            }
        }

        tracing::debug!(
            ul_teid, dl_teid, enb_addr = ?enb_addr,
            "Bearer info updated after ICSRSP"
        );
        true
    }

    // ── Session removal ───────────────────────────────────────────────────────

    /// Remove a session on detach or `UpfEvent::RemoveSession`.
    ///
    /// BPF: removes the entry from BOTH `TEID_TO_ROUTE` and `UE_IP_TO_ROUTE`.
    /// After this, UL packets for this TEID and DL packets for this UE both
    /// return `XDP_PASS` and are handled (or dropped) by userspace.
    ///
    /// The freed `ul_teid` goes back into the free list so a future
    /// `create_session` call can reuse it instead of growing the counter
    /// forever. Returns the session record for billing/audit purposes.
    pub fn remove_session(&mut self, ul_teid: u32) -> Option<UserPlaneSession> {
        // Snapshot ue_ip before removing from the routing table, so we can
        // still key the UE_IP_TO_ROUTE deletion after `rt.remove` runs.
        let ue_ip = self.sessions.get(&ul_teid).map(|s| s.ue_ip);

        self.routing.lock().unwrap().remove(ul_teid);

        // Remove BPF map entries so neither XDP program matches this session
        // anymore.
        #[cfg(target_os = "linux")]
        if let Some(ref mut bpf) = self.bpf {
            if let Err(e) = bpf.remove_teid(ul_teid) {
                tracing::warn!(
                    ul_teid, error = %e,
                    "BPF TEID_TO_ROUTE remove failed (RemoveSession)"
                );
            }
            if let Some(ip) = ue_ip {
                if let Err(e) = bpf.remove_ue_route(ip) {
                    tracing::warn!(
                        ul_teid, ue_ip = ?ip, error = %e,
                        "BPF UE_IP_TO_ROUTE remove failed (RemoveSession)"
                    );
                }
            }
        }

        let removed = self.sessions.remove(&ul_teid);
        if removed.is_some() {
            self.free_ul_teids.push(ul_teid);
        }

        match removed {
            Some(s) => {
                tracing::info!(
                    imsi     = s.imsi,
                    ul_teid,
                    bytes_ul = s.bytes_ul,
                    bytes_dl = s.bytes_dl,
                    "User-plane session removed — TEID recycled"
                );
                Some(s)
            }
            None => None,
        }
    }

    // ── Lookups ───────────────────────────────────────────────────────────────

    pub fn get_session(&self, ul_teid: u32) -> Option<&UserPlaneSession> {
        self.sessions.get(&ul_teid)
    }

    /// Find a session by IMSI (linear scan — control-plane queries only).
    pub fn find_by_imsi(&self, imsi: u64) -> Option<&UserPlaneSession> {
        self.sessions.values().find(|s| s.imsi == imsi)
    }

    // ── Byte accounting ───────────────────────────────────────────────────────

    pub fn account_uplink(&mut self, ul_teid: u32, bytes: u64) {
        if let Some(s) = self.sessions.get_mut(&ul_teid) { s.bytes_ul += bytes; }
    }

    pub fn account_downlink(&mut self, ul_teid: u32, bytes: u64) {
        if let Some(s) = self.sessions.get_mut(&ul_teid) { s.bytes_dl += bytes; }
    }

    // ── Metrics ───────────────────────────────────────────────────────────────

    pub fn active_session_count(&self) -> usize {
        self.sessions.values().filter(|s| s.active).count()
    }

    pub fn total_bytes_uplink(&self) -> u64 {
        self.sessions.values().map(|s| s.bytes_ul).sum()
    }

    pub fn total_bytes_downlink(&self) -> u64 {
        self.sessions.values().map(|s| s.bytes_dl).sum()
    }

    /// Number of TEIDs currently available for reuse by `create_session`.
    pub fn free_teid_count(&self) -> usize {
        self.free_ul_teids.len()
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn install(
        &mut self,
        ul_teid:   u32,
        entity_id: u32,
        imsi:      u64,
        ue_ip:     [u8; 4],
        dl_teid:   u32,
        enb_addr:  [u8; 4],
        qci:       u8,
    ) {
        let entry = RouteEntry::new(ue_ip, dl_teid, enb_addr, qci);
        self.routing.lock().unwrap().install(ul_teid, entry);
        self.sessions.insert(ul_teid, UserPlaneSession {
            entity_id,
            imsi,
            ul_teid,
            dl_teid,
            ue_ip,
            enb_addr,
            active:   true,
            bytes_ul: 0,
            bytes_dl: 0,
        });
    }

    fn alloc_ul_teid(&mut self) -> u32 {
        if let Some(id) = self.free_ul_teids.pop() {
            return id;
        }
        let teid = self.next_ul_teid;
        self.next_ul_teid = self.next_ul_teid.wrapping_add(1);
        if self.next_ul_teid < INITIAL_UL_TEID {
            self.next_ul_teid = INITIAL_UL_TEID;
        }
        teid
    }
}

impl Default for SessionManager { fn default() -> Self { Self::new() } }

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> SessionManager { SessionManager::new() }

    // ── create_session (internal TEID) ────────────────────────────────────────

    #[test]
    fn create_and_remove_session() {
        let mut m = mgr();
        let ul = m.create_session(0, 234_15_1234567890, [10, 0, 0, 1], 0, [192, 168, 1, 1], 9);
        assert_eq!(m.active_session_count(), 1);
        assert!(m.get_session(ul).is_some());
        assert!(m.routing_arc().lock().unwrap().lookup_ul(ul).is_some());
        m.remove_session(ul);
        assert_eq!(m.active_session_count(), 0);
        assert!(m.routing_arc().lock().unwrap().lookup_ul(ul).is_none());
    }

    #[test]
    fn unique_teid_per_session() {
        let mut m = mgr();
        let t1 = m.create_session(0, 1, [10, 0, 0, 1], 0, [1, 1, 1, 1], 9);
        let t2 = m.create_session(1, 2, [10, 0, 0, 2], 0, [1, 1, 1, 1], 9);
        assert_ne!(t1, t2);
        assert_eq!(t1, INITIAL_UL_TEID);
        assert_eq!(t2, INITIAL_UL_TEID + 1);
    }

    // ── create_session_with_teid ──────────────────────────────────────────────

    #[test]
    fn create_session_with_teid_uses_provided_teid() {
        let mut m   = mgr();
        let ul_teid = 0xDEAD_0001_u32;
        m.create_session_with_teid(ul_teid, 42, 234_15_9876543210, [10, 0, 1, 5], [0; 4], 9);

        assert_eq!(m.active_session_count(), 1);
        let s = m.get_session(ul_teid).unwrap();
        assert_eq!(s.ul_teid,   ul_teid);
        assert_eq!(s.entity_id, 42);
        assert_eq!(s.imsi,      234_15_9876543210);
        assert_eq!(s.dl_teid,   0, "dl_teid must be placeholder until ICSRSP");

        let arc = m.routing_arc();
        let rt  = arc.lock().unwrap();
        let e   = rt.lookup_ul(ul_teid).unwrap();
        assert_eq!(e.ue_ip,  [10, 0, 1, 5]);
        assert_eq!(e.dl_teid, 0);
    }

    #[test]
    fn create_with_teid_does_not_advance_internal_counter() {
        let mut m    = mgr();
        let ext_teid = 0xAAAA_0001_u32;
        m.create_session_with_teid(ext_teid, 0, 1, [10, 0, 0, 1], [0; 4], 9);
        let auto_teid = m.create_session(0, 2, [10, 0, 0, 2], 0, [1, 1, 1, 1], 9);
        assert_eq!(auto_teid, INITIAL_UL_TEID);
        assert_ne!(auto_teid, ext_teid);
    }

    // ── update_bearer_info ────────────────────────────────────────────────────

    #[test]
    fn update_bearer_info_updates_both_maps_and_session() {
        let mut m   = mgr();
        let ul_teid = 0xBBBB_0001_u32;
        m.create_session_with_teid(ul_teid, 0, 1, [10, 0, 0, 3], [0; 4], 9);

        let real_dl_teid  = 0xCCCC_0001_u32;
        let real_enb_addr = [192u8, 168, 1, 100];

        assert!(m.update_bearer_info(ul_teid, real_dl_teid, real_enb_addr));

        let s = m.get_session(ul_teid).unwrap();
        assert_eq!(s.dl_teid,  real_dl_teid);
        assert_eq!(s.enb_addr, real_enb_addr);

        let arc = m.routing_arc();
        let rt  = arc.lock().unwrap();
        let ul  = rt.lookup_ul(ul_teid).unwrap();
        assert_eq!(ul.dl_teid,  real_dl_teid);
        assert_eq!(ul.enb_addr, real_enb_addr);
        let dl  = rt.lookup_dl(&[10, 0, 0, 3]).unwrap();
        assert_eq!(dl.dl_teid,  real_dl_teid);
        assert_eq!(dl.enb_addr, real_enb_addr);
    }

    #[test]
    fn update_bearer_info_preserves_ue_ip_and_qci() {
        let mut m   = mgr();
        let ul_teid = 0xDDDD_0001_u32;
        m.create_session_with_teid(ul_teid, 0, 1, [10, 1, 2, 3], [0; 4], 5);
        m.update_bearer_info(ul_teid, 0x1234_5678, [172, 16, 0, 1]);

        let arc = m.routing_arc();
        let rt  = arc.lock().unwrap();
        let e   = rt.lookup_ul(ul_teid).unwrap();
        assert_eq!(e.ue_ip, [10, 1, 2, 3], "ue_ip must not change");
        assert_eq!(e.qci,   5,              "qci must not change");
    }

    #[test]
    fn update_bearer_info_returns_false_for_unknown() {
        let mut m = mgr();
        assert!(!m.update_bearer_info(0xDEAD_BEEF, 0x1234_5678, [1, 2, 3, 4]));
    }

    // ── Full Phase 3 lifecycle ─────────────────────────────────────────────────

    #[test]
    fn full_phase3_lifecycle() {
        let mut m   = mgr();
        let ul_teid = 0x0001_0000_u32;
        let imsi    = 234_15_1234567890_u64;

        // 1. MME emits CreateSession
        m.create_session_with_teid(ul_teid, 7, imsi, [10, 0, 5, 1], [0; 4], 9);
        assert_eq!(m.active_session_count(), 1);
        assert_eq!(m.get_session(ul_teid).unwrap().dl_teid, 0);

        // 2. MME emits UpdateBearer after ICSRSP
        let enb_dl_teid = 0xABCD_1234_u32;
        let enb_addr    = [192u8, 168, 1, 200];
        assert!(m.update_bearer_info(ul_teid, enb_dl_teid, enb_addr));
        let s = m.get_session(ul_teid).unwrap();
        assert_eq!(s.dl_teid,  enb_dl_teid);
        assert_eq!(s.enb_addr, enb_addr);

        // 3. Byte accounting
        m.account_uplink(ul_teid, 4096);
        m.account_downlink(ul_teid, 8192);
        assert_eq!(m.total_bytes_uplink(),   4096);
        assert_eq!(m.total_bytes_downlink(), 8192);

        // 4. MME emits RemoveSession on detach
        let rec = m.remove_session(ul_teid).unwrap();
        assert_eq!(rec.imsi,     imsi);
        assert_eq!(rec.bytes_ul, 4096);
        assert_eq!(m.active_session_count(), 0);
        assert!(m.routing_arc().lock().unwrap().lookup_ul(ul_teid).is_none());
    }

    #[test]
    fn find_by_imsi_works() {
        let mut m   = mgr();
        let imsi    = 234_15_9999999999_u64;
        let ul_teid = 0x0002_0000_u32;
        m.create_session_with_teid(ul_teid, 42, imsi, [10, 0, 0, 99], [0; 4], 9);
        let s = m.find_by_imsi(imsi).unwrap();
        assert_eq!(s.ul_teid,   ul_teid);
        assert_eq!(s.entity_id, 42);
        assert!(m.find_by_imsi(999).is_none());
    }

    #[test]
    fn remove_cleans_both_routing_maps() {
        let mut m   = mgr();
        let ul_teid = 0x0003_0000_u32;
        m.create_session_with_teid(ul_teid, 0, 1, [10, 1, 2, 3], [0; 4], 9);
        m.update_bearer_info(ul_teid, 0xAAAA_0001, [192, 168, 0, 1]);
        {
            let arc = m.routing_arc();
            let rt  = arc.lock().unwrap();
            assert!(rt.lookup_ul(ul_teid).is_some());
            assert!(rt.lookup_dl(&[10, 1, 2, 3]).is_some());
        }
        m.remove_session(ul_teid);
        {
            let arc = m.routing_arc();
            let rt  = arc.lock().unwrap();
            assert!(rt.lookup_ul(ul_teid).is_none());
            assert!(rt.lookup_dl(&[10, 1, 2, 3]).is_none());
        }
    }

    #[test]
    fn has_bpf_false_by_default() {
        assert!(!mgr().has_bpf());
    }

    // ── TEID free list ─────────────────────────────────────────────────────────

    #[test]
    fn removed_teid_is_recycled() {
        let mut m = mgr();
        let t1    = m.create_session(0, 1, [10, 0, 0, 1], 0, [1, 1, 1, 1], 9);
        m.remove_session(t1);
        let t2    = m.create_session(0, 2, [10, 0, 0, 2], 0, [1, 1, 1, 1], 9);
        assert_eq!(t2, t1, "freed TEID should be recycled before advancing the counter");
    }

    #[test]
    fn free_teid_count_tracks_recycled_teids() {
        let mut m = mgr();
        assert_eq!(m.free_teid_count(), 0);
        let t1 = m.create_session(0, 1, [10, 0, 0, 1], 0, [1, 1, 1, 1], 9);
        m.remove_session(t1);
        assert_eq!(m.free_teid_count(), 1);
        m.create_session(0, 2, [10, 0, 0, 2], 0, [1, 1, 1, 1], 9);
        assert_eq!(m.free_teid_count(), 0, "recycled TEID consumed by the next create_session");
    }

    #[test]
    fn externally_allocated_teid_is_also_recyclable() {
        // create_session_with_teid bypasses the internal counter entirely, but
        // removing it should still feed the free list — a later internal
        // create_session() call can pick it up.
        let mut m    = mgr();
        let ext_teid = 0x9999_0001_u32;
        m.create_session_with_teid(ext_teid, 0, 1, [10, 0, 0, 1], [0; 4], 9);
        m.remove_session(ext_teid);
        let next = m.create_session(0, 2, [10, 0, 0, 2], 0, [1, 1, 1, 1], 9);
        assert_eq!(next, ext_teid);
    }

    // ── DL (UE_IP_TO_ROUTE) mirroring — bpf = None path ──────────────────────
    //
    // With no BpfHandle wired (the default in every unit test — a real
    // aya::Ebpf requires root + a real Linux kernel), the `#[cfg(target_os =
    // "linux")] if let Some(ref mut bpf) = self.bpf` blocks are simply
    // skipped. These tests confirm the plain (non-BPF) session/routing state
    // is unaffected by the new UE_IP_TO_ROUTE calls added alongside the
    // existing TEID_TO_ROUTE ones — i.e. adding the DL mirroring didn't
    // change any pre-existing behavior on the path every unit test exercises.

    #[test]
    fn dl_mirroring_does_not_affect_session_state_without_bpf() {
        let mut m   = mgr();
        let ul_teid = 0x0004_0000_u32;
        m.create_session_with_teid(ul_teid, 0, 1, [10, 2, 0, 1], [0; 4], 9);
        m.update_bearer_info(ul_teid, 0xABCD_0001, [172, 16, 5, 5]);

        let s = m.get_session(ul_teid).unwrap();
        assert_eq!(s.ue_ip,    [10, 2, 0, 1]);
        assert_eq!(s.dl_teid,  0xABCD_0001);
        assert_eq!(s.enb_addr, [172, 16, 5, 5]);
        assert!(!m.has_bpf(), "no BpfHandle wired in this test — UE_IP_TO_ROUTE calls are skipped");
    }

    #[test]
    fn remove_session_snapshots_ue_ip_before_routing_table_removal() {
        // Regression guard: remove_session must read the session's ue_ip
        // BEFORE clearing the routing table entry, since the (bpf-enabled)
        // UE_IP_TO_ROUTE removal needs that ue_ip and the session map entry
        // is what remove_session's own return value is built from.
        let mut m   = mgr();
        let ul_teid = 0x0005_0000_u32;
        m.create_session_with_teid(ul_teid, 0, 1, [10, 3, 0, 1], [0; 4], 9);
        let rec = m.remove_session(ul_teid).unwrap();
        assert_eq!(rec.ue_ip, [10, 3, 0, 1]);
    }
}
