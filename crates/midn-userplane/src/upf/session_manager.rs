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
//!                              Used in Phase 3 when the MME allocates the TEID
//!                              and embeds it in `InitialContextSetupRequest`
//!                              before this method is called.
//!
//! ## UpfEvent mapping
//!
//! ```text
//! UpfEvent::CreateSession { ul_teid, entity_id, imsi, ue_ip, enb_addr, qci }
//!     → session_manager.create_session_with_teid(ul_teid, entity_id, imsi, ue_ip, enb_addr, qci)
//!
//! UpfEvent::UpdateBearer { ul_teid, dl_teid, enb_addr }
//!     → session_manager.update_bearer_info(ul_teid, dl_teid, enb_addr)
//!
//! UpfEvent::RemoveSession { ul_teid }
//!     → session_manager.remove_session(ul_teid)
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::upf::routing::{RouteEntry, RoutingTable};
use crate::upf::session::UserPlaneSession;

const INITIAL_UL_TEID: u32 = 0x0001_0000;

/// Manages all active user-plane sessions for one UPF instance.
pub struct SessionManager {
    next_ul_teid: u32,
    routing:      Arc<Mutex<RoutingTable>>,
    /// ul_teid → session record
    sessions:     HashMap<u32, UserPlaneSession>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            next_ul_teid: INITIAL_UL_TEID,
            routing:      Arc::new(Mutex::new(RoutingTable::new())),
            sessions:     HashMap::with_capacity(1024),
        }
    }

    /// Return an `Arc` handle to the shared routing table.
    /// Pass this into `GtpForwarder::bind_addr` so both share the same map.
    pub fn routing_arc(&self) -> Arc<Mutex<RoutingTable>> {
        Arc::clone(&self.routing)
    }

    // ── Session creation ──────────────────────────────────────────────────────

    /// Create a session with an internally allocated UL TEID.
    ///
    /// Use this for standalone UPF operation without MME coordination.
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
    /// Called when processing `UpfEvent::CreateSession`. The MME allocates the
    /// TEID and embeds it in `InitialContextSetupRequest.e_rabs_to_setup[*].gtp_teid`
    /// so the eNodeB knows where to send UL packets before this call completes.
    ///
    /// `dl_teid` and `enb_addr` are typically zero/placeholder at this point —
    /// they are set to real values when `update_bearer_info` is called after
    /// the `InitialContextSetupResponse` arrives from the eNodeB.
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
        tracing::info!(
            imsi, ul_teid, ue_ip = ?ue_ip,
            "User-plane session created (MME-allocated TEID)"
        );
    }

    // ── Bearer update ─────────────────────────────────────────────────────────

    /// Update DL TEID only — kept for backward compatibility.
    /// Prefer `update_bearer_info` for Phase 3 use.
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
    /// routing entry so the `GtpForwarder` never observes a partial update.
    ///
    /// Returns `false` if no session exists for `ul_teid`.
    pub fn update_bearer_info(
        &mut self,
        ul_teid:  u32,
        dl_teid:  u32,
        enb_addr: [u8; 4],
    ) -> bool {
        // Snapshot the current entry — need ue_ip and qci to rebuild it.
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
            s.dl_teid = dl_teid;
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
    /// Returns the session record for billing/audit purposes.
    pub fn remove_session(&mut self, ul_teid: u32) -> Option<UserPlaneSession> {
        self.routing.lock().unwrap().remove(ul_teid);
        if let Some(s) = self.sessions.remove(&ul_teid) {
            tracing::info!(
                imsi     = s.imsi,
                ul_teid,
                bytes_ul = s.bytes_ul,
                bytes_dl = s.bytes_dl,
                "User-plane session removed"
            );
            Some(s)
        } else {
            None
        }
    }

    // ── Lookups ───────────────────────────────────────────────────────────────

    pub fn get_session(&self, ul_teid: u32) -> Option<&UserPlaneSession> {
        self.sessions.get(&ul_teid)
    }

    /// Find a session by IMSI (linear scan — for control-plane queries only).
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
            active:   true,
            bytes_ul: 0,
            bytes_dl: 0,
        });
    }

    fn alloc_ul_teid(&mut self) -> u32 {
        let teid = self.next_ul_teid;
        self.next_ul_teid = self.next_ul_teid.wrapping_add(1);
        if self.next_ul_teid < INITIAL_UL_TEID { self.next_ul_teid = INITIAL_UL_TEID; }
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

    // ── create_session_with_teid (external TEID from MME) ─────────────────────

    #[test]
    fn create_session_with_teid_uses_provided_teid() {
        let mut m    = mgr();
        let ul_teid  = 0xDEAD_0001_u32;
        m.create_session_with_teid(ul_teid, 42, 234_15_9876543210, [10, 0, 1, 5], [0; 4], 9);

        assert_eq!(m.active_session_count(), 1);

        let s = m.get_session(ul_teid).unwrap();
        assert_eq!(s.ul_teid,   ul_teid);
        assert_eq!(s.entity_id, 42);
        assert_eq!(s.imsi,      234_15_9876543210);
        assert_eq!(s.dl_teid,   0, "dl_teid is placeholder until ICSRSP");

        // FIX E0716: bind the Arc before locking so the temporary outlives the guard
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

        // Internal counter unchanged — next create_session should still get INITIAL_UL_TEID
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

        // Session record updated
        let s = m.get_session(ul_teid).unwrap();
        assert_eq!(s.dl_teid, real_dl_teid);

        // FIX E0716: bind the Arc before locking
        let arc      = m.routing_arc();
        let rt       = arc.lock().unwrap();
        let ul_entry = rt.lookup_ul(ul_teid).unwrap();
        assert_eq!(ul_entry.dl_teid,  real_dl_teid);
        assert_eq!(ul_entry.enb_addr, real_enb_addr);

        // DL routing map (by UE IP) also updated — rt is still in scope
        let dl_entry = rt.lookup_dl(&[10, 0, 0, 3]).unwrap();
        assert_eq!(dl_entry.dl_teid,  real_dl_teid);
        assert_eq!(dl_entry.enb_addr, real_enb_addr);
    }

    #[test]
    fn update_bearer_info_preserves_ue_ip_and_qci() {
        let mut m   = mgr();
        let ul_teid = 0xDDDD_0001_u32;
        m.create_session_with_teid(ul_teid, 0, 1, [10, 1, 2, 3], [0; 4], 5);

        m.update_bearer_info(ul_teid, 0x1234_5678, [172, 16, 0, 1]);

        // FIX E0716: bind the Arc before locking
        let arc = m.routing_arc();
        let rt  = arc.lock().unwrap();
        let e   = rt.lookup_ul(ul_teid).unwrap();
        assert_eq!(e.ue_ip, [10, 1, 2, 3], "ue_ip must not change");
        assert_eq!(e.qci,   5,             "qci must not change");
    }

    #[test]
    fn update_bearer_info_returns_false_for_unknown() {
        let mut m = mgr();
        assert!(!m.update_bearer_info(0xDEAD_BEEF, 0x1234_5678, [1, 2, 3, 4]));
    }

    // ── Full lifecycle: create_with_teid → update_bearer → remove ─────────────

    #[test]
    fn full_phase3_lifecycle() {
        let mut m   = mgr();
        let ul_teid = 0x0001_0000_u32;
        let imsi    = 234_15_1234567890_u64;

        // 1. MME emits CreateSession — UPF creates session with placeholder DL info
        m.create_session_with_teid(ul_teid, 7, imsi, [10, 0, 5, 1], [0; 4], 9);
        assert_eq!(m.active_session_count(), 1);
        assert_eq!(m.get_session(ul_teid).unwrap().dl_teid, 0);

        // 2. MME emits UpdateBearer after ICSRSP from eNodeB
        let enb_dl_teid  = 0xABCD_1234_u32;
        let enb_addr     = [192u8, 168, 1, 200];
        assert!(m.update_bearer_info(ul_teid, enb_dl_teid, enb_addr));
        assert_eq!(m.get_session(ul_teid).unwrap().dl_teid, enb_dl_teid);

        // 3. Forwarder accounts bytes
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

    // ── find_by_imsi ──────────────────────────────────────────────────────────

    #[test]
    fn find_by_imsi_works() {
        let mut m    = mgr();
        let imsi     = 234_15_9999999999_u64;
        let ul_teid  = 0x0002_0000_u32;
        m.create_session_with_teid(ul_teid, 42, imsi, [10, 0, 0, 99], [0; 4], 9);
        let s = m.find_by_imsi(imsi).unwrap();
        assert_eq!(s.ul_teid,   ul_teid);
        assert_eq!(s.entity_id, 42);
        assert!(m.find_by_imsi(999).is_none());
    }

    // ── Routing cleanup ───────────────────────────────────────────────────────

    #[test]
    fn remove_cleans_both_routing_maps() {
        let mut m   = mgr();
        let ul_teid = 0x0003_0000_u32;
        m.create_session_with_teid(ul_teid, 0, 1, [10, 1, 2, 3], [0; 4], 9);
        m.update_bearer_info(ul_teid, 0xAAAA_0001, [192, 168, 0, 1]);

        // FIX E0716: bind the Arc before locking (first block)
        {
            let arc = m.routing_arc();
            let rt  = arc.lock().unwrap();
            assert!(rt.lookup_ul(ul_teid).is_some());
            assert!(rt.lookup_dl(&[10, 1, 2, 3]).is_some());
        }

        m.remove_session(ul_teid);

        // FIX E0716: bind the Arc before locking (second block)
        {
            let arc = m.routing_arc();
            let rt  = arc.lock().unwrap();
            assert!(rt.lookup_ul(ul_teid).is_none());
            assert!(rt.lookup_dl(&[10, 1, 2, 3]).is_none());
        }
    }
        }
