// crates/midn-userplane/src/upf/session_manager.rs
//! SessionManager — production user-plane session lifecycle.
//!
//! Higher-level than `TunnelManager`: owns the routing table as an
//! `Arc<Mutex<RoutingTable>>` so it can be shared with `GtpForwarder`.
//! Also tracks per-session byte counters and exposes IMSI-keyed lookups.
//!
//! ## Relationship to TunnelManager
//!
//! `TunnelManager` is a simple building block (counter + HashMap wrapper)
//! kept as-is for the existing bench suite. `SessionManager` replaces it
//! for production use, handling the full lifecycle including TEID updates
//! after `InitialContextSetupResponse` arrives from the eNodeB.
//!
//! ## Phase 3 checklist (beyond this file)
//!
//! - [ ] Mirror routing entry to eBPF BPF_MAP_TYPE_HASH in `create_session`
//! - [ ] Remove BPF entry in `remove_session`
//! - [ ] `update_dl_teid` — atomic BPF map update after ICSR response

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::upf::routing::{RouteEntry, RoutingTable};
use crate::upf::session::UserPlaneSession;

/// Starting value for allocated uplink TEIDs.
/// Values 0–65535 reserved; we start at 64k to avoid confusion.
const INITIAL_UL_TEID: u32 = 0x0001_0000;

/// Manages all active user-plane sessions for one UPF instance.
///
/// The internal `RoutingTable` is shared with `GtpForwarder` via
/// `Arc<Mutex<>>` so the forwarder can read routes without locking
/// `SessionManager` itself.
pub struct SessionManager {
    next_ul_teid: u32,
    routing:      Arc<Mutex<RoutingTable>>,
    /// ul_teid → session record
    sessions:     HashMap<u32, UserPlaneSession>,
}

impl SessionManager {
    /// Create a new session manager with an empty routing table.
    pub fn new() -> Self {
        Self {
            next_ul_teid: INITIAL_UL_TEID,
            routing:      Arc::new(Mutex::new(RoutingTable::new())),
            sessions:     HashMap::with_capacity(1024),
        }
    }

    /// Return an `Arc` handle to the shared routing table for use in
    /// `GtpForwarder::bind` / `GtpForwarder::bind_addr`.
    ///
    /// The forwarder and session manager share the same underlying map.
    pub fn routing_arc(&self) -> Arc<Mutex<RoutingTable>> {
        Arc::clone(&self.routing)
    }

    // ── Session lifecycle ─────────────────────────────────────────────────────

    /// Create a new data-plane session for a subscriber.
    ///
    /// Allocates an uplink TEID and installs a bidirectional routing entry.
    /// Returns the UL TEID to send to the eNodeB in `InitialContextSetupRequest`.
    ///
    /// Pass `dl_teid = 0` as a placeholder; the real value arrives in
    /// `InitialContextSetupResponse` — update it with `update_dl_teid`.
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
        let entry   = RouteEntry::new(ue_ip, dl_teid, enb_addr, qci);

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

        tracing::info!(
            imsi, ul_teid, dl_teid, ue_ip = ?ue_ip, enb_addr = ?enb_addr,
            "User-plane session created"
        );
        ul_teid
    }

    /// Update the downlink TEID once the eNodeB assigns it via
    /// `InitialContextSetupResponse`.
    ///
    /// Atomically replaces the routing entry — any in-flight lookups will
    /// continue to use the old (placeholder) value until the lock is released.
    ///
    /// Returns `false` if no session is found for `ul_teid`.
    pub fn update_dl_teid(&mut self, ul_teid: u32, real_dl_teid: u32) -> bool {
        // Copy the existing entry while holding the lock.
        let current = {
            let rt = self.routing.lock().unwrap();
            match rt.lookup_ul(ul_teid).copied() {
                Some(e) => e,
                None    => return false,
            }
        };

        // Re-install with updated DL TEID.
        {
            let mut rt = self.routing.lock().unwrap();
            rt.remove(ul_teid);
            let updated = RouteEntry::new(
                current.ue_ip, real_dl_teid, current.enb_addr, current.qci,
            );
            rt.install(ul_teid, updated);
        }

        // Update session record.
        if let Some(s) = self.sessions.get_mut(&ul_teid) {
            s.dl_teid = real_dl_teid;
        }

        tracing::debug!(ul_teid, real_dl_teid, "DL TEID updated after ICSR response");
        true
    }

    /// Remove a session on subscriber detach.
    ///
    /// Removes both routing entries and returns the session record for
    /// billing/audit purposes.
    pub fn remove_session(&mut self, ul_teid: u32) -> Option<UserPlaneSession> {
        self.routing.lock().unwrap().remove(ul_teid);
        if let Some(s) = self.sessions.remove(&ul_teid) {
            tracing::info!(
                imsi      = s.imsi,
                ul_teid,
                bytes_ul  = s.bytes_ul,
                bytes_dl  = s.bytes_dl,
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

    /// Find a session by IMSI (linear scan — infrequent, only for control-plane queries).
    pub fn find_by_imsi(&self, imsi: u64) -> Option<&UserPlaneSession> {
        self.sessions.values().find(|s| s.imsi == imsi)
    }

    // ── Byte accounting ───────────────────────────────────────────────────────

    /// Record bytes forwarded uplink for a session.
    pub fn account_uplink(&mut self, ul_teid: u32, bytes: u64) {
        if let Some(s) = self.sessions.get_mut(&ul_teid) {
            s.bytes_ul += bytes;
        }
    }

    /// Record bytes forwarded downlink for a session.
    pub fn account_downlink(&mut self, ul_teid: u32, bytes: u64) {
        if let Some(s) = self.sessions.get_mut(&ul_teid) {
            s.bytes_dl += bytes;
        }
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

    // ── Internal ─────────────────────────────────────────────────────────────

    fn alloc_ul_teid(&mut self) -> u32 {
        let teid = self.next_ul_teid;
        self.next_ul_teid = self.next_ul_teid.wrapping_add(1);
        // Skip zero and the reserved block on wraparound.
        if self.next_ul_teid < INITIAL_UL_TEID {
            self.next_ul_teid = INITIAL_UL_TEID;
        }
        teid
    }
}

impl Default for SessionManager {
    fn default() -> Self { Self::new() }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mgr() -> SessionManager { SessionManager::new() }

    #[test]
    fn create_and_remove_session() {
        let mut mgr = make_mgr();
        let ul = mgr.create_session(0, 234_15_1234567890, [10, 0, 0, 1], 0, [192, 168, 1, 1], 9);
        assert_eq!(mgr.active_session_count(), 1);
        assert!(mgr.get_session(ul).is_some());
        // Routing table should have the entry
        assert!(mgr.routing_arc().lock().unwrap().lookup_ul(ul).is_some());
        mgr.remove_session(ul);
        assert_eq!(mgr.active_session_count(), 0);
        assert!(mgr.routing_arc().lock().unwrap().lookup_ul(ul).is_none());
    }

    #[test]
    fn update_dl_teid_replaces_routing_entry() {
        let mut mgr = make_mgr();
        let ul = mgr.create_session(0, 1, [10, 0, 0, 1], 0, [192, 168, 1, 1], 9);

        assert!(mgr.update_dl_teid(ul, 0xDEAD_BEEF));

        // Session record updated
        let s = mgr.get_session(ul).unwrap();
        assert_eq!(s.dl_teid, 0xDEAD_BEEF);

        // Routing table updated — both UL and DL maps
        let rt = mgr.routing_arc().lock().unwrap();
        let ul_entry = rt.lookup_ul(ul).unwrap();
        assert_eq!(ul_entry.dl_teid, 0xDEAD_BEEF);
        let dl_entry = rt.lookup_dl(&[10, 0, 0, 1]).unwrap();
        assert_eq!(dl_entry.dl_teid, 0xDEAD_BEEF);
    }

    #[test]
    fn update_dl_teid_returns_false_for_unknown() {
        let mut mgr = make_mgr();
        assert!(!mgr.update_dl_teid(0xDEAD_BEEF, 0x1234_5678));
    }

    #[test]
    fn byte_accounting_totals() {
        let mut mgr = make_mgr();
        let ul = mgr.create_session(0, 1, [10, 0, 0, 1], 0, [1, 1, 1, 1], 9);
        mgr.account_uplink(ul, 1000);
        mgr.account_uplink(ul, 500);
        mgr.account_downlink(ul, 2048);
        assert_eq!(mgr.total_bytes_uplink(),   1500);
        assert_eq!(mgr.total_bytes_downlink(), 2048);
        let s = mgr.get_session(ul).unwrap();
        assert_eq!(s.bytes_ul, 1500);
        assert_eq!(s.bytes_dl, 2048);
    }

    #[test]
    fn unique_teid_per_session() {
        let mut mgr = make_mgr();
        let t1 = mgr.create_session(0, 1, [10, 0, 0, 1], 0, [1, 1, 1, 1], 9);
        let t2 = mgr.create_session(1, 2, [10, 0, 0, 2], 0, [1, 1, 1, 1], 9);
        let t3 = mgr.create_session(2, 3, [10, 0, 0, 3], 0, [1, 1, 1, 1], 9);
        assert_ne!(t1, t2);
        assert_ne!(t2, t3);
        assert_eq!(t1, INITIAL_UL_TEID);
        assert_eq!(t2, INITIAL_UL_TEID + 1);
        assert_eq!(t3, INITIAL_UL_TEID + 2);
    }

    #[test]
    fn find_by_imsi() {
        let mut mgr = make_mgr();
        let imsi = 234_15_9999999999_u64;
        let ul   = mgr.create_session(42, imsi, [10, 0, 0, 99], 0, [1, 1, 1, 1], 9);
        let s    = mgr.find_by_imsi(imsi).unwrap();
        assert_eq!(s.ul_teid, ul);
        assert_eq!(s.entity_id, 42);
        assert!(mgr.find_by_imsi(999).is_none());
    }

    #[test]
    fn remove_session_cleans_both_routing_maps() {
        let mut mgr = make_mgr();
        let ul = mgr.create_session(0, 1, [10, 1, 2, 3], 0xAAAA_0001, [192, 168, 0, 1], 9);
        {
            let rt = mgr.routing_arc().lock().unwrap();
            assert!(rt.lookup_ul(ul).is_some());
            assert!(rt.lookup_dl(&[10, 1, 2, 3]).is_some());
        }
        mgr.remove_session(ul);
        {
            let rt = mgr.routing_arc().lock().unwrap();
            assert!(rt.lookup_ul(ul).is_none());
            assert!(rt.lookup_dl(&[10, 1, 2, 3]).is_none());
        }
    }

    #[test]
    fn remove_session_returns_record_for_billing() {
        let mut mgr = make_mgr();
        let ul = mgr.create_session(7, 234_15_0000000007, [10, 0, 7, 1], 0, [1, 1, 1, 1], 9);
        mgr.account_uplink(ul, 99_999);
        let rec = mgr.remove_session(ul).unwrap();
        assert_eq!(rec.imsi,     234_15_0000000007);
        assert_eq!(rec.bytes_ul, 99_999);
        assert!(mgr.remove_session(ul).is_none()); // second remove returns None
    }
}
