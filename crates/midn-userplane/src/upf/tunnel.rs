// crates/midn-userplane/src/upf/tunnel.rs
//! GTP-U tunnel manager — lifecycle of GTP-U tunnels.
//!
//! Manages the creation and teardown of GTP-U tunnels.
//! Allocates uplink TEIDs for new sessions and coordinates with
//! the RoutingTable.
//!
//! ## TEID allocation
//!
//! TEIDs are 32-bit identifiers chosen by this UPF for UL tunnels.
//! DL TEIDs are assigned by the eNodeB and carried in
//! InitialContextSetupResponse. A simple counter provides unique TEIDs;
//! Phase 3 can improve this with a proper allocator.

use crate::upf::routing::{RouteEntry, RoutingTable};

/// GTP-U tunnel manager.
pub struct TunnelManager {
    /// Next uplink TEID to allocate (monotonically increasing).
    next_ul_teid: u32,
    /// Routing table managed by this tunnel manager.
    pub routing:  RoutingTable,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            next_ul_teid: 0x0001_0000, // start at 64k to avoid low values
            routing: RoutingTable::new(),
        }
    }

    /// Create a new GTP-U tunnel for a subscriber session.
    ///
    /// Allocates a UL TEID, installs bidirectional routing, returns the UL TEID
    /// to send to the eNodeB in InitialContextSetupRequest.
    pub fn create_tunnel(
        &mut self,
        ue_ip:    [u8; 4],
        dl_teid:  u32,       // assigned by eNodeB
        enb_addr: [u8; 4],
        qci:      u8,
    ) -> u32 {
        let ul_teid = self.alloc_ul_teid();
        let entry   = RouteEntry::new(ue_ip, dl_teid, enb_addr, qci);
        self.routing.install(ul_teid, entry);
        tracing::debug!(
            ul_teid, dl_teid, ue_ip = ?ue_ip, enb_addr = ?enb_addr,
            "GTP-U tunnel created"
        );
        ul_teid
    }

    /// Teardown a tunnel by its uplink TEID (called on detach).
    pub fn destroy_tunnel(&mut self, ul_teid: u32) {
        if self.routing.remove(ul_teid).is_some() {
            tracing::debug!(ul_teid, "GTP-U tunnel destroyed");
        }
    }

    /// Allocate the next uplink TEID. Wraps on overflow.
    fn alloc_ul_teid(&mut self) -> u32 {
        let teid = self.next_ul_teid;
        self.next_ul_teid = self.next_ul_teid.wrapping_add(1);
        if self.next_ul_teid == 0 { self.next_ul_teid = 0x0001_0000; }
        teid
    }

    pub fn active_tunnel_count(&self) -> usize { self.routing.len() }
}

impl Default for TunnelManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_destroy_tunnel() {
        let mut mgr = TunnelManager::new();
        let ul_teid = mgr.create_tunnel(
            [10, 0, 0, 1], 0xBBBB_0001, [192, 168, 1, 100], 9
        );
        assert_eq!(mgr.active_tunnel_count(), 1);
        // UL lookup should work
        assert!(mgr.routing.lookup_ul(ul_teid).is_some());
        // DL lookup by UE IP should work
        assert!(mgr.routing.lookup_dl(&[10, 0, 0, 1]).is_some());
        mgr.destroy_tunnel(ul_teid);
        assert_eq!(mgr.active_tunnel_count(), 0);
    }

    #[test]
    fn teid_allocation_is_unique() {
        let mut mgr = TunnelManager::new();
        let t1 = mgr.create_tunnel([10, 0, 0, 1], 0x1000, [1, 1, 1, 1], 9);
        let t2 = mgr.create_tunnel([10, 0, 0, 2], 0x2000, [1, 1, 1, 1], 9);
        assert_ne!(t1, t2);
    }
}
