// crates/midn-userplane/src/upf/routing.rs
//! GTP-U routing table — TEID → next-hop resolution.
//!
//! Maps uplink TEIDs (UE → internet) and UE IP addresses (internet → UE)
//! to routing entries for fast packet forwarding decisions.
//!
//! ## Performance
//!
//! HashMap provides O(1) amortized lookup. For Phase 3, this table is
//! mirrored into a BPF_MAP_TYPE_HASH in the kernel — the XDP program
//! reads it directly without touching userspace.

use std::collections::HashMap;

/// Routing entry: maps a subscriber's tunnel to forwarding information.
#[derive(Debug, Clone, Copy)]
pub struct RouteEntry {
    /// Subscriber's assigned IPv4 address (source for PDN-bound traffic).
    pub ue_ip:       [u8; 4],
    /// Downlink TEID — used when encapsulating packets destined for UE.
    pub dl_teid:     u32,
    /// eNodeB/gNodeB transport address (DL GTP-U destination).
    pub enb_addr:    [u8; 4],
    /// eNodeB GTP-U port (always 2152 for standard deployments).
    pub enb_port:    u16,
    /// QoS Class Identifier (1–9, 65–66, 69–70 for special bearers).
    pub qci:         u8,
}

impl RouteEntry {
    pub fn new(
        ue_ip: [u8; 4],
        dl_teid: u32,
        enb_addr: [u8; 4],
        qci: u8,
    ) -> Self {
        Self { ue_ip, dl_teid, enb_addr, enb_port: 2152, qci }
    }
}

/// Bidirectional routing table.
///
/// UL path: `ul_teid → RouteEntry`
/// DL path: `ue_ip   → RouteEntry`
pub struct RoutingTable {
    /// Uplink TEID → route (UE → PDN direction)
    ul_map: HashMap<u32, RouteEntry>,
    /// UE IP address → route (PDN → UE direction)
    dl_map: HashMap<[u8; 4], RouteEntry>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            ul_map: HashMap::with_capacity(1024),
            dl_map: HashMap::with_capacity(1024),
        }
    }

    /// Install a bidirectional route for a new subscriber session.
    ///
    /// Called when InitialContextSetupResponse is received from eNodeB
    /// and the bearer has been established.
    pub fn install(
        &mut self,
        ul_teid:   u32,
        entry:     RouteEntry,
    ) {
        self.dl_map.insert(entry.ue_ip, entry);
        self.ul_map.insert(ul_teid, entry);
    }

    /// Remove all routes for a subscriber (called on detach).
    pub fn remove(&mut self, ul_teid: u32) -> Option<RouteEntry> {
        if let Some(entry) = self.ul_map.remove(&ul_teid) {
            self.dl_map.remove(&entry.ue_ip);
            Some(entry)
        } else {
            None
        }
    }

    /// Uplink lookup: TEID → route entry. O(1). Hot path.
    #[inline(always)]
    pub fn lookup_ul(&self, ul_teid: u32) -> Option<&RouteEntry> {
        self.ul_map.get(&ul_teid)
    }

    /// Downlink lookup: UE IP → route entry. O(1). Hot path.
    #[inline(always)]
    pub fn lookup_dl(&self, ue_ip: &[u8; 4]) -> Option<&RouteEntry> {
        self.dl_map.get(ue_ip)
    }

    pub fn len(&self) -> usize { self.ul_map.len() }
    pub fn is_empty(&self) -> bool { self.ul_map.is_empty() }
}

impl Default for RoutingTable { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(ue_ip: [u8; 4], dl_teid: u32) -> RouteEntry {
        RouteEntry::new(ue_ip, dl_teid, [192, 168, 1, 100], 9)
    }

    #[test]
    fn install_and_lookup_bidirectional() {
        let mut table = RoutingTable::new();
        let ul_teid = 0x1000_0001u32;
        let entry   = make_entry([10, 0, 0, 1], 0x2000_0001);
        table.install(ul_teid, entry);

        let ul_hit = table.lookup_ul(ul_teid).unwrap();
        assert_eq!(ul_hit.dl_teid, 0x2000_0001);

        let dl_hit = table.lookup_dl(&[10, 0, 0, 1]).unwrap();
        assert_eq!(dl_hit.dl_teid, 0x2000_0001);
    }

    #[test]
    fn remove_cleans_both_maps() {
        let mut table = RoutingTable::new();
        let ul_teid = 0xAAAA_0001u32;
        let entry   = make_entry([10, 0, 1, 1], 0xBBBB_0001);
        table.install(ul_teid, entry);
        assert_eq!(table.len(), 1);
        table.remove(ul_teid);
        assert!(table.lookup_ul(ul_teid).is_none());
        assert!(table.lookup_dl(&[10, 0, 1, 1]).is_none());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn lookup_miss_returns_none() {
        let table = RoutingTable::new();
        assert!(table.lookup_ul(0xDEAD_BEEF).is_none());
        assert!(table.lookup_dl(&[1, 2, 3, 4]).is_none());
    }

    #[test]
    fn large_table_no_collisions() {
        let mut table = RoutingTable::new();
        for i in 0u32..1000 {
            let ip     = [(i >> 8) as u8, (i & 0xFF) as u8, 0, 0];
            let entry  = make_entry(ip, i * 2);
            table.install(i, entry);
        }
        assert_eq!(table.len(), 1000);
        for i in 0u32..1000 {
            assert!(table.lookup_ul(i).is_some());
        }
    }
}
