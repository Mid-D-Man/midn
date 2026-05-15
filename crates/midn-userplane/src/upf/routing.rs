//! Routing table — maps TEID to subscriber next-hop.
//!
//! Every incoming GTP-U packet carries a TEID. The routing table
//! maps TEID → destination (PDN IP, or another tunnel).

use std::collections::HashMap;

/// A routing entry: maps an uplink TEID to an internet destination.
#[derive(Debug, Clone, Copy)]
pub struct RouteEntry {
    /// Subscriber's assigned IP address (source in PDN direction)
    pub ue_ip:      [u8; 4],
    /// PDN gateway IP address
    pub pdn_gw_ip:  [u8; 4],
    /// Downlink TEID (toward eNodeB)
    pub dl_teid:    u32,
    /// eNodeB transport address
    pub enb_ip:     [u8; 4],
    pub enb_port:   u16,
}

pub struct RoutingTable {
    /// ul_teid → RouteEntry
    entries: HashMap<u32, RouteEntry>,
}

impl RoutingTable {
    pub fn new() -> Self { Self { entries: HashMap::new() } }

    pub fn insert(&mut self, ul_teid: u32, entry: RouteEntry) {
        self.entries.insert(ul_teid, entry);
    }

    pub fn remove(&mut self, ul_teid: u32) -> Option<RouteEntry> {
        self.entries.remove(&ul_teid)
    }

    #[inline(always)]
    pub fn lookup(&self, ul_teid: u32) -> Option<&RouteEntry> {
        self.entries.get(&ul_teid)
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

impl Default for RoutingTable { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn insert_and_lookup() {
        let mut table = RoutingTable::new();
        let entry = RouteEntry {
            ue_ip: [10, 0, 0, 1],
            pdn_gw_ip: [203, 0, 113, 1],
            dl_teid: 0xAAAA_0001,
            enb_ip: [192, 168, 1, 1],
            enb_port: 2152,
        };
        table.insert(0xBBBB_0001, entry);
        let found = table.lookup(0xBBBB_0001).unwrap();
        assert_eq!(found.ue_ip, [10, 0, 0, 1]);
        assert!(table.lookup(0xDEAD_BEEF).is_none());
    }
}
