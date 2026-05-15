// crates/midn-core/src/ecs/registry.rs
//! IMSI → EntityId reverse index.
//!
//! When a UE sends an Attach Request containing its IMSI, the MME
//! must find the corresponding ECS entity in O(1). This registry is
//! the secondary index that makes that lookup fast.
//!
//! ## Invariants
//!
//! - An IMSI maps to at most ONE EntityId at any time.
//! - When a subscriber detaches, their IMSI is removed from the registry.
//! - IMSI values are u64 (BCD-decoded 15-digit integers).

use std::collections::HashMap;
use crate::ecs::world::EntityId;

/// Secondary index: IMSI (u64) → EntityId.
pub struct ImsiRegistry {
    map: HashMap<u64, EntityId>,
}

impl ImsiRegistry {
    pub fn new() -> Self {
        Self { map: HashMap::with_capacity(1024) }
    }

    /// Register a subscriber's IMSI → EntityId mapping.
    ///
    /// Returns the previous EntityId if the IMSI was already registered
    /// (indicates a re-attach without prior detach).
    pub fn register(&mut self, imsi: u64, entity: EntityId) -> Option<EntityId> {
        self.map.insert(imsi, entity)
    }

    /// Remove the IMSI mapping (call on detach or despawn).
    pub fn deregister(&mut self, imsi: u64) -> Option<EntityId> {
        self.map.remove(&imsi)
    }

    /// Look up an EntityId by IMSI. O(1).
    #[inline]
    pub fn lookup(&self, imsi: u64) -> Option<EntityId> {
        self.map.get(&imsi).copied()
    }

    pub fn len(&self) -> usize  { self.map.len() }
    pub fn is_empty(&self) -> bool { self.map.is_empty() }
}

impl Default for ImsiRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_lookup() {
        let mut reg = ImsiRegistry::new();
        let imsi   = 234_15_1234567890_u64;
        let entity = EntityId(0);
        assert!(reg.register(imsi, entity).is_none());
        assert_eq!(reg.lookup(imsi), Some(entity));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn deregister_removes_entry() {
        let mut reg = ImsiRegistry::new();
        let imsi = 234_15_0000000001_u64;
        reg.register(imsi, EntityId(42));
        assert_eq!(reg.deregister(imsi), Some(EntityId(42)));
        assert!(reg.lookup(imsi).is_none());
    }

    #[test]
    fn re_register_returns_old_entity() {
        let mut reg = ImsiRegistry::new();
        let imsi = 234_15_0000000002_u64;
        reg.register(imsi, EntityId(1));
        let old = reg.register(imsi, EntityId(2));
        assert_eq!(old, Some(EntityId(1)));
        assert_eq!(reg.lookup(imsi), Some(EntityId(2)));
    }
}
