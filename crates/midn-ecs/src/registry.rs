//! IMSI → EntityId reverse index.
//!
//! Separate from `World` because EntityId recycling means an IMSI→entity
//! mapping needs explicit register/deregister calls at exactly the
//! attach/detach boundaries.

use std::collections::HashMap;
use crate::world::EntityId;

pub struct ImsiRegistry {
    map: HashMap<u64, EntityId>,
}

impl ImsiRegistry {
    pub fn new() -> Self {
        Self { map: HashMap::with_capacity(1024) }
    }

    pub fn register(&mut self, imsi: u64, entity: EntityId) -> Option<EntityId> {
        self.map.insert(imsi, entity)
    }

    pub fn deregister(&mut self, imsi: u64) -> Option<EntityId> {
        self.map.remove(&imsi)
    }

    #[inline]
    pub fn lookup(&self, imsi: u64) -> Option<EntityId> {
        self.map.get(&imsi).copied()
    }

    pub fn len(&self) -> usize { self.map.len() }
    pub fn is_empty(&self) -> bool { self.map.is_empty() }
}

impl Default for ImsiRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_lookup_deregister() {
        let mut reg = ImsiRegistry::new();
        reg.register(1, 0);
        assert_eq!(reg.lookup(1), Some(0));
        reg.deregister(1);
        assert!(reg.lookup(1).is_none());
    }
}
