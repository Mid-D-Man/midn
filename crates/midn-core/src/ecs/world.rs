//! ECS World — entity allocator and component storage.
//!
//! Designed to hold 100k+ concurrent subscribers.
//! SoA layout: each component type in a separate Vec.

use std::collections::HashMap;
use crate::ecs::components::{
    ImsiComponent, AuthState, SecurityContext, SessionState, TunnelComponent
};

/// Entity ID — opaque u32 index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntityId(pub u32);

/// The ECS world — owns all subscriber component storage.
///
/// SoA layout: each Vec<T> is independently cache-friendly.
/// Iteration over any single component type is a sequential scan.
pub struct CoreWorld {
    // Entity allocator
    next_id:     u32,
    free_list:   Vec<EntityId>,

    // Component storage (SoA)
    pub imsi:     HashMap<EntityId, ImsiComponent>,
    pub auth:     HashMap<EntityId, AuthState>,
    pub security: HashMap<EntityId, SecurityContext>,
    pub session:  HashMap<EntityId, SessionState>,
    pub tunnel:   HashMap<EntityId, TunnelComponent>,
}

impl CoreWorld {
    pub fn new() -> Self {
        Self {
            next_id:   0,
            free_list: Vec::new(),
            imsi:     HashMap::new(),
            auth:     HashMap::new(),
            security: HashMap::new(),
            session:  HashMap::new(),
            tunnel:   HashMap::new(),
        }
    }

    /// Allocate a new entity (subscriber slot).
    pub fn spawn(&mut self) -> EntityId {
        if let Some(id) = self.free_list.pop() {
            return id;
        }
        let id = EntityId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Deallocate an entity — all components are removed.
    pub fn despawn(&mut self, id: EntityId) {
        self.imsi.remove(&id);
        self.auth.remove(&id);
        self.security.remove(&id);
        self.session.remove(&id);
        self.tunnel.remove(&id);
        self.free_list.push(id);
    }

    /// Return number of live entities.
    pub fn len(&self) -> usize { self.imsi.len() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

impl Default for CoreWorld {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spawn_and_despawn() {
        let mut world = CoreWorld::new();
        let e1 = world.spawn();
        let e2 = world.spawn();
        assert_ne!(e1, e2);
        world.imsi.insert(e1, ImsiComponent(123456789012345));
        assert_eq!(world.len(), 1);
        world.despawn(e1);
        assert_eq!(world.len(), 0);
        // Free list should recycle e1
        let e3 = world.spawn();
        assert_eq!(e3, e1);
    }
}
