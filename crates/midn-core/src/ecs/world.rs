// crates/midn-core/src/ecs/world.rs
//! CoreWorld — entity allocator and component storage.
//!
//! ## Storage model (Phase 1)
//!
//! `HashMap<EntityId, ComponentT>` per component type. Correct for
//! 100k subscribers but not cache-optimal. A dense SoA layout (Phase 2)
//! would improve bulk iteration by 4–10× for operations like
//! "expire all sessions older than T" or "collect all active tunnels".
//!
//! The public interface (spawn/despawn/get/insert) is stable across phases.

use std::collections::HashMap;
use crate::ecs::components::{
    AuthState, ImsiComponent, SecurityContext, SessionState, TunnelComponent,
};

/// Opaque entity identifier. Recycled via free list on despawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntityId(pub u32);

impl EntityId {
    pub const INVALID: Self = Self(u32::MAX);
}

impl core::fmt::Display for EntityId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "UE#{}", self.0)
    }
}

/// The ECS world — owns all subscriber component storage.
///
/// Component access is O(1) HashMap lookup per component type.
/// All collections are pre-allocated with capacity 1024 (configurable).
pub struct CoreWorld {
    // ── Entity allocator ──────────────────────────────────────────────────
    next_id:   u32,
    free_list: Vec<EntityId>,

    // ── Component storage (SoA, one collection per type) ──────────────────
    pub imsi:     HashMap<EntityId, ImsiComponent>,
    pub auth:     HashMap<EntityId, AuthState>,
    pub security: HashMap<EntityId, SecurityContext>,
    pub session:  HashMap<EntityId, SessionState>,
    pub tunnel:   HashMap<EntityId, TunnelComponent>,
}

impl CoreWorld {
    /// Create a new world pre-allocated for `capacity` subscribers.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            next_id:   0,
            free_list: Vec::with_capacity(64),
            imsi:     HashMap::with_capacity(capacity),
            auth:     HashMap::with_capacity(capacity),
            security: HashMap::with_capacity(capacity),
            session:  HashMap::with_capacity(capacity),
            tunnel:   HashMap::with_capacity(capacity),
        }
    }

    pub fn new() -> Self { Self::with_capacity(1024) }

    // ── Entity lifecycle ──────────────────────────────────────────────────

    /// Allocate a new entity (subscriber slot). O(1).
    pub fn spawn(&mut self) -> EntityId {
        if let Some(id) = self.free_list.pop() {
            return id;
        }
        let id = EntityId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    /// Deallocate an entity — all components are dropped and zeroized. O(1).
    ///
    /// SecurityContext is ZeroizeOnDrop — key material is wiped at this point.
    pub fn despawn(&mut self, id: EntityId) {
        self.imsi.remove(&id);
        self.auth.remove(&id);
        self.security.remove(&id);  // triggers ZeroizeOnDrop → keys wiped
        self.session.remove(&id);
        self.tunnel.remove(&id);
        self.free_list.push(id);
    }

    // ── Convenience accessors ─────────────────────────────────────────────

    pub fn auth_state(&self, id: EntityId) -> Option<AuthState> {
        self.auth.get(&id).copied()
    }

    pub fn set_auth_state(&mut self, id: EntityId, state: AuthState) {
        self.auth.insert(id, state);
    }

    pub fn is_authenticated(&self, id: EntityId) -> bool {
        matches!(self.auth.get(&id), Some(AuthState::Authenticated))
    }

    // ── Metrics ───────────────────────────────────────────────────────────

    /// Number of live entities (subscribers with at least an IMSI component).
    pub fn len(&self) -> usize { self.imsi.len() }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Number of fully authenticated subscribers.
    pub fn authenticated_count(&self) -> usize {
        self.auth.values().filter(|s| **s == AuthState::Authenticated).count()
    }

    /// Number of active PDN sessions.
    pub fn active_session_count(&self) -> usize {
        self.session.values().filter(|s| s.active).count()
    }
}

impl Default for CoreWorld {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_and_despawn_basic() {
        let mut world = CoreWorld::new();
        let e1 = world.spawn();
        let e2 = world.spawn();
        assert_ne!(e1, e2);
        world.imsi.insert(e1, ImsiComponent(234_15_1234567890_u64));
        assert_eq!(world.len(), 1);
        world.despawn(e1);
        assert_eq!(world.len(), 0);
    }

    #[test]
    fn despawn_recycles_id() {
        let mut world = CoreWorld::new();
        let e1 = world.spawn();
        world.despawn(e1);
        let e2 = world.spawn();
        assert_eq!(e1, e2, "despawned id should be recycled");
    }

    #[test]
    fn auth_state_lifecycle() {
        let mut world = CoreWorld::new();
        let ue = world.spawn();
        world.auth.insert(ue, AuthState::Unauthenticated);
        assert!(!world.is_authenticated(ue));
        world.set_auth_state(ue, AuthState::Authenticated);
        assert!(world.is_authenticated(ue));
        assert_eq!(world.authenticated_count(), 1);
    }

    #[test]
    fn security_context_zeroize_on_despawn() {
        let mut world = CoreWorld::new();
        let ue = world.spawn();
        let mut ctx = SecurityContext::new_empty();
        ctx.ck = [0xAA; 16];
        world.security.insert(ue, ctx);
        // despawn triggers Drop → ZeroizeOnDrop wipes memory
        world.despawn(ue);
        assert!(world.security.get(&ue).is_none());
    }

    #[test]
    fn large_spawn_capacity() {
        let mut world = CoreWorld::with_capacity(100_000);
        let ids: Vec<EntityId> = (0..1000).map(|_| world.spawn()).collect();
        assert_eq!(ids.len(), 1000);
        // All unique
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 1000);
    }
}
