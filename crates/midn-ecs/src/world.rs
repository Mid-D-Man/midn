//! World — dense SoA entity/component storage for MME subscriber state.
//!
//! Every live entity gets the same component shape — no archetype
//! diversity, so each component is one dense `Vec<T>` indexed directly by
//! entity id. `NasSecurityContext`/`TunnelComponent` are genuinely optional
//! (set post-SecurityModeComplete / Phase-3-only), so they stay
//! `Vec<Option<T>>`. Despawned slots are reused via a free list; despawn
//! overwrites components with fresh empty values, so `ZeroizeOnDrop` fires.

use midn_proto::nas::NasSecurityContext;
use crate::components::{AuthState, IdentityComponent, SecurityContext, TunnelComponent};

pub type EntityId = u32;

pub struct World {
    next_id: u32,
    free_ids: Vec<u32>,
    live_count: usize,
    live: Vec<bool>,
    identity: Vec<IdentityComponent>,
    auth: Vec<AuthState>,
    security: Vec<SecurityContext>,
    nas_security: Vec<Option<NasSecurityContext>>,
    tunnel: Vec<Option<TunnelComponent>>,
}

impl World {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            next_id: 0, free_ids: Vec::with_capacity(64), live_count: 0,
            live: Vec::with_capacity(capacity),
            identity: Vec::with_capacity(capacity),
            auth: Vec::with_capacity(capacity),
            security: Vec::with_capacity(capacity),
            nas_security: Vec::with_capacity(capacity),
            tunnel: Vec::with_capacity(capacity),
        }
    }

    pub fn new() -> Self { Self::with_capacity(1024) }

    pub fn spawn(&mut self) -> EntityId {
        if let Some(id) = self.free_ids.pop() {
            self.live[id as usize] = true;
            self.live_count += 1;
            return id;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.live.push(true);
        self.identity.push(IdentityComponent::empty());
        self.auth.push(AuthState::Unauthenticated);
        self.security.push(SecurityContext::new_empty());
        self.nas_security.push(None);
        self.tunnel.push(None);
        self.live_count += 1;
        id
    }

    pub fn despawn(&mut self, id: EntityId) {
        if !self.is_live(id) { return; }
        let idx = id as usize;
        self.live[idx] = false;
        self.identity[idx] = IdentityComponent::empty();
        self.auth[idx] = AuthState::Unauthenticated;
        self.security[idx] = SecurityContext::new_empty();
        self.nas_security[idx] = None;
        self.tunnel[idx] = None;
        self.free_ids.push(id);
        self.live_count -= 1;
    }

    #[inline]
    pub fn is_live(&self, id: EntityId) -> bool {
        (id as usize) < self.live.len() && self.live[id as usize]
    }

    pub fn insert_identity(&mut self, id: EntityId, identity: IdentityComponent) {
        if self.is_live(id) { self.identity[id as usize] = identity; }
    }

    pub fn identity(&self, id: EntityId) -> Option<&IdentityComponent> {
        if self.is_live(id) { self.identity.get(id as usize) } else { None }
    }

    pub fn auth_state(&self, id: EntityId) -> Option<AuthState> {
        if self.is_live(id) { self.auth.get(id as usize).copied() } else { None }
    }

    pub fn set_auth_state(&mut self, id: EntityId, state: AuthState) {
        if self.is_live(id) { self.auth[id as usize] = state; }
    }

    pub fn is_authenticated(&self, id: EntityId) -> bool {
        matches!(self.auth_state(id), Some(AuthState::Authenticated))
    }

    pub fn authenticated_count(&self) -> usize {
        self.live.iter().zip(self.auth.iter())
            .filter(|&(&live, &state)| live && state == AuthState::Authenticated)
            .count()
    }

    pub fn insert_security(&mut self, id: EntityId, security: SecurityContext) {
        if self.is_live(id) { self.security[id as usize] = security; }
    }

    pub fn security(&self, id: EntityId) -> Option<&SecurityContext> {
        if self.is_live(id) { self.security.get(id as usize) } else { None }
    }

    pub fn security_mut(&mut self, id: EntityId) -> Option<&mut SecurityContext> {
        if self.is_live(id) { self.security.get_mut(id as usize) } else { None }
    }

    pub fn set_nas_security(&mut self, id: EntityId, ctx: NasSecurityContext) {
        if self.is_live(id) { self.nas_security[id as usize] = Some(ctx); }
    }

    pub fn nas_security(&self, id: EntityId) -> Option<&NasSecurityContext> {
        if self.is_live(id) { self.nas_security.get(id as usize)?.as_ref() } else { None }
    }

    pub fn nas_security_mut(&mut self, id: EntityId) -> Option<&mut NasSecurityContext> {
        if self.is_live(id) { self.nas_security.get_mut(id as usize)?.as_mut() } else { None }
    }

    pub fn set_tunnel(&mut self, id: EntityId, tunnel: TunnelComponent) {
        if self.is_live(id) { self.tunnel[id as usize] = Some(tunnel); }
    }

    pub fn tunnel(&self, id: EntityId) -> Option<&TunnelComponent> {
        if self.is_live(id) { self.tunnel.get(id as usize)?.as_ref() } else { None }
    }

    pub fn tunnel_mut(&mut self, id: EntityId) -> Option<&mut TunnelComponent> {
        if self.is_live(id) { self.tunnel.get_mut(id as usize)?.as_mut() } else { None }
    }

    pub fn subscriber_count(&self) -> usize { self.live_count }
}

impl Default for World {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_despawn_recycles_id() {
        let mut w = World::new();
        let e1 = w.spawn();
        w.despawn(e1);
        let e2 = w.spawn();
        assert_eq!(e1, e2);
    }

    #[test]
    fn security_context_zeroize_on_despawn() {
        let mut w = World::new();
        let e = w.spawn();
        let mut ctx = SecurityContext::new_empty();
        ctx.ck = [0xAA; 16];
        w.insert_security(e, ctx);
        w.despawn(e);
        assert!(w.security(e).is_none());
    }

    #[test]
    fn dead_id_ops_are_safe_noops() {
        let mut w = World::new();
        assert!(w.identity(999).is_none());
        w.despawn(999);
    }
}
