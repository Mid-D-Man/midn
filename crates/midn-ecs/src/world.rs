//! World — dense SoA entity/component storage for MME/AMF subscriber state.
//!
//! Every live entity gets the same component shape — no archetype
//! diversity, so each component is one dense `Vec<T>` indexed directly by
//! entity id. `NasSecurityContext`/`TunnelComponent` are genuinely optional
//! (set post-SecurityModeComplete / Phase-3-only), so they stay
//! `Vec<Option<T>>`. Despawned slots are reused via a free list; despawn
//! overwrites components with fresh empty values, so `ZeroizeOnDrop` fires.
//!
//! `security5g`/`nas_security5g` are the 5G-AKA counterparts to
//! `security`/`nas_security` — added so a future `midn-core::amf` can share
//! this exact storage type the way it was always intended to (see this
//! module's own git history). Every entity carries both LTE and 5G slots
//! regardless of which protocol it's actually being driven by — a bit
//! wasteful memory-wise, but consistent with "no archetype diversity," and
//! `Mme`/`Amf` each construct their own separate `World` instance anyway
//! (see `midn_core::amf::state_machine`), so an LTE-only or 5G-only
//! deployment never actually populates the other protocol's fields.

use midn_proto::nas::NasSecurityContext;
use midn_proto::nas5gs::Nas5gsSecurityContext;
use crate::components::{
    AuthState, IdentityComponent, Nas5gsAkaContext, SecurityContext, TunnelComponent,
};

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
    security5g: Vec<Nas5gsAkaContext>,
    nas_security5g: Vec<Option<Nas5gsSecurityContext>>,
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
            security5g: Vec::with_capacity(capacity),
            nas_security5g: Vec::with_capacity(capacity),
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
        self.security5g.push(Nas5gsAkaContext::new_empty());
        self.nas_security5g.push(None);
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
        self.security5g[idx] = Nas5gsAkaContext::new_empty();
        self.nas_security5g[idx] = None;
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

    // ── LTE (S1AP/NAS-EPS) security ─────────────────────────────────────────

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

    // ── 5G (NGAP/NAS-5GS) security ───────────────────────────────────────────

    pub fn insert_security5g(&mut self, id: EntityId, security: Nas5gsAkaContext) {
        if self.is_live(id) { self.security5g[id as usize] = security; }
    }

    pub fn security5g(&self, id: EntityId) -> Option<&Nas5gsAkaContext> {
        if self.is_live(id) { self.security5g.get(id as usize) } else { None }
    }

    pub fn security5g_mut(&mut self, id: EntityId) -> Option<&mut Nas5gsAkaContext> {
        if self.is_live(id) { self.security5g.get_mut(id as usize) } else { None }
    }

    pub fn set_nas_security5g(&mut self, id: EntityId, ctx: Nas5gsSecurityContext) {
        if self.is_live(id) { self.nas_security5g[id as usize] = Some(ctx); }
    }

    pub fn nas_security5g(&self, id: EntityId) -> Option<&Nas5gsSecurityContext> {
        if self.is_live(id) { self.nas_security5g.get(id as usize)?.as_ref() } else { None }
    }

    pub fn nas_security5g_mut(&mut self, id: EntityId) -> Option<&mut Nas5gsSecurityContext> {
        if self.is_live(id) { self.nas_security5g.get_mut(id as usize)?.as_mut() } else { None }
    }

    // ── Tunnel (shared shape, GTP-U N3/S1-U TEIDs) ───────────────────────────

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

    #[test]
    fn spawn_gives_entities_an_empty_5g_aka_context_by_default() {
        let mut w = World::new();
        let e = w.spawn();
        assert!(w.security5g(e).is_some(), "security5g is mandatory per-entity, mirrors security");
        assert_eq!(w.security5g(e).unwrap().pending_xres_star, [0u8; 16]);
    }

    #[test]
    fn insert_and_read_security5g() {
        let mut w = World::new();
        let e = w.spawn();
        let mut ctx = crate::components::Nas5gsAkaContext::new_empty();
        ctx.ck = [0xBB; 16];
        w.insert_security5g(e, ctx);
        assert_eq!(w.security5g(e).unwrap().ck, [0xBB; 16]);
    }

    #[test]
    fn security5g_zeroizes_on_despawn() {
        let mut w = World::new();
        let e = w.spawn();
        let mut ctx = crate::components::Nas5gsAkaContext::new_empty();
        ctx.ck = [0xBB; 16];
        w.insert_security5g(e, ctx);
        w.despawn(e);
        let e2 = w.spawn();
        assert_eq!(e, e2, "recycled id");
        assert_eq!(w.security5g(e2).unwrap().ck, [0u8; 16], "despawn must reset security5g");
    }

    #[test]
    fn nas_security5g_is_none_until_set() {
        let mut w = World::new();
        let e = w.spawn();
        assert!(w.nas_security5g(e).is_none());
    }

    #[test]
    fn dead_id_5g_ops_are_safe_noops() {
        let mut w = World::new();
        assert!(w.security5g(999).is_none());
        assert!(w.nas_security5g(999).is_none());
    }

    #[test]
    fn lte_and_5g_security_slots_are_independent() {
        let mut w = World::new();
        let e = w.spawn();
        let mut lte_ctx = SecurityContext::new_empty();
        lte_ctx.ck = [0x11; 16];
        w.insert_security(e, lte_ctx);

        let mut fiveg_ctx = crate::components::Nas5gsAkaContext::new_empty();
        fiveg_ctx.ck = [0x22; 16];
        w.insert_security5g(e, fiveg_ctx);

        assert_eq!(w.security(e).unwrap().ck, [0x11; 16]);
        assert_eq!(w.security5g(e).unwrap().ck, [0x22; 16]);
    }
}
