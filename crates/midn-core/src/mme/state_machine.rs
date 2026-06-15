// crates/midn-core/src/mme/state_machine.rs
//! MME state machine — main `Mme` struct and `process_s1ap` entry point.
//!
//! ## ECS model
//!
//! Each attached UE maps to an `EntityId` (u32).  Components are stored in
//! per-type HashMaps inside `World`. The `ImsiRegistry` independently maps
//! IMSI → EntityId for subscriber lookup.
//!
//! ## Phase modes
//!
//! | Mode    | Trigger                  | SecModeComplete response          |
//! |---------|--------------------------|-----------------------------------|
//! | Phase 2 | `Mme::new()`             | DownlinkNasTransport(AttachAccept)|
//! | Phase 3 | `.with_phase3(upf_addr)` | InitialContextSetupRequest        |

use std::collections::HashMap;

use crate::s1ap::S1apMessage;
use crate::hss::Hss;
use crate::mme::attach;

// ── EntityId ──────────────────────────────────────────────────────────────────

pub type EntityId = u32;

// ── Component types ───────────────────────────────────────────────────────────

/// Per-UE attach state — lives from AttachRequest until SecModeComplete.
#[derive(Clone, Debug)]
pub struct AttachContext {
    pub imsi:           u64,
    pub enb_ue_s1ap_id: u32,
    pub mme_ue_s1ap_id: u32,
    /// 128-bit RAND used in the auth challenge.
    pub rand:           [u8; 16],
    /// XRES = f2 output; compared with UE's RES in constant time.
    pub xres:           [u8; 8],
    /// f3 output — used for deriving Kasme.
    pub ck:             [u8; 16],
    /// f4 output — used for deriving Kasme.
    pub ik:             [u8; 16],
    /// SQN used for AUTN.
    pub sqn_used:       [u8; 6],
    /// UE PDN address (from AttachRequest or allocated by MME).
    pub ue_ip:          [u8; 4],
    /// Uplink GTP-U TEID allocated in SecModeComplete (Phase 3 only).
    pub ul_teid:        Option<u32>,
}

/// Per-UE session state — lives from SecModeComplete onward.
#[derive(Clone, Debug)]
pub struct SessionState {
    pub imsi:    u64,
    pub ul_teid: u32,
}

/// GTP-U tunnel endpoint — updated by `handle_icsrsp` with real DL TEID.
#[derive(Clone, Debug)]
pub struct TunnelComponent {
    pub ul_teid:  u32,
    pub dl_teid:  u32,
    pub enb_addr: [u8; 4],
}

// ── World (simple ECS) ────────────────────────────────────────────────────────

#[derive(Default)]
pub struct World {
    next_id:         u32,
    free_ids:        Vec<u32>,
    attach_contexts: HashMap<u32, AttachContext>,
    session_states:  HashMap<u32, SessionState>,
    tunnels:         HashMap<u32, TunnelComponent>,
}

impl World {
    pub fn new() -> Self { Self::default() }

    pub fn spawn(&mut self) -> u32 {
        self.free_ids.pop().unwrap_or_else(|| {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            id
        })
    }

    pub fn despawn(&mut self, entity: u32) {
        self.attach_contexts.remove(&entity);
        self.session_states.remove(&entity);
        self.tunnels.remove(&entity);
        self.free_ids.push(entity);
    }

    pub fn insert_attach_context(&mut self, entity: u32, ctx: AttachContext) {
        self.attach_contexts.insert(entity, ctx);
    }
    pub fn get_attach_context(&self, entity: u32) -> Option<AttachContext> {
        self.attach_contexts.get(&entity).cloned()
    }
    pub fn get_attach_context_mut(&mut self, entity: u32) -> Option<&mut AttachContext> {
        self.attach_contexts.get_mut(&entity)
    }

    pub fn insert_session_state(&mut self, entity: u32, s: SessionState) {
        self.session_states.insert(entity, s);
    }

    pub fn insert_tunnel(&mut self, entity: u32, t: TunnelComponent) {
        self.tunnels.insert(entity, t);
    }
    pub fn get_tunnel_mut(&mut self, entity: u32) -> Option<&mut TunnelComponent> {
        self.tunnels.get_mut(&entity)
    }
}

// ── ImsiRegistry ──────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct ImsiRegistry {
    map: HashMap<u64, u32>,
}

impl ImsiRegistry {
    pub fn new() -> Self { Self::default() }
    pub fn register(&mut self, imsi: u64, entity: u32) { self.map.insert(imsi, entity); }
    pub fn deregister(&mut self, imsi: u64) { self.map.remove(&imsi); }
    pub fn lookup(&self, imsi: u64) -> Option<u32> { self.map.get(&imsi).copied() }
}

// ── UpfEvent ──────────────────────────────────────────────────────────────────

/// Events emitted to the UPF orchestrator / caller.
#[derive(Debug, Clone)]
pub enum UpfEvent {
    CreateSession {
        ul_teid:   u32,
        entity_id: u32,
        imsi:      u64,
        ue_ip:     [u8; 4],
        enb_addr:  [u8; 4],
        qci:       u8,
    },
    UpdateBearer {
        ul_teid:  u32,
        dl_teid:  u32,
        enb_addr: [u8; 4],
    },
    RemoveSession {
        ul_teid: u32,
    },
}

// ── Mme ───────────────────────────────────────────────────────────────────────

pub struct Mme {
    world:        World,
    registry:     ImsiRegistry,
    pub hss:      Hss,
    phase3_upf:   Option<[u8; 4]>,
    teid_counter: u32,
}

impl Mme {
    /// Phase 2 mode — SecModeComplete → DownlinkNasTransport(AttachAccept).
    pub fn new() -> Self {
        Self {
            world:        World::new(),
            registry:     ImsiRegistry::new(),
            hss:          Hss::new(),
            phase3_upf:   None,
            teid_counter: 0x0001_0000,
        }
    }

    /// Phase 3 mode — SecModeComplete → InitialContextSetupRequest + UpfEvent::CreateSession.
    pub fn with_phase3(mut self, upf_addr: [u8; 4]) -> Self {
        self.phase3_upf = Some(upf_addr);
        self
    }

    pub fn hss_mut(&mut self) -> &mut Hss { &mut self.hss }

    pub fn alloc_ul_teid(&mut self) -> u32 {
        let t = self.teid_counter;
        self.teid_counter = self.teid_counter.wrapping_add(1);
        t
    }

    /// Main entry point — process one incoming S1AP message.
    pub async fn process_s1ap(
        &mut self,
        msg: S1apMessage,
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        use midn_proto::s1ap::S1apMessage::*;
        match msg {
            InitialUeMessage(m) => {
                attach::start_attach(
                    &mut self.world,
                    &mut self.registry,
                    &mut self.hss,
                    m.enb_ue_s1ap_id,
                    &m.nas_pdu,
                )
            }
            UplinkNasTransport(m) => {
                self.handle_uplink_nas(
                    m.enb_ue_s1ap_id,
                    m.mme_ue_s1ap_id,
                    &m.nas_pdu,
                )
            }
            InitialContextSetupResponse(m) => self.handle_icsrsp(m),
            UeContextReleaseComplete(m)    => self.handle_release_complete(m),
            _ => (vec![], vec![]),
        }
    }

    // ── Internal routing ──────────────────────────────────────────────────────

    fn handle_uplink_nas(
        &mut self,
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
        nas_pdu: &[u8],
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        use midn_proto::nas::{decode_nas, NasPdu};
        match decode_nas(nas_pdu) {
            Ok(NasPdu::AuthenticationResponse(..)) => {
                attach::handle_auth_response(
                    &mut self.world,
                    &self.registry,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                    nas_pdu,
                )
            }
            Ok(NasPdu::SecurityModeComplete) => {
                attach::handle_security_mode_complete(
                    &mut self.world,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                    self.phase3_upf,
                    &mut self.teid_counter,
                )
            }
            Ok(NasPdu::AttachComplete) => {
                attach::handle_attach_complete(&mut self.world, mme_ue_s1ap_id)
            }
            _ => {
                tracing::warn!(mme_ue_s1ap_id, "UplinkNasTransport: unknown NAS PDU");
                (vec![], vec![])
            }
        }
    }

    /// Handle `InitialContextSetupResponse` from eNodeB (Phase 3).
    fn handle_icsrsp(
        &mut self,
        resp: midn_proto::s1ap::InitialContextSetupResponse,
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        let entity = resp.mme_ue_s1ap_id;

        let erab = match resp.e_rabs_setup.first() {
            Some(e) => e,
            None => {
                tracing::warn!(entity, "ICSRSP: no e-RABs in response");
                return (vec![], vec![]);
            }
        };

        let dl_teid  = u32::from_be_bytes(erab.gtp_teid);
        let enb_addr = erab.transport_layer_addr;

        if let Some(t) = self.world.get_tunnel_mut(entity) {
            let ul_teid = t.ul_teid;
            t.dl_teid  = dl_teid;
            t.enb_addr = enb_addr;

            let evt = UpfEvent::UpdateBearer { ul_teid, dl_teid, enb_addr };
            return (vec![], vec![evt]);
        }

        tracing::warn!(entity, "ICSRSP: no tunnel component — Phase 2 mode?");
        (vec![], vec![])
    }

    /// Handle `UeContextReleaseComplete` — despawn entity and emit RemoveSession.
    fn handle_release_complete(
        &mut self,
        msg: midn_proto::s1ap::UeContextReleaseComplete,
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        let entity = msg.mme_ue_s1ap_id;

        let ul_teid = self.world
            .get_tunnel_mut(entity)
            .map(|t| t.ul_teid);

        if let Some(ctx) = self.world.get_attach_context(entity) {
            self.registry.deregister(ctx.imsi);
        }

        self.world.despawn(entity);
        tracing::info!(entity, "UeContextReleaseComplete — entity despawned");

        match ul_teid {
            Some(t) => (vec![], vec![UpfEvent::RemoveSession { ul_teid: t }]),
            None    => (vec![], vec![]),
        }
    }
}

impl Default for Mme {
    fn default() -> Self { Self::new() }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecs_spawn_returns_sequential_ids() {
        let mut w = World::new();
        assert_eq!(w.spawn(), 0);
        assert_eq!(w.spawn(), 1);
        assert_eq!(w.spawn(), 2);
    }

    #[test]
    fn ecs_spawn_reuses_despawned_ids() {
        let mut w = World::new();
        let a = w.spawn();
        let b = w.spawn();
        w.despawn(a);
        let c = w.spawn();
        assert_eq!(c, a);
        let _ = b;
    }

    #[test]
    fn ecs_spawn_with_all_components() {
        let mut w = World::new();
        let e = w.spawn();
        w.insert_attach_context(e, AttachContext {
            imsi: 1, enb_ue_s1ap_id: 0, mme_ue_s1ap_id: e,
            rand: [0;16], xres: [0;8], ck: [0;16], ik: [0;16],
            sqn_used: [0;6], ue_ip: [0;4], ul_teid: None,
        });
        w.insert_session_state(e, SessionState { imsi: 1, ul_teid: 0x0001_0000 });
        w.insert_tunnel(e, TunnelComponent { ul_teid: 0x0001_0000, dl_teid: 0, enb_addr: [0;4] });
        assert!(w.get_attach_context(e).is_some());
    }

    #[test]
    fn ecs_despawn_removes_all_components() {
        let mut w = World::new();
        let e = w.spawn();
        w.insert_attach_context(e, AttachContext {
            imsi: 1, enb_ue_s1ap_id: 0, mme_ue_s1ap_id: e,
            rand: [0;16], xres: [0;8], ck: [0;16], ik: [0;16],
            sqn_used: [0;6], ue_ip: [0;4], ul_teid: None,
        });
        w.despawn(e);
        assert!(w.get_attach_context(e).is_none());
    }

    #[test]
    fn imsi_registry_register_and_lookup() {
        let mut r = ImsiRegistry::new();
        r.register(901_700_000_000_001, 42);
        assert_eq!(r.lookup(901_700_000_000_001), Some(42));
        assert_eq!(r.lookup(999), None);
    }

    #[test]
    fn imsi_registry_deregister() {
        let mut r = ImsiRegistry::new();
        r.register(1, 0);
        r.deregister(1);
        assert_eq!(r.lookup(1), None);
    }

    #[test]
    fn mme_new_is_phase2() {
        let mme = Mme::new();
        assert!(mme.phase3_upf.is_none());
    }

    #[test]
    fn mme_with_phase3_sets_flag() {
        let mme = Mme::new().with_phase3([127, 0, 0, 1]);
        assert_eq!(mme.phase3_upf, Some([127, 0, 0, 1]));
    }

    #[test]
    fn alloc_ul_teid_starts_at_base() {
        let mut mme = Mme::new();
        assert_eq!(mme.alloc_ul_teid(), 0x0001_0000);
        assert_eq!(mme.alloc_ul_teid(), 0x0001_0001);
    }

    #[test]
    fn hss_provision_and_generate() {
        let mut mme = Mme::new();
        mme.hss.provision(
            901_700_000_000_001,
            [0x46,0x5b,0x5c,0xe8,0xb1,0x99,0xb4,0x9f,0xaa,0x5f,0x0a,0x2e,0xe2,0x38,0xa6,0xbc],
            [0xcd,0x63,0xcb,0x71,0x95,0x4a,0x9f,0x4e,0x48,0xa5,0x99,0x4e,0x37,0xa0,0x2b,0xaf],
        );
        let info = mme.hss.generate_auth_vector(901_700_000_000_001);
        assert!(info.is_some());
    }

    #[test]
    fn hss_unknown_imsi_returns_none() {
        let mut mme = Mme::new();
        assert!(mme.hss.generate_auth_vector(999).is_none());
    }
        }
