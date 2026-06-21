// crates/midn-core/src/mme/state_machine.rs
//! MME state machine — main `Mme` struct and `process_s1ap` entry point.
//!
//! ## Phase modes
//!
//! | Mode    | Trigger                  | SecModeComplete response          |
//! |---------|--------------------------|------------------------------------|
//! | Phase 2 | `Mme::new()`             | DownlinkNasTransport(AttachAccept) |
//! | Phase 3 | `.with_phase3(upf_addr)` | InitialContextSetupRequest         |
//!
//! ## TEID lifecycle
//!
//! `TeidAllocator` (below) hands out Phase 3 UL TEIDs with a free list, so a
//! detached subscriber's TEID becomes available for the next attach instead
//! of the counter growing unbounded. Allocated in
//! `attach::handle_security_mode_complete`, released in
//! `handle_release_complete` once `UeContextReleaseComplete` confirms the
//! eNodeB has actually torn down the radio context — whether that release was
//! triggered by the network or by `mme::detach::handle_detach_request`.
//!
//! ## NAS security
//!
//! `AttachContext::nas_security` holds the per-subscriber
//! `NasSecurityContext` once it's created (in
//! `attach::handle_security_mode_complete` — see that function and
//! `nas::security` module docs for the activation point). Kasme is derived
//! via `crate::kdf::derive_kasme` (TS 33.401 Annex A.2), using
//! `AttachContext::plmn` (captured from S1AP `tai` in `start_attach`) and
//! `AttachContext::ak` (the Milenage f5 output, combined with `sqn_used` as
//! SQN ⊕ AK). `handle_uplink_nas` auto-detects protected vs plain uplink NAS
//! PDUs from the security header type nibble (octet 1, high nibble) and
//! transparently unwraps protected ones before dispatching — callers/tests
//! that still send plain bytes for later messages (AttachComplete, Detach)
//! are unaffected.

use std::borrow::Cow;
use std::collections::HashMap;

use midn_proto::nas::NasSecurityContext;

use crate::s1ap::S1apMessage;
use crate::hss::Hss;
use crate::mme::attach;
use crate::mme::detach;

// ── EntityId ──────────────────────────────────────────────────────────────────

pub type EntityId = u32;

// ── Component types ───────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct AttachContext {
    pub imsi:           u64,
    pub enb_ue_s1ap_id: u32,
    pub mme_ue_s1ap_id: u32,
    pub rand:           [u8; 16],
    pub xres:           [u8; 8],
    pub ck:             [u8; 16],
    pub ik:             [u8; 16],
    /// Milenage f5 output (AK) for this auth attempt. Combined with
    /// `sqn_used` (SQN ⊕ AK) as a Kasme KDF input — see
    /// `crate::kdf::derive_kasme` and `mme::attach` module docs.
    pub ak:             [u8; 6],
    /// Serving network identity (PLMN-Id, 3 octets) — captured from the
    /// S1AP `tai` field on `InitialUeMessage` (TAI = PLMN(3) ‖ TAC(2)).
    /// Used as a Kasme KDF input (TS 33.401 Annex A.2).
    pub plmn:           [u8; 3],
    pub sqn_used:       [u8; 6],
    pub ue_ip:          [u8; 4],
    pub ul_teid:        Option<u32>,
    /// NAS security context for this subscriber — `None` until
    /// `attach::handle_security_mode_complete` creates it. See module docs.
    pub nas_security:   Option<NasSecurityContext>,
}

#[derive(Clone, Debug)]
pub struct SessionState {
    pub imsi:    u64,
    pub ul_teid: u32,
}

#[derive(Clone, Debug)]
pub struct TunnelComponent {
    pub ul_teid:  u32,
    pub dl_teid:  u32,
    pub enb_addr: [u8; 4],
}

// ── World ─────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct World {
    next_id:         u32,
    free_ids:        Vec<u32>,
    attach_contexts: HashMap<u32, AttachContext>,
    session_states:  HashMap<u32, SessionState>,
    pub tunnels:     HashMap<u32, TunnelComponent>,
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
    pub fn subscriber_count(&self) -> usize {
        self.attach_contexts.len()
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

// ── TEID allocator ────────────────────────────────────────────────────────────

/// Allocates uplink TEIDs for Phase 3 sessions, with a free list so detached
/// subscribers' TEIDs get reused instead of the counter growing forever.
///
/// Mirrors the same free-list pattern as `World`'s entity ID allocator and
/// `midn_userplane::upf::tunnel::TunnelManager` — pop a freed id first, only
/// fall back to the monotonic counter when the free list is empty.
#[derive(Debug)]
pub struct TeidAllocator {
    next: u32,
    free: Vec<u32>,
}

impl TeidAllocator {
    pub fn new(base: u32) -> Self {
        Self { next: base, free: Vec::with_capacity(64) }
    }

    /// Allocate a TEID — reuses a freed one if available, else advances the counter.
    pub fn alloc(&mut self) -> u32 {
        if let Some(id) = self.free.pop() {
            return id;
        }
        let t = self.next;
        self.next = self.next.wrapping_add(1);
        t
    }

    /// Return a TEID to the free list after its session has torn down.
    ///
    /// Call exactly once per TEID, after the subscriber's tunnel/session
    /// state has been removed — double-releasing the same TEID would let it
    /// be handed out twice concurrently.
    pub fn release(&mut self, teid: u32) {
        self.free.push(teid);
    }

    /// Number of TEIDs currently available for reuse.
    pub fn free_count(&self) -> usize { self.free.len() }
}

impl Default for TeidAllocator {
    fn default() -> Self { Self::new(0x0001_0000) }
}

// ── UpfEvent ──────────────────────────────────────────────────────────────────

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
    pub(crate) world: World,
    pub(crate) registry: ImsiRegistry,
    pub hss:          Hss,
    phase3_upf:       Option<[u8; 4]>,
    teid_allocator:   TeidAllocator,
}

impl Mme {
    pub fn new() -> Self {
        Self {
            world:          World::new(),
            registry:       ImsiRegistry::new(),
            hss:            Hss::new(),
            phase3_upf:     None,
            teid_allocator: TeidAllocator::new(0x0001_0000),
        }
    }

    pub fn with_phase3(mut self, upf_addr: [u8; 4]) -> Self {
        self.phase3_upf = Some(upf_addr);
        self
    }

    pub fn hss_mut(&mut self) -> &mut Hss { &mut self.hss }

    pub fn alloc_ul_teid(&mut self) -> u32 {
        self.teid_allocator.alloc()
    }

    /// Return a TEID to the free list — call after a subscriber's session has
    /// fully torn down (see `handle_release_complete`).
    pub fn release_ul_teid(&mut self, teid: u32) {
        self.teid_allocator.release(teid);
    }

    /// Number of TEIDs currently available for reuse — mainly for tests/metrics.
    pub fn free_teid_count(&self) -> usize {
        self.teid_allocator.free_count()
    }

    pub fn subscriber_count(&self) -> usize {
        self.world.subscriber_count()
    }

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
                    m.tai,
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

    fn handle_uplink_nas(
        &mut self,
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
        nas_pdu: &[u8],
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        use midn_proto::nas::{decode_nas, decode_protected, NasPdu, NAS_BEARER, SHT_PLAIN};

        // Detect a protected envelope vs a plain PDU from the security header
        // type in the high nibble of octet 1 (see nas::codec module docs).
        // Plain messages (AuthenticationResponse, SecurityModeComplete — sent
        // before NAS security activates) and a mock UE that still sends later
        // messages plain both take the fast path straight into decode_nas,
        // exactly as before NAS security was wired in.
        let sht = nas_pdu.first().map(|b| (*b >> 4) & 0x0F).unwrap_or(0);

        let plain_pdu: Cow<[u8]> = if sht == SHT_PLAIN {
            Cow::Borrowed(nas_pdu)
        } else {
            let nas_ctx = match self.world
                .get_attach_context_mut(mme_ue_s1ap_id)
                .and_then(|ctx| ctx.nas_security.as_mut())
            {
                Some(c) => c,
                None => {
                    tracing::warn!(
                        mme_ue_s1ap_id,
                        "UplinkNasTransport: protected PDU received but no NAS security context exists"
                    );
                    return (vec![], vec![]);
                }
            };
            match decode_protected(nas_ctx, nas_pdu, NAS_BEARER) {
                Some(inner) => Cow::Owned(inner),
                None => {
                    tracing::warn!(mme_ue_s1ap_id, "UplinkNasTransport: NAS integrity check failed — dropping");
                    return (vec![], vec![]);
                }
            }
        };

        match decode_nas(&plain_pdu) {
            Ok(NasPdu::AuthenticationResponse(..)) => {
                attach::handle_auth_response(
                    &mut self.world,
                    &self.registry,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                    &plain_pdu,
                )
            }
            Ok(NasPdu::SecurityModeComplete) => {
                attach::handle_security_mode_complete(
                    &mut self.world,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                    self.phase3_upf,
                    &mut self.teid_allocator,
                )
            }
            Ok(NasPdu::AttachComplete) => {
                attach::handle_attach_complete(&mut self.world, mme_ue_s1ap_id)
            }
            Ok(NasPdu::DetachRequest(..)) => {
                let responses = detach::handle_detach_request(
                    &mut self.world, enb_ue_s1ap_id, mme_ue_s1ap_id, &plain_pdu,
                );
                (responses, vec![])
            }
            _ => {
                tracing::warn!(mme_ue_s1ap_id, "UplinkNasTransport: unknown NAS PDU");
                (vec![], vec![])
            }
        }
    }

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
            return (vec![], vec![UpfEvent::UpdateBearer { ul_teid, dl_teid, enb_addr }]);
        }

        tracing::warn!(entity, "ICSRSP: no tunnel component — Phase 2 mode?");
        (vec![], vec![])
    }

    fn handle_release_complete(
        &mut self,
        msg: midn_proto::s1ap::UeContextReleaseComplete,
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        let entity = msg.mme_ue_s1ap_id;

        let ul_teid = self.world.get_tunnel_mut(entity).map(|t| t.ul_teid);

        if let Some(ctx) = self.world.get_attach_context(entity) {
            self.registry.deregister(ctx.imsi);
        }

        self.world.despawn(entity);
        tracing::info!(entity, "UeContextReleaseComplete — entity despawned");

        match ul_teid {
            Some(t) => {
                self.teid_allocator.release(t);
                (vec![], vec![UpfEvent::RemoveSession { ul_teid: t }])
            }
            None => (vec![], vec![]),
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
    use midn_auth::{AuthKey, OpCode};
    use midn_auth::keys::{Amf, Rand, Sqn};

    // ── Unit tests ────────────────────────────────────────────────────────────

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
            ak: [0;6], plmn: [0;3],
            sqn_used: [0;6], ue_ip: [0;4], ul_teid: None,
            nas_security: None,
        });
        w.insert_session_state(e, SessionState { imsi: 1, ul_teid: 0x0001_0000 });
        w.insert_tunnel(e, TunnelComponent { ul_teid: 0x0001_0000, dl_teid: 0, enb_addr: [0;4] });
        assert!(w.get_attach_context(e).is_some());
        assert_eq!(w.subscriber_count(), 1);
    }

    #[test]
    fn ecs_despawn_removes_all_components() {
        let mut w = World::new();
        let e = w.spawn();
        w.insert_attach_context(e, AttachContext {
            imsi: 1, enb_ue_s1ap_id: 0, mme_ue_s1ap_id: e,
            rand: [0;16], xres: [0;8], ck: [0;16], ik: [0;16],
            ak: [0;6], plmn: [0;3],
            sqn_used: [0;6], ue_ip: [0;4], ul_teid: None,
            nas_security: None,
        });
        w.despawn(e);
        assert!(w.get_attach_context(e).is_none());
        assert_eq!(w.subscriber_count(), 0);
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
    fn teid_allocator_recycles_freed_ids() {
        let mut alloc = TeidAllocator::new(100);
        let a = alloc.alloc();
        let b = alloc.alloc();
        assert_eq!(a, 100);
        assert_eq!(b, 101);
        alloc.release(a);
        assert_eq!(alloc.free_count(), 1);
        let c = alloc.alloc();
        assert_eq!(c, a, "freed id should be handed out before advancing the counter");
        assert_eq!(alloc.free_count(), 0);
    }

    #[test]
    fn mme_release_ul_teid_recycles_via_allocator() {
        let mut mme = Mme::new();
        let t1 = mme.alloc_ul_teid();
        mme.release_ul_teid(t1);
        assert_eq!(mme.free_teid_count(), 1);
        let t2 = mme.alloc_ul_teid();
        assert_eq!(t2, t1);
    }

    #[test]
    fn hss_provision_and_generate() {
        let mut mme = Mme::new();
        mme.hss.provision(
            901_700_000_000_001,
            AuthKey([0x46,0x5b,0x5c,0xe8,0xb1,0x99,0xb4,0x9f,
                     0xaa,0x5f,0x0a,0x2e,0xe2,0x38,0xa6,0xbc]),
            OpCode([0xcd,0x63,0xcb,0x71,0x95,0x4a,0x9f,0x4e,
                    0x48,0xa5,0x99,0x4e,0x37,0xa0,0x2b,0xaf]),
        );
        assert!(mme.hss.generate_auth_vector(901_700_000_000_001).is_some());
    }

    #[test]
    fn hss_unknown_imsi_returns_none() {
        let mut mme = Mme::new();
        assert!(mme.hss.generate_auth_vector(999).is_none());
    }

    // ── Phase 3 integration test ──────────────────────────────────────────────

    #[tokio::test]
    async fn phase3_full_attach_procedure() {
        use midn_auth::MilenageContext;
        use midn_proto::nas::{
            decode_nas, encode_attach_request, encode_auth_response,
            encode_sec_mode_complete, encode_attach_complete, NasPdu,
        };
        use midn_proto::s1ap::{
            ErabSetupItem, InitialContextSetupResponse,
            InitialUeMessage, S1apMessage, UplinkNasTransport,
        };

        let k_buf: [u8; 16] = [
            0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f,
            0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
        ];
        let opc_buf: [u8; 16] = [
            0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e,
            0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf,
        ];
        let imsi     = 234_15_1234567890_u64;
        let upf_addr = [127u8, 0, 0, 1];
        let enb_id   = 0x0001_0001_u32;

        let mut mme = Mme::new().with_phase3(upf_addr);
        mme.hss.provision(imsi, AuthKey(k_buf), OpCode(opc_buf));

        // ── Step 1: AttachRequest → AuthenticationRequest ─────────────────────

        let (responses, events) = mme.process_s1ap(
            S1apMessage::InitialUeMessage(InitialUeMessage {
                enb_ue_s1ap_id: enb_id,
                nas_pdu:        encode_attach_request(imsi, 1, 0),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
                rrc_cause:      1,
            })
        ).await;

        assert_eq!(responses.len(), 1, "step 1: expect DownlinkNasTransport(AuthReq)");
        assert!(events.is_empty(),   "step 1: no UPF events yet");
        assert_eq!(mme.subscriber_count(), 1, "step 1: one entity spawned");

        let (mme_ue_id, auth_req_pdu) = match &responses[0] {
            S1apMessage::DownlinkNasTransport(m) => (m.mme_ue_s1ap_id, m.nas_pdu.clone()),
            _ => panic!("step 1: expected DownlinkNasTransport"),
        };

        // Decode AuthReq and extract RAND.
        let rand_bytes = match decode_nas(&auth_req_pdu).unwrap() {
            NasPdu::AuthenticationRequest(d) => d.rand,
            other => panic!("step 1: expected AuthReq NAS PDU, got {:?}", other),
        };

        // Compute correct RES: same K, OPc, RAND, SQN=0 (first call), AMF=[0x80,0x00].
        let ctx = MilenageContext::new(AuthKey(k_buf), OpCode(opc_buf));
        let av  = ctx.generate_vector_with_rand(
            Sqn::from_bytes(&[0u8; 6]),
            Amf([0x80, 0x00]),
            Rand(rand_bytes),
        );

        // ── Step 2: AuthenticationResponse(RES) → SecurityModeCommand ─────────

        let (responses, events) = mme.process_s1ap(
            S1apMessage::UplinkNasTransport(UplinkNasTransport {
                enb_ue_s1ap_id: enb_id,
                mme_ue_s1ap_id: mme_ue_id,
                nas_pdu:        encode_auth_response(&av.res),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            })
        ).await;

        assert_eq!(responses.len(), 1, "step 2: expect SecurityModeCommand");
        assert!(events.is_empty(),   "step 2: no UPF events");
        assert!(
            matches!(&responses[0], S1apMessage::DownlinkNasTransport(_)),
            "step 2: expected DownlinkNasTransport(SecModeCmd)"
        );

        // ── Step 3: SecurityModeComplete → InitialContextSetupRequest ─────────

        let (responses, events) = mme.process_s1ap(
            S1apMessage::UplinkNasTransport(UplinkNasTransport {
                enb_ue_s1ap_id: enb_id,
                mme_ue_s1ap_id: mme_ue_id,
                nas_pdu:        encode_sec_mode_complete(),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            })
        ).await;

        assert_eq!(responses.len(), 1, "step 3: expect InitialContextSetupRequest");
        assert_eq!(events.len(),    1, "step 3: expect CreateSession event");

        let ul_teid = match &responses[0] {
            S1apMessage::InitialContextSetupRequest(icsr) => {
                assert_eq!(icsr.mme_ue_s1ap_id, mme_ue_id);
                assert_eq!(icsr.enb_ue_s1ap_id, enb_id);
                assert!(!icsr.e_rabs.is_empty());
                assert_eq!(icsr.e_rabs[0].transport_layer_addr, upf_addr,
                    "E-RAB transport addr must point at UPF");
                assert!(icsr.nas_pdu.is_some(), "AttachAccept must be embedded (now protected)");
                u32::from_be_bytes(icsr.e_rabs[0].gtp_teid)
            }
            _ => panic!("step 3: expected InitialContextSetupRequest"),
        };

        assert_eq!(ul_teid, 0x0001_0000, "step 3: first UL TEID = base");

        match &events[0] {
            UpfEvent::CreateSession { ul_teid: t, entity_id, imsi: i, qci, .. } => {
                assert_eq!(*t,         ul_teid,  "CreateSession UL TEID");
                assert_eq!(*entity_id, mme_ue_id,"CreateSession entity_id");
                assert_eq!(*i,         imsi,     "CreateSession IMSI");
                assert_eq!(*qci,       9,        "CreateSession QCI");
            }
            _ => panic!("step 3: expected CreateSession event"),
        }

        // ── Step 4: InitialContextSetupResponse → UpfEvent::UpdateBearer ──────

        let enb_dl_teid  = 0xBEEF_0001_u32;
        let enb_s1u_addr = [192u8, 168, 1, 100];

        let (responses, events) = mme.process_s1ap(
            S1apMessage::InitialContextSetupResponse(InitialContextSetupResponse {
                mme_ue_s1ap_id: mme_ue_id,
                enb_ue_s1ap_id: enb_id,
                e_rabs_setup: vec![ErabSetupItem {
                    e_rab_id:             5,
                    transport_layer_addr: enb_s1u_addr,
                    gtp_teid:             enb_dl_teid.to_be_bytes(),
                }],
                e_rabs_failed: vec![],
            })
        ).await;

        assert!(responses.is_empty(), "step 4: ICSRSP generates no S1AP responses");
        assert_eq!(events.len(), 1,   "step 4: expect UpdateBearer event");

        match &events[0] {
            UpfEvent::UpdateBearer { ul_teid: t, dl_teid, enb_addr } => {
                assert_eq!(*t,        ul_teid,       "UpdateBearer UL TEID");
                assert_eq!(*dl_teid,  enb_dl_teid,   "UpdateBearer DL TEID from eNB");
                assert_eq!(*enb_addr, enb_s1u_addr,  "UpdateBearer eNB S1-U addr");
            }
            _ => panic!("step 4: expected UpdateBearer event"),
        }

        let tunnel = mme.world.tunnels.get(&mme_ue_id).expect("tunnel must exist");
        assert_eq!(tunnel.dl_teid,  enb_dl_teid);
        assert_eq!(tunnel.enb_addr, enb_s1u_addr);
        assert_eq!(tunnel.ul_teid,  ul_teid);

        // ── Step 5: AttachComplete → subscriber online ────────────────────────
        //
        // Sent PLAIN here (mock UE doesn't bother protecting it) — the
        // dispatcher auto-detects sht=0 and takes the unchanged plain path.
        // See phase3_attach_complete_via_protected_nas_envelope below for the
        // protected-envelope version of this same step.

        let (responses, events) = mme.process_s1ap(
            S1apMessage::UplinkNasTransport(UplinkNasTransport {
                enb_ue_s1ap_id: enb_id,
                mme_ue_s1ap_id: mme_ue_id,
                nas_pdu:        encode_attach_complete(),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            })
        ).await;

        assert!(responses.is_empty(), "step 5: AttachComplete is silent");
        assert!(events.is_empty(),    "step 5: no UPF events on AttachComplete");
        assert_eq!(mme.subscriber_count(), 1, "step 5: one online subscriber");
        assert_eq!(mme.registry.lookup(imsi), Some(mme_ue_id),
            "step 5: IMSI registry correct");
    }

    // ── Phase 3 negative: wrong RES is rejected ───────────────────────────────

    #[tokio::test]
    async fn phase3_wrong_res_rejected() {
        use midn_proto::nas::{encode_attach_request, encode_auth_response};
        use midn_proto::s1ap::{InitialUeMessage, S1apMessage, UplinkNasTransport};

        let k_buf: [u8; 16] = [
            0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f,
            0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
        ];
        let opc_buf: [u8; 16] = [
            0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e,
            0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf,
        ];
        let imsi = 234_15_0000000001_u64;

        let mut mme = Mme::new().with_phase3([127, 0, 0, 1]);
        mme.hss.provision(imsi, AuthKey(k_buf), OpCode(opc_buf));

        let (responses, _) = mme.process_s1ap(
            S1apMessage::InitialUeMessage(InitialUeMessage {
                enb_ue_s1ap_id: 1,
                nas_pdu: encode_attach_request(imsi, 1, 0),
                tai: [0; 5], eutran_cgi: [0; 7], rrc_cause: 1,
            })
        ).await;

        let mme_ue_id = match &responses[0] {
            S1apMessage::DownlinkNasTransport(m) => m.mme_ue_s1ap_id,
            _ => panic!(),
        };

        // Send deliberately wrong RES — all 0xAA
        let wrong_res = [0xAAu8; 8];
        let (responses, events) = mme.process_s1ap(
            S1apMessage::UplinkNasTransport(UplinkNasTransport {
                enb_ue_s1ap_id: 1,
                mme_ue_s1ap_id: mme_ue_id,
                nas_pdu: encode_auth_response(&wrong_res),
                tai: [0; 5], eutran_cgi: [0; 7],
            })
        ).await;

        assert!(responses.is_empty(), "wrong RES must produce no S1AP response");
        assert!(events.is_empty(),    "wrong RES must produce no UPF events");
    }

    // ── Phase 3 detach: full close-the-loop test ──────────────────────────────

    #[tokio::test]
    async fn phase3_detach_releases_teid_for_reuse() {
        use midn_auth::MilenageContext;
        use midn_proto::nas::{
            decode_nas, encode_attach_request, encode_auth_response,
            encode_sec_mode_complete, encode_detach_request, NasPdu,
        };
        use midn_proto::s1ap::{
            InitialUeMessage, S1apMessage, UeContextReleaseComplete, UplinkNasTransport,
        };

        let k_buf: [u8; 16] = [
            0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f,
            0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
        ];
        let opc_buf: [u8; 16] = [
            0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e,
            0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf,
        ];
        let imsi     = 234_15_5550001_u64;
        let upf_addr = [127u8, 0, 0, 1];
        let enb_id   = 0x0002_0001_u32;

        let mut mme = Mme::new().with_phase3(upf_addr);
        mme.hss.provision(imsi, AuthKey(k_buf), OpCode(opc_buf));
        let ctx = MilenageContext::new(AuthKey(k_buf), OpCode(opc_buf));

        // ── Drive through attach far enough to allocate a UL TEID ────────────

        let (responses, _) = mme.process_s1ap(S1apMessage::InitialUeMessage(InitialUeMessage {
            enb_ue_s1ap_id: enb_id,
            nas_pdu:        encode_attach_request(imsi, 1, 0),
            tai: [0; 5], eutran_cgi: [0; 7], rrc_cause: 1,
        })).await;
        let (mme_ue_id, auth_req_pdu) = match &responses[0] {
            S1apMessage::DownlinkNasTransport(m) => (m.mme_ue_s1ap_id, m.nas_pdu.clone()),
            _ => panic!("expected DownlinkNasTransport"),
        };
        let rand_bytes = match decode_nas(&auth_req_pdu).unwrap() {
            NasPdu::AuthenticationRequest(d) => d.rand,
            _ => panic!("expected AuthReq"),
        };
        let av = ctx.generate_vector_with_rand(
            Sqn::from_bytes(&[0u8; 6]), Amf([0x80, 0x00]), Rand(rand_bytes),
        );
        mme.process_s1ap(S1apMessage::UplinkNasTransport(UplinkNasTransport {
            enb_ue_s1ap_id: enb_id, mme_ue_s1ap_id: mme_ue_id,
            nas_pdu: encode_auth_response(&av.res),
            tai: [0; 5], eutran_cgi: [0; 7],
        })).await;
        let (_, events) = mme.process_s1ap(S1apMessage::UplinkNasTransport(UplinkNasTransport {
            enb_ue_s1ap_id: enb_id, mme_ue_s1ap_id: mme_ue_id,
            nas_pdu: encode_sec_mode_complete(),
            tai: [0; 5], eutran_cgi: [0; 7],
        })).await;
        let ul_teid = match &events[0] {
            UpfEvent::CreateSession { ul_teid, .. } => *ul_teid,
            _ => panic!("expected CreateSession"),
        };
        assert_eq!(mme.free_teid_count(), 0, "freshly allocated TEID is not free");

        // ── UE sends DetachRequest (plain — exercises the sht=0 fast path) ────

        let (responses, events) = mme.process_s1ap(S1apMessage::UplinkNasTransport(UplinkNasTransport {
            enb_ue_s1ap_id: enb_id, mme_ue_s1ap_id: mme_ue_id,
            nas_pdu: encode_detach_request(1, false, 0, &[0; 10]),
            tai: [0; 5], eutran_cgi: [0; 7],
        })).await;
        assert_eq!(responses.len(), 2, "expect DetachAccept (now protected) + UeContextReleaseCommand");
        assert!(events.is_empty(), "no UpfEvent until UeContextReleaseComplete");
        assert!(matches!(responses[1], S1apMessage::UeContextReleaseCommand { .. }));

        // ── eNodeB confirms release ───────────────────────────────────────────

        let (responses, events) = mme.process_s1ap(
            S1apMessage::UeContextReleaseComplete(UeContextReleaseComplete {
                mme_ue_s1ap_id: mme_ue_id,
                enb_ue_s1ap_id: enb_id,
            })
        ).await;
        assert!(responses.is_empty());
        match &events[0] {
            UpfEvent::RemoveSession { ul_teid: t } => assert_eq!(*t, ul_teid),
            _ => panic!("expected RemoveSession"),
        }
        assert_eq!(mme.subscriber_count(), 0);
        assert_eq!(mme.free_teid_count(), 1, "TEID returned to the free list");

        // ── Next subscriber's attach reuses the freed TEID ────────────────────

        let imsi2 = 234_15_5550002_u64;
        mme.hss.provision(imsi2, AuthKey(k_buf), OpCode(opc_buf));
        let (responses, _) = mme.process_s1ap(S1apMessage::InitialUeMessage(InitialUeMessage {
            enb_ue_s1ap_id: enb_id + 1,
            nas_pdu: encode_attach_request(imsi2, 1, 0),
            tai: [0; 5], eutran_cgi: [0; 7], rrc_cause: 1,
        })).await;
        let (mme_ue_id2, auth_req_pdu2) = match &responses[0] {
            S1apMessage::DownlinkNasTransport(m) => (m.mme_ue_s1ap_id, m.nas_pdu.clone()),
            _ => panic!("expected DownlinkNasTransport"),
        };
        let rand_bytes2 = match decode_nas(&auth_req_pdu2).unwrap() {
            NasPdu::AuthenticationRequest(d) => d.rand,
            _ => panic!("expected AuthReq"),
        };
        let av2 = ctx.generate_vector_with_rand(
            Sqn::from_bytes(&[0u8; 6]), Amf([0x80, 0x00]), Rand(rand_bytes2),
        );
        mme.process_s1ap(S1apMessage::UplinkNasTransport(UplinkNasTransport {
            enb_ue_s1ap_id: enb_id + 1, mme_ue_s1ap_id: mme_ue_id2,
            nas_pdu: encode_auth_response(&av2.res),
            tai: [0; 5], eutran_cgi: [0; 7],
        })).await;
        let (_, events2) = mme.process_s1ap(S1apMessage::UplinkNasTransport(UplinkNasTransport {
            enb_ue_s1ap_id: enb_id + 1, mme_ue_s1ap_id: mme_ue_id2,
            nas_pdu: encode_sec_mode_complete(),
            tai: [0; 5], eutran_cgi: [0; 7],
        })).await;
        let ul_teid2 = match &events2[0] {
            UpfEvent::CreateSession { ul_teid, .. } => *ul_teid,
            _ => panic!("expected CreateSession"),
        };
        assert_eq!(ul_teid2, ul_teid, "second subscriber recycles first subscriber's freed TEID");
        assert_eq!(mme.free_teid_count(), 0);
    }

    // ── NAS security: protected AttachComplete, wired end-to-end ─────────────

    #[tokio::test]
    async fn phase3_attach_complete_via_protected_nas_envelope() {
        use midn_auth::MilenageContext;
        use midn_proto::nas::{
            decode_nas, derive_nas_keys, eea2_apply, eia2_compute_mac,
            encode_attach_complete, encode_attach_request, encode_auth_response,
            encode_sec_mode_complete, Direction, NasEeaAlgorithm, NasEiaAlgorithm,
            NasPdu, NAS_BEARER, NAS_EPS_MM_PD, SHT_INTEGRITY_CIPHERED,
        };
        use midn_proto::s1ap::{InitialUeMessage, S1apMessage, UplinkNasTransport};

        let k_buf: [u8; 16] = [
            0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f,
            0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
        ];
        let opc_buf: [u8; 16] = [
            0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e,
            0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf,
        ];
        let imsi     = 234_15_0007770001_u64;
        let upf_addr = [127u8, 0, 0, 1];
        let enb_id   = 0x0003_0001_u32;

        let mut mme = Mme::new().with_phase3(upf_addr);
        mme.hss.provision(imsi, AuthKey(k_buf), OpCode(opc_buf));
        let milenage = MilenageContext::new(AuthKey(k_buf), OpCode(opc_buf));

        // ── Drive through attach far enough to activate NAS security ──────────
        // (steps 1-3, same shape as phase3_full_attach_procedure)

        let (responses, _) = mme.process_s1ap(S1apMessage::InitialUeMessage(InitialUeMessage {
            enb_ue_s1ap_id: enb_id,
            nas_pdu:        encode_attach_request(imsi, 1, 0),
            tai: [0; 5], eutran_cgi: [0; 7], rrc_cause: 1,
        })).await;
        let (mme_ue_id, auth_req_pdu) = match &responses[0] {
            S1apMessage::DownlinkNasTransport(m) => (m.mme_ue_s1ap_id, m.nas_pdu.clone()),
            _ => panic!("expected DownlinkNasTransport"),
        };
        let rand_bytes = match decode_nas(&auth_req_pdu).unwrap() {
            NasPdu::AuthenticationRequest(d) => d.rand,
            _ => panic!("expected AuthReq"),
        };
        let av = milenage.generate_vector_with_rand(
            Sqn::from_bytes(&[0u8; 6]), Amf([0x80, 0x00]), Rand(rand_bytes),
        );
        mme.process_s1ap(S1apMessage::UplinkNasTransport(UplinkNasTransport {
            enb_ue_s1ap_id: enb_id, mme_ue_s1ap_id: mme_ue_id,
            nas_pdu: encode_auth_response(&av.res),
            tai: [0; 5], eutran_cgi: [0; 7],
        })).await;
        mme.process_s1ap(S1apMessage::UplinkNasTransport(UplinkNasTransport {
            enb_ue_s1ap_id: enb_id, mme_ue_s1ap_id: mme_ue_id,
            nas_pdu: encode_sec_mode_complete(),
            tai: [0; 5], eutran_cgi: [0; 7],
        })).await;

        // ── Build a protected AttachComplete, exactly as a real UE would ──────
        //
        // The MME never exposes its NasSecurityContext to test code — this
        // independently re-derives the SAME Kasme and NAS keys the MME just
        // derived internally. SQN=0 for this subscriber's first auth attempt,
        // so SQN ⊕ AK == AK. PLMN matches the all-zero `tai` this test's
        // InitialUeMessage sent, which `start_attach` reads into
        // AttachContext::plmn — both sides land on the same Kasme input.
        let mut sqn_xor_ak = [0u8; 6];
        sqn_xor_ak.copy_from_slice(&av.ak);
        let kasme = crate::kdf::derive_kasme(&av.ck, &av.ik, &[0, 0, 0], &sqn_xor_ak);
        let (k_enc, k_int) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);

        let attach_complete_plain = encode_attach_complete();
        let count = 0u32; // first protected message this UE sends
        let mut ciphertext = attach_complete_plain.to_vec();
        eea2_apply(&k_enc, count, NAS_BEARER, Direction::Uplink, &mut ciphertext);
        let mac_i = eia2_compute_mac(&k_int, count, NAS_BEARER, Direction::Uplink, &ciphertext);

        let mut envelope = vec![(SHT_INTEGRITY_CIPHERED << 4) | NAS_EPS_MM_PD];
        envelope.extend_from_slice(&mac_i);
        envelope.push(count as u8);
        envelope.extend_from_slice(&ciphertext);

        let (responses, events) = mme.process_s1ap(S1apMessage::UplinkNasTransport(UplinkNasTransport {
            enb_ue_s1ap_id: enb_id, mme_ue_s1ap_id: mme_ue_id,
            nas_pdu: envelope.into(),
            tai: [0; 5], eutran_cgi: [0; 7],
        })).await;

        assert!(responses.is_empty(), "AttachComplete is silent, protected or not");
        assert!(events.is_empty());
        assert_eq!(mme.subscriber_count(), 1, "subscriber should still be online after protected AttachComplete");
    }
            }
