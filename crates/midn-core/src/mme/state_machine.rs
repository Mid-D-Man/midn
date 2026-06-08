// crates/midn-core/src/mme/state_machine.rs
//! MME top-level state machine.

use std::collections::HashMap;
use bytes::Bytes;

use midn_proto::s1ap::messages::{
    DownlinkNasTransport, ErabToSetup, InitialContextSetupRequest,
    InitialContextSetupResponse as S1apIcsrsp,
    S1apMessage, UplinkNasTransport,
};
use midn_proto::nas::codec::{
    MT_ATTACH_REQUEST, MT_AUTHENTICATION_RESPONSE,
    MT_SECURITY_MODE_COMPLETE, MT_ATTACH_COMPLETE,
};

use crate::ecs::components::ImsiComponent;
use crate::ecs::registry::ImsiRegistry;
use crate::ecs::world::CoreWorld;
use crate::hss::Hss;
use crate::mme::attach::{
    handle_attach_request, handle_auth_response, handle_security_mode_complete,
    handle_initial_context_setup_response, handle_attach_complete,
    AttachContext, IpPool,
};

/// Events emitted by `Mme::process_s1ap` that require user-plane action.
///
/// The caller processes these by calling into `SessionManager`
/// (midn-userplane). This keeps midn-core free of midn-userplane imports.
#[derive(Debug, Clone)]
pub enum UpfEvent {
    /// Create a data-plane session. Use `ul_teid` as the routing key — the UPF
    /// MUST install a route entry for exactly this TEID.
    CreateSession {
        ul_teid:   u32,
        entity_id: u32,
        imsi:      u64,
        ue_ip:     [u8; 4],
        enb_addr:  [u8; 4],
        qci:       u8,
    },
    /// Update DL TEID and eNodeB address after InitialContextSetupResponse.
    UpdateBearer {
        ul_teid:  u32,
        dl_teid:  u32,
        enb_addr: [u8; 4],
    },
    /// Remove session on detach or UE context release.
    RemoveSession {
        ul_teid: u32,
    },
}

// ── Mme ───────────────────────────────────────────────────────────────────────

pub struct Mme {
    pub world:    CoreWorld,
    pub registry: ImsiRegistry,
    pub hss:      Hss,
    pub ip_pool:  IpPool,

    attach_ctxs:    HashMap<u32, AttachContext>,
    enb_to_mme_id:  HashMap<u32, u32>,
    next_mme_ue_id: u32,

    /// When true, send `InitialContextSetupRequest` after Security Mode Complete
    /// (Phase 3 flow). When false (default), send AttachAccept directly via
    /// DownlinkNasTransport (Phase 2 compatible).
    pub phase3_upf:  bool,
    /// UPF IPv4 transport address — embedded in ICSR `ErabToSetup.transport_addr`.
    pub upf_addr:    [u8; 4],
    /// Next uplink TEID to assign to a new session.
    next_ul_teid:    u32,
}

impl Mme {
    pub fn new() -> Self {
        Self {
            world:          CoreWorld::new(),
            registry:       ImsiRegistry::new(),
            hss:            Hss::new(),
            ip_pool:        IpPool::default(),
            attach_ctxs:    HashMap::new(),
            enb_to_mme_id:  HashMap::new(),
            next_mme_ue_id: 1,
            phase3_upf:     false,
            upf_addr:       [127, 0, 0, 1],
            next_ul_teid:   0x0001_0000,
        }
    }

    /// Enable Phase 3 ICSR flow. `upf_addr` is the UPF's GTP-U listen address
    /// — included in the ICSR so eNodeBs know where to send UL packets.
    pub fn with_phase3(mut self, upf_addr: [u8; 4]) -> Self {
        self.phase3_upf = true;
        self.upf_addr   = upf_addr;
        self
    }

    // ── Public entry point ────────────────────────────────────────────────────

    /// Process an incoming S1AP message. Returns S1AP responses to send to the
    /// eNodeB and user-plane events for the caller to forward to `SessionManager`.
    pub async fn process_s1ap(
        &mut self,
        msg: S1apMessage,
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        match msg {
            S1apMessage::InitialUeMessage(ium) => {
                self.handle_initial_ue_message(ium.enb_ue_s1ap_id, ium.nas_pdu).await
            }
            S1apMessage::UplinkNasTransport(unt) => {
                self.handle_uplink_nas(
                    unt.enb_ue_s1ap_id, unt.mme_ue_s1ap_id, unt.nas_pdu,
                ).await
            }
            S1apMessage::InitialContextSetupResponse(icsrsp) => {
                self.handle_icsrsp(icsrsp).await
            }
            S1apMessage::UeContextReleaseComplete { mme_ue_s1ap_id, .. } => {
                let events = self.handle_ue_release(mme_ue_s1ap_id);
                (vec![], events)
            }
            _ => {
                tracing::warn!("Unhandled S1AP message");
                (vec![], vec![])
            }
        }
    }

    // ── Initial UE Message ────────────────────────────────────────────────────

    async fn handle_initial_ue_message(
        &mut self,
        enb_ue_s1ap_id: u32,
        nas_pdu:        Bytes,
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        let msg_type = nas_pdu.get(1).copied().unwrap_or(0);
        if msg_type != MT_ATTACH_REQUEST {
            tracing::warn!(msg_type, "InitialUeMessage: non-AttachRequest NAS PDU");
            return (vec![], vec![]);
        }

        let mme_ue_s1ap_id = self.alloc_mme_ue_id();
        self.enb_to_mme_id.insert(enb_ue_s1ap_id, mme_ue_s1ap_id);

        match handle_attach_request(
            &nas_pdu,
            enb_ue_s1ap_id,
            mme_ue_s1ap_id,
            &mut self.world,
            &mut self.registry,
            &mut self.hss,
        ) {
            Ok((ctx, step)) => {
                self.attach_ctxs.insert(mme_ue_s1ap_id, ctx);
                (vec![S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
                    mme_ue_s1ap_id,
                    enb_ue_s1ap_id,
                    nas_pdu: step.nas_pdu,
                })], vec![])
            }
            Err(reason) => {
                tracing::warn!(?reason, "Attach request failed");
                (vec![], vec![])
            }
        }
    }

    // ── Uplink NAS dispatch ───────────────────────────────────────────────────

    async fn handle_uplink_nas(
        &mut self,
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
        nas_pdu:        Bytes,
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        let msg_type = nas_pdu.get(1).copied().unwrap_or(0);
        match msg_type {
            MT_AUTHENTICATION_RESPONSE => {
                self.handle_auth_response_msg(enb_ue_s1ap_id, mme_ue_s1ap_id, nas_pdu).await
            }
            MT_SECURITY_MODE_COMPLETE => {
                self.handle_sec_mode_complete_msg(enb_ue_s1ap_id, mme_ue_s1ap_id, nas_pdu).await
            }
            MT_ATTACH_COMPLETE => {
                self.handle_attach_complete_msg(mme_ue_s1ap_id, nas_pdu).await;
                (vec![], vec![])
            }
            _ => {
                tracing::warn!(msg_type, mme_ue_s1ap_id, "Unhandled uplink NAS type");
                (vec![], vec![])
            }
        }
    }

    async fn handle_auth_response_msg(
        &mut self,
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
        nas_pdu:        Bytes,
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        let ctx = match self.attach_ctxs.get_mut(&mme_ue_s1ap_id) {
            Some(c) => c,
            None => {
                tracing::warn!(mme_ue_s1ap_id, "No attach context for auth response");
                return (vec![], vec![]);
            }
        };
        match handle_auth_response(ctx, &nas_pdu, &mut self.world) {
            Ok(step) => (vec![S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id,
                nas_pdu: step.nas_pdu,
            })], vec![]),
            Err(reason) => {
                tracing::warn!(?reason, mme_ue_s1ap_id, "Auth response handling failed");
                (vec![], vec![])
            }
        }
    }

    async fn handle_sec_mode_complete_msg(
        &mut self,
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
        nas_pdu:        Bytes,
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        let ul_teid = self.alloc_ul_teid();

        let ctx = match self.attach_ctxs.get_mut(&mme_ue_s1ap_id) {
            Some(c) => c,
            None => {
                tracing::warn!(mme_ue_s1ap_id, "No attach context for sec mode complete");
                return (vec![], vec![]);
            }
        };

        match handle_security_mode_complete(ctx, &nas_pdu, &mut self.world, &mut self.ip_pool, ul_teid) {
            Ok(step) => {
                // Extract session info for the UpfEvent — borrow ends before we use ctx.
                let ue_ip = self.world.session.get(&ctx.entity_id)
                    .map(|s| s.ip_address)
                    .unwrap_or([0; 4]);
                let entity_id = ctx.entity_id.0;
                let imsi      = ctx.imsi;

                let upf_event = UpfEvent::CreateSession {
                    ul_teid,
                    entity_id,
                    imsi,
                    ue_ip,
                    enb_addr: [0; 4], // updated by ICSRSP
                    qci: 9,
                };

                if self.phase3_upf {
                    // Phase 3: send InitialContextSetupRequest to eNodeB.
                    // AttachAccept NAS PDU is embedded inside the ICSR;
                    // eNodeB delivers it to the UE via RRC Connection Reconfiguration.
                    let security_key = self.world.security.get(&self.attach_ctxs[&mme_ue_s1ap_id].entity_id)
                        .map(|s| s.kasme)
                        .unwrap_or([0; 32]);

                    let icsr = InitialContextSetupRequest {
                        mme_ue_s1ap_id,
                        enb_ue_s1ap_id,
                        ue_ambr_dl: 100_000_000, // 100 Mbps
                        ue_ambr_ul:  50_000_000, //  50 Mbps
                        e_rabs_to_setup: vec![ErabToSetup {
                            e_rab_id:             5,
                            qci:                  9,
                            alloc_retention_prio: 1,
                            transport_addr: self.upf_addr,
                            gtp_teid:       ul_teid,
                        }],
                        nas_pdu:      Some(step.nas_pdu), // AttachAccept
                        security_key,
                    };

                    (vec![S1apMessage::InitialContextSetupRequest(icsr)], vec![upf_event])
                } else {
                    // Phase 2: send AttachAccept directly.
                    (vec![S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
                        mme_ue_s1ap_id,
                        enb_ue_s1ap_id,
                        nas_pdu: step.nas_pdu,
                    })], vec![upf_event])
                }
            }
            Err(reason) => {
                tracing::warn!(?reason, mme_ue_s1ap_id, "Sec mode complete failed");
                (vec![], vec![])
            }
        }
    }

    // ── Initial Context Setup Response ────────────────────────────────────────

    async fn handle_icsrsp(
        &mut self,
        icsrsp: S1apIcsrsp,
    ) -> (Vec<S1apMessage>, Vec<UpfEvent>) {
        let ctx = match self.attach_ctxs.get(&icsrsp.mme_ue_s1ap_id) {
            Some(c) => c,
            None => {
                tracing::warn!(mme_ue_s1ap_id = icsrsp.mme_ue_s1ap_id, "No attach context for ICSRSP");
                return (vec![], vec![]);
            }
        };

        let ul_teid = match ctx.ul_teid {
            Some(t) => t,
            None => {
                tracing::warn!("ICSRSP arrived but no ul_teid in attach context");
                return (vec![], vec![]);
            }
        };

        let (dl_teid, enb_addr) = match icsrsp.e_rabs_setup.first() {
            Some(item) => (item.gtp_teid, item.transport_addr),
            None => {
                tracing::warn!("ICSRSP has no E-RAB setup items");
                return (vec![], vec![]);
            }
        };

        if let Err(e) = handle_initial_context_setup_response(ctx, dl_teid, enb_addr, &mut self.world) {
            tracing::warn!(?e, "ICSRSP tunnel update failed");
            return (vec![], vec![]);
        }

        let event = UpfEvent::UpdateBearer { ul_teid, dl_teid, enb_addr };
        tracing::info!(ul_teid, dl_teid, enb_addr = ?enb_addr, "Bearer established");
        (vec![], vec![event])
    }

    async fn handle_attach_complete_msg(&mut self, mme_ue_s1ap_id: u32, nas_pdu: Bytes) {
        let ctx = match self.attach_ctxs.get_mut(&mme_ue_s1ap_id) {
            Some(c) => c,
            None    => return,
        };
        if let Err(reason) = handle_attach_complete(ctx, &nas_pdu) {
            tracing::warn!(?reason, "Attach complete handling failed");
        }
    }

    // ── UE release ────────────────────────────────────────────────────────────

    fn handle_ue_release(&mut self, mme_ue_s1ap_id: u32) -> Vec<UpfEvent> {
        if let Some(ctx) = self.attach_ctxs.remove(&mme_ue_s1ap_id) {
            self.ip_pool.release(ctx.entity_id);
            if let Some(ImsiComponent(imsi)) = self.world.imsi.get(&ctx.entity_id).copied() {
                self.registry.deregister(imsi);
            }
            self.world.despawn(ctx.entity_id);
            tracing::info!(mme_ue_s1ap_id, "UE context released");
            if let Some(ul_teid) = ctx.ul_teid {
                return vec![UpfEvent::RemoveSession { ul_teid }];
            }
        }
        vec![]
    }

    // ── Allocators ────────────────────────────────────────────────────────────

    fn alloc_mme_ue_id(&mut self) -> u32 {
        let id = self.next_mme_ue_id;
        self.next_mme_ue_id = self.next_mme_ue_id.wrapping_add(1);
        id
    }

    fn alloc_ul_teid(&mut self) -> u32 {
        let t = self.next_ul_teid;
        self.next_ul_teid = self.next_ul_teid.wrapping_add(1);
        if self.next_ul_teid < 0x0001_0000 { self.next_ul_teid = 0x0001_0000; }
        t
    }

    // ── Metrics ───────────────────────────────────────────────────────────────

    pub fn subscriber_count(&self) -> usize  { self.world.len() }
    pub fn authenticated_count(&self) -> usize { self.world.authenticated_count() }
}

impl Default for Mme { fn default() -> Self { Self::new() } }

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use midn_proto::s1ap::messages::{
        ErabSetupItem, InitialContextSetupResponse as IcsrResp, InitialUeMessage,
    };
    use midn_proto::nas::codec::{
        encode_attach_request, encode_auth_response,
        encode_sec_mode_complete, encode_attach_complete, decode_nas, NasPdu,
    };

    // ── Phase 2 gate — full attach, direct AttachAccept ───────────────────────

    #[tokio::test]
    async fn test_full_attach_procedure_phase2_gate() {
        let imsi: u64 = 234_15_1234567890_u64;
        let mut mme = Mme::new(); // phase3_upf = false

        mme.hss.provision_hex(imsi,
            "465b5ce8b199b49faa5f0a2ee238a6bc",
            "cd63cb71954a9f4e48a5994e37a02baf",
        ).expect("valid test credentials");

        // Step 1: Attach Request
        let (responses, events) = mme.process_s1ap(S1apMessage::InitialUeMessage(
            InitialUeMessage {
                enb_ue_s1ap_id: 1,
                nas_pdu:        encode_attach_request(imsi, 0x01, 0x07),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
                rrc_cause:      0,
            }
        )).await;
        assert_eq!(responses.len(), 1, "MME should send AuthenticationRequest");
        assert!(events.is_empty());

        let (mme_ue_s1ap_id, _) = match &responses[0] {
            S1apMessage::DownlinkNasTransport(d) => (d.mme_ue_s1ap_id, d.nas_pdu.clone()),
            _ => panic!("Expected DownlinkNasTransport(AuthRequest)"),
        };

        // Step 2: Auth Response (correct RES)
        let entity_id = mme.registry.lookup(imsi).expect("IMSI registered");
        let xres = mme.world.security.get(&entity_id).map(|s| s.pending_xres).unwrap();

        let (responses, _) = mme.process_s1ap(S1apMessage::UplinkNasTransport(
            UplinkNasTransport {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 1,
                nas_pdu:        encode_auth_response(&xres),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            }
        )).await;
        assert_eq!(responses.len(), 1, "MME should send SecurityModeCommand");
        assert!(mme.world.is_authenticated(entity_id));

        // Step 3: Security Mode Complete → Phase 2 sends AttachAccept directly
        let (responses, events) = mme.process_s1ap(S1apMessage::UplinkNasTransport(
            UplinkNasTransport {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 1,
                nas_pdu:        encode_sec_mode_complete(),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            }
        )).await;
        assert_eq!(responses.len(), 1, "Phase 2: MME should send AttachAccept directly");
        assert_eq!(events.len(), 1,    "Phase 2: CreateSession event emitted");

        let attach_accept_pdu = match &responses[0] {
            S1apMessage::DownlinkNasTransport(d) => d.nas_pdu.clone(),
            _ => panic!("Phase 2: Expected DownlinkNasTransport(AttachAccept)"),
        };
        match decode_nas(&attach_accept_pdu) {
            Ok(NasPdu::AttachAccept(aa)) => {
                assert!(aa.ip_address.is_some());
                assert_eq!(aa.ip_address.unwrap()[0], 10);
            }
            other => panic!("Expected AttachAccept, got {other:?}"),
        }
        match &events[0] {
            UpfEvent::CreateSession { ul_teid, ue_ip, .. } => {
                assert_eq!(ue_ip[0], 10, "UE IP should be in 10.x range");
                assert!(*ul_teid >= 0x0001_0000, "UL TEID should be in allocated range");
            }
            _ => panic!("Expected CreateSession event"),
        }

        // Step 4: Attach Complete
        let (responses, events) = mme.process_s1ap(S1apMessage::UplinkNasTransport(
            UplinkNasTransport {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 1,
                nas_pdu:        encode_attach_complete(),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            }
        )).await;
        assert!(responses.is_empty());
        assert!(events.is_empty());

        assert_eq!(mme.subscriber_count(),    1);
        assert_eq!(mme.authenticated_count(), 1);
        assert!(mme.world.is_authenticated(entity_id));
        assert!(mme.world.session.contains_key(&entity_id));
        assert!(mme.world.tunnel.contains_key(&entity_id));
    }

    // ── Phase 3 gate — ICSR flow, real DL TEID from eNodeB ───────────────────

    #[tokio::test]
    async fn test_full_attach_procedure_phase3_icsr() {
        let imsi: u64 = 234_15_9876543210_u64;
        let mut mme = Mme::new().with_phase3([10, 100, 0, 1]);

        mme.hss.provision_hex(imsi,
            "465b5ce8b199b49faa5f0a2ee238a6bc",
            "cd63cb71954a9f4e48a5994e37a02baf",
        ).unwrap();

        // Step 1: Attach Request
        let (responses, _) = mme.process_s1ap(S1apMessage::InitialUeMessage(
            InitialUeMessage {
                enb_ue_s1ap_id: 2,
                nas_pdu:        encode_attach_request(imsi, 0x01, 0x07),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
                rrc_cause:      0,
            }
        )).await;
        assert_eq!(responses.len(), 1);
        let (mme_ue_s1ap_id, _) = match &responses[0] {
            S1apMessage::DownlinkNasTransport(d) => (d.mme_ue_s1ap_id, d.nas_pdu.clone()),
            _ => panic!(),
        };

        // Step 2: Auth Response
        let entity_id = mme.registry.lookup(imsi).unwrap();
        let xres = mme.world.security.get(&entity_id).map(|s| s.pending_xres).unwrap();
        let (responses, _) = mme.process_s1ap(S1apMessage::UplinkNasTransport(
            UplinkNasTransport {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 2,
                nas_pdu:        encode_auth_response(&xres),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            }
        )).await;
        assert_eq!(responses.len(), 1, "SecModeCmd");

        // Step 3: Security Mode Complete → Phase 3 sends ICSR
        let (responses, events) = mme.process_s1ap(S1apMessage::UplinkNasTransport(
            UplinkNasTransport {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 2,
                nas_pdu:        encode_sec_mode_complete(),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            }
        )).await;
        assert_eq!(responses.len(), 1, "Phase 3: MME should send InitialContextSetupRequest");
        assert_eq!(events.len(),    1, "Phase 3: CreateSession event emitted");

        let icsr = match &responses[0] {
            S1apMessage::InitialContextSetupRequest(r) => r,
            _ => panic!("Phase 3: Expected InitialContextSetupRequest, got {:?}", responses[0]),
        };
        let ul_teid_from_icsr = icsr.e_rabs_to_setup[0].gtp_teid;
        assert_eq!(icsr.e_rabs_to_setup[0].transport_addr, [10, 100, 0, 1], "UPF addr in ICSR");
        // Verify AttachAccept is embedded
        let nas_in_icsr = icsr.nas_pdu.clone().unwrap();
        match decode_nas(&nas_in_icsr) {
            Ok(NasPdu::AttachAccept(aa)) => {
                assert!(aa.ip_address.is_some(), "ICSR must carry AttachAccept with IP");
            }
            other => panic!("Expected AttachAccept in ICSR NAS PDU, got {other:?}"),
        }

        let create_ul_teid = match &events[0] {
            UpfEvent::CreateSession { ul_teid, .. } => *ul_teid,
            _ => panic!("Expected CreateSession"),
        };
        assert_eq!(create_ul_teid, ul_teid_from_icsr, "CreateSession ul_teid must match ICSR");

        // Step 4: Simulate eNodeB ICSRSP with its assigned DL TEID
        let enb_dl_teid = 0xDEAD_BEEF_u32;
        let enb_addr    = [192u8, 168, 1, 100];
        let (responses, events) = mme.process_s1ap(
            S1apMessage::InitialContextSetupResponse(IcsrResp {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 2,
                e_rabs_setup: vec![ErabSetupItem {
                    e_rab_id:       5,
                    transport_addr: enb_addr,
                    gtp_teid:       enb_dl_teid,
                }],
                e_rabs_failed: vec![],
            })
        ).await;
        assert!(responses.is_empty(), "ICSRSP needs no S1AP response");
        assert_eq!(events.len(), 1, "UpdateBearer event emitted");
        match &events[0] {
            UpfEvent::UpdateBearer { ul_teid, dl_teid, enb_addr: ea } => {
                assert_eq!(*ul_teid,  ul_teid_from_icsr);
                assert_eq!(*dl_teid,  enb_dl_teid);
                assert_eq!(*ea,       enb_addr);
            }
            _ => panic!("Expected UpdateBearer"),
        }
        // ECS TunnelComponent updated
        let tunnel = mme.world.tunnel.get(&entity_id).unwrap();
        assert_eq!(tunnel.dl_teid,   enb_dl_teid);
        assert_eq!(tunnel.enb_addr,  enb_addr);
        assert_eq!(tunnel.ul_teid,   ul_teid_from_icsr);

        // Step 5: Attach Complete (eNodeB relayed AttachAccept → UE via RRC)
        let (responses, events) = mme.process_s1ap(S1apMessage::UplinkNasTransport(
            UplinkNasTransport {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 2,
                nas_pdu:        encode_attach_complete(),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            }
        )).await;
        assert!(responses.is_empty());
        assert!(events.is_empty());

        assert_eq!(mme.subscriber_count(),    1);
        assert_eq!(mme.authenticated_count(), 1);
        assert!(mme.world.is_authenticated(entity_id));
        assert!(mme.world.session.contains_key(&entity_id));
    }

    // ── Failure paths ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_attach_fails_for_unknown_imsi() {
        let mut mme = Mme::new();
        let (responses, events) = mme.process_s1ap(S1apMessage::InitialUeMessage(
            InitialUeMessage {
                enb_ue_s1ap_id: 1,
                nas_pdu:        encode_attach_request(999_99_9999999999_u64, 1, 7),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
                rrc_cause:      0,
            }
        )).await;
        assert!(responses.is_empty(), "Unknown IMSI: no response");
        assert!(events.is_empty());
        assert_eq!(mme.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn test_attach_fails_on_wrong_res() {
        let imsi = 234_15_0000000001_u64;
        let mut mme = Mme::new();
        mme.hss.provision_hex(imsi,
            "465b5ce8b199b49faa5f0a2ee238a6bc",
            "cd63cb71954a9f4e48a5994e37a02baf",
        ).unwrap();

        let (responses, _) = mme.process_s1ap(S1apMessage::InitialUeMessage(
            InitialUeMessage {
                enb_ue_s1ap_id: 3,
                nas_pdu:        encode_attach_request(imsi, 1, 7),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
                rrc_cause:      0,
            }
        )).await;
        let mme_ue_id = match &responses[0] {
            S1apMessage::DownlinkNasTransport(d) => d.mme_ue_s1ap_id,
            _ => panic!(),
        };

        let (responses, events) = mme.process_s1ap(S1apMessage::UplinkNasTransport(
            UplinkNasTransport {
                mme_ue_s1ap_id: mme_ue_id,
                enb_ue_s1ap_id: 3,
                nas_pdu:        encode_auth_response(&[0u8; 8]),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            }
        )).await;
        assert!(responses.is_empty(), "Wrong RES: no response");
        assert!(events.is_empty());

        let entity_id = mme.registry.lookup(imsi).expect("entity still exists");
        assert!(!mme.world.is_authenticated(entity_id));
    }
            }
