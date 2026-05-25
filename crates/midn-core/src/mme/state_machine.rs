// crates/midn-core/src/mme/state_machine.rs
//! MME top-level state machine — routes S1AP messages to attach handlers.

use std::collections::HashMap;
use bytes::Bytes;

use midn_proto::s1ap::messages::{
    DownlinkNasTransport, S1apMessage,
    // UplinkNasTransport is only constructed in tests — imported there instead
};
use midn_proto::nas::codec::{
    MT_ATTACH_REQUEST, MT_AUTHENTICATION_RESPONSE,
    MT_SECURITY_MODE_COMPLETE, MT_ATTACH_COMPLETE,
};

use crate::ecs::components::ImsiComponent;   // ← was missing
use crate::ecs::registry::ImsiRegistry;
use crate::ecs::world::CoreWorld;
use crate::hss::Hss;
use crate::mme::attach::{
    handle_attach_request, handle_auth_response, handle_security_mode_complete,
    handle_attach_complete, AttachContext, IpPool,
};

/// Mobility Management Entity.
pub struct Mme {
    pub world:    CoreWorld,
    pub registry: ImsiRegistry,
    pub hss:      Hss,
    pub ip_pool:  IpPool,

    /// In-flight attach procedures keyed by MME-UE-S1AP-ID.
    attach_ctxs:    HashMap<u32, AttachContext>,
    /// Maps ENB-UE-S1AP-ID → MME-UE-S1AP-ID for uplink routing.
    enb_to_mme_id:  HashMap<u32, u32>,
    /// Next MME-UE-S1AP-ID to assign.
    next_mme_ue_id: u32,
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
        }
    }

    /// Process an incoming S1AP message from an eNodeB.
    /// Returns S1AP responses to send back.
    pub async fn process_s1ap(&mut self, msg: S1apMessage) -> Vec<S1apMessage> {
        match msg {
            S1apMessage::InitialUeMessage(ium) => {
                self.handle_initial_ue_message(ium.enb_ue_s1ap_id, ium.nas_pdu).await
            }
            S1apMessage::UplinkNasTransport(unt) => {
                self.handle_uplink_nas(unt.enb_ue_s1ap_id, unt.mme_ue_s1ap_id, unt.nas_pdu).await
            }
            S1apMessage::UeContextReleaseComplete { mme_ue_s1ap_id, .. } => {
                self.handle_ue_release(mme_ue_s1ap_id);
                vec![]
            }
            _ => {
                tracing::warn!("Unhandled S1AP message");
                vec![]
            }
        }
    }

    // ── Initial UE Message — starts an attach procedure ───────────────────────

    async fn handle_initial_ue_message(
        &mut self,
        enb_ue_s1ap_id: u32,
        nas_pdu:        Bytes,
    ) -> Vec<S1apMessage> {
        let msg_type = nas_pdu.get(1).copied().unwrap_or(0);
        if msg_type != MT_ATTACH_REQUEST {
            tracing::warn!(msg_type, "InitialUeMessage contains non-AttachRequest NAS PDU");
            return vec![];
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
                vec![S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
                    mme_ue_s1ap_id,
                    enb_ue_s1ap_id,
                    nas_pdu: step.nas_pdu,
                })]
            }
            Err(reason) => {
                tracing::warn!(?reason, "Attach request failed");
                vec![]
            }
        }
    }

    // ── Uplink NAS Transport — routes to active procedure ─────────────────────

    async fn handle_uplink_nas(
        &mut self,
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
        nas_pdu:        Bytes,
    ) -> Vec<S1apMessage> {
        let msg_type = nas_pdu.get(1).copied().unwrap_or(0);

        match msg_type {
            MT_AUTHENTICATION_RESPONSE => {
                self.handle_auth_response_message(enb_ue_s1ap_id, mme_ue_s1ap_id, nas_pdu).await
            }
            MT_SECURITY_MODE_COMPLETE => {
                self.handle_sec_mode_complete_message(enb_ue_s1ap_id, mme_ue_s1ap_id, nas_pdu).await
            }
            MT_ATTACH_COMPLETE => {
                self.handle_attach_complete_message(mme_ue_s1ap_id, nas_pdu).await;
                vec![]
            }
            _ => {
                tracing::warn!(msg_type, mme_ue_s1ap_id, "Unhandled uplink NAS message type");
                vec![]
            }
        }
    }

    async fn handle_auth_response_message(
        &mut self,
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
        nas_pdu:        Bytes,
    ) -> Vec<S1apMessage> {
        let ctx = match self.attach_ctxs.get_mut(&mme_ue_s1ap_id) {
            Some(c) => c,
            None => {
                tracing::warn!(mme_ue_s1ap_id, "No attach context for auth response");
                return vec![];
            }
        };

        match handle_auth_response(ctx, &nas_pdu, &mut self.world) {
            Ok(step) => {
                vec![S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
                    mme_ue_s1ap_id,
                    enb_ue_s1ap_id,
                    nas_pdu: step.nas_pdu,
                })]
            }
            Err(reason) => {
                tracing::warn!(?reason, mme_ue_s1ap_id, "Auth response handling failed");
                vec![]
            }
        }
    }

    async fn handle_sec_mode_complete_message(
        &mut self,
        enb_ue_s1ap_id: u32,
        mme_ue_s1ap_id: u32,
        nas_pdu:        Bytes,
    ) -> Vec<S1apMessage> {
        let ctx = match self.attach_ctxs.get_mut(&mme_ue_s1ap_id) {
            Some(c) => c,
            None => {
                tracing::warn!(mme_ue_s1ap_id, "No attach context for sec mode complete");
                return vec![];
            }
        };

        match handle_security_mode_complete(ctx, &nas_pdu, &mut self.world, &mut self.ip_pool) {
            Ok(step) => {
                vec![S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
                    mme_ue_s1ap_id,
                    enb_ue_s1ap_id,
                    nas_pdu: step.nas_pdu,
                })]
            }
            Err(reason) => {
                tracing::warn!(?reason, mme_ue_s1ap_id, "Security mode complete failed");
                vec![]
            }
        }
    }

    async fn handle_attach_complete_message(&mut self, mme_ue_s1ap_id: u32, nas_pdu: Bytes) {
        let ctx = match self.attach_ctxs.get_mut(&mme_ue_s1ap_id) {
            Some(c) => c,
            None => return,
        };
        if let Err(reason) = handle_attach_complete(ctx, &nas_pdu) {
            tracing::warn!(?reason, "Attach complete handling failed");
        }
    }

    fn handle_ue_release(&mut self, mme_ue_s1ap_id: u32) {
        if let Some(ctx) = self.attach_ctxs.remove(&mme_ue_s1ap_id) {
            self.ip_pool.release(ctx.entity_id);
            if let Some(ImsiComponent(imsi)) = self.world.imsi.get(&ctx.entity_id).copied() {
                self.registry.deregister(imsi);
            }
            self.world.despawn(ctx.entity_id);
            tracing::info!(mme_ue_s1ap_id, "UE context released");
        }
    }

    fn alloc_mme_ue_id(&mut self) -> u32 {
        let id = self.next_mme_ue_id;
        self.next_mme_ue_id = self.next_mme_ue_id.wrapping_add(1);
        id
    }

    pub fn subscriber_count(&self) -> usize { self.world.len() }
    pub fn authenticated_count(&self) -> usize { self.world.authenticated_count() }
}

impl Default for Mme { fn default() -> Self { Self::new() } }

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // UplinkNasTransport only constructed in tests — import here, not at crate level
    use midn_proto::s1ap::messages::UplinkNasTransport;
    use midn_proto::nas::codec::{
        encode_attach_request, encode_auth_response,
        encode_sec_mode_complete, encode_attach_complete,
    };
    use midn_proto::s1ap::messages::InitialUeMessage;

    /// End-to-end LTE attach procedure.
    ///
    /// Phase 2 gate test. If this passes, Phase 2 is done.
    ///
    /// Drives the full 5-step UE↔MME exchange:
    ///   AttachRequest → AuthenticationRequest
    ///   AuthenticationResponse → SecurityModeCommand
    ///   SecurityModeComplete → AttachAccept
    ///   AttachComplete → subscriber online
    #[tokio::test]
    async fn test_full_attach_procedure_phase2_gate() {
        let imsi: u64 = 234_15_1234567890_u64;

        let mut mme = Mme::new();
        mme.hss.provision_hex(
            imsi,
            "465b5ce8b199b49faa5f0a2ee238a6bc",
            "cd63cb71954a9f4e48a5994e37a02baf",
        ).expect("valid test credentials");

        // Step 1: UE → MME : AttachRequest
        let attach_req_pdu = encode_attach_request(imsi, 0x01, 0x07);
        let responses = mme.process_s1ap(S1apMessage::InitialUeMessage(
            InitialUeMessage {
                enb_ue_s1ap_id: 1,
                nas_pdu:        attach_req_pdu,
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
                rrc_cause:      0,
            }
        )).await;

        assert_eq!(responses.len(), 1, "MME should send AuthenticationRequest");
        let (mme_ue_s1ap_id, auth_req_pdu) = match &responses[0] {
            S1apMessage::DownlinkNasTransport(d) => (d.mme_ue_s1ap_id, d.nas_pdu.clone()),
            _ => panic!("Expected DownlinkNasTransport"),
        };

        // Verify it decoded as an AuthenticationRequest
        match midn_proto::nas::codec::decode_nas(&auth_req_pdu) {
            Ok(midn_proto::nas::codec::NasPdu::AuthenticationRequest(_)) => {}
            other => panic!("Expected AuthenticationRequest, got {other:?}"),
        }

        // Step 2: Simulate correct UE response.
        // Retrieve the stored XRES directly (Milenage generate_vector is stubbed;
        // replace with real UE-side computation once Phase 1 validates test sets).
        let entity_id = mme.registry.lookup(imsi)
            .expect("IMSI should be registered after attach request");
        let xres = mme.world.security.get(&entity_id)
            .map(|s| s.pending_xres)
            .expect("security context should contain pending XRES");

        // Step 3: UE → MME : AuthenticationResponse (with correct RES)
        let auth_resp_pdu = encode_auth_response(&xres);
        let responses = mme.process_s1ap(S1apMessage::UplinkNasTransport(
            UplinkNasTransport {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 1,
                nas_pdu:        auth_resp_pdu,
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            }
        )).await;

        assert_eq!(responses.len(), 1, "MME should send SecurityModeCommand");
        assert!(mme.world.is_authenticated(entity_id), "Subscriber should be authenticated");

        let sec_cmd_pdu = match &responses[0] {
            S1apMessage::DownlinkNasTransport(d) => d.nas_pdu.clone(),
            _ => panic!("Expected SecurityModeCommand"),
        };
        match midn_proto::nas::codec::decode_nas(&sec_cmd_pdu) {
            Ok(midn_proto::nas::codec::NasPdu::SecurityModeCommand(_)) => {}
            other => panic!("Expected SecurityModeCommand, got {other:?}"),
        }

        // Step 4: UE → MME : SecurityModeComplete
        let responses = mme.process_s1ap(S1apMessage::UplinkNasTransport(
            UplinkNasTransport {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 1,
                nas_pdu:        encode_sec_mode_complete(),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            }
        )).await;

        assert_eq!(responses.len(), 1, "MME should send AttachAccept");
        let attach_accept_pdu = match &responses[0] {
            S1apMessage::DownlinkNasTransport(d) => d.nas_pdu.clone(),
            _ => panic!("Expected AttachAccept"),
        };
        match midn_proto::nas::codec::decode_nas(&attach_accept_pdu) {
            Ok(midn_proto::nas::codec::NasPdu::AttachAccept(aa)) => {
                assert!(aa.ip_address.is_some(), "AttachAccept must contain IP address");
                assert_eq!(aa.ip_address.unwrap()[0], 10, "IP should be in 10.x.x.x range");
            }
            other => panic!("Expected AttachAccept, got {other:?}"),
        }
        assert!(mme.world.session.contains_key(&entity_id), "Session must exist");

        // Step 5: UE → MME : AttachComplete
        let responses = mme.process_s1ap(S1apMessage::UplinkNasTransport(
            UplinkNasTransport {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 1,
                nas_pdu:        encode_attach_complete(),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            }
        )).await;

        assert_eq!(responses.len(), 0, "No response needed for AttachComplete");

        // Final state assertions
        assert_eq!(mme.subscriber_count(),    1);
        assert_eq!(mme.authenticated_count(), 1);
        assert!(mme.world.is_authenticated(entity_id));
        assert!(mme.world.session.contains_key(&entity_id));
        assert!(mme.world.tunnel.contains_key(&entity_id));
    }

    #[tokio::test]
    async fn test_attach_fails_for_unknown_imsi() {
        let mut mme = Mme::new();

        let responses = mme.process_s1ap(S1apMessage::InitialUeMessage(
            InitialUeMessage {
                enb_ue_s1ap_id: 1,
                nas_pdu:        encode_attach_request(999_99_9999999999_u64, 1, 7),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
                rrc_cause:      0,
            }
        )).await;

        assert_eq!(responses.len(), 0, "Unknown IMSI should produce no response");
        assert_eq!(mme.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn test_attach_fails_on_wrong_res() {
        let imsi = 234_15_0000000001_u64;
        let mut mme = Mme::new();
        mme.hss.provision_hex(
            imsi,
            "465b5ce8b199b49faa5f0a2ee238a6bc",
            "cd63cb71954a9f4e48a5994e37a02baf",
        ).unwrap();

        let responses = mme.process_s1ap(S1apMessage::InitialUeMessage(
            InitialUeMessage {
                enb_ue_s1ap_id: 2,
                nas_pdu:        encode_attach_request(imsi, 1, 7),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
                rrc_cause:      0,
            }
        )).await;
        assert_eq!(responses.len(), 1);

        let mme_ue_id = match &responses[0] {
            S1apMessage::DownlinkNasTransport(d) => d.mme_ue_s1ap_id,
            _ => panic!(),
        };

        // Send wrong RES
        let responses = mme.process_s1ap(S1apMessage::UplinkNasTransport(
            UplinkNasTransport {
                mme_ue_s1ap_id: mme_ue_id,
                enb_ue_s1ap_id: 2,
                nas_pdu:        encode_auth_response(&[0u8; 8]),
                tai:            [0; 5],
                eutran_cgi:     [0; 7],
            }
        )).await;

        assert_eq!(responses.len(), 0, "Wrong RES must produce no response");

        let entity_id = mme.registry.lookup(imsi).expect("entity should still exist");
        assert!(
            !mme.world.is_authenticated(entity_id),
            "Subscriber must NOT be authenticated after wrong RES"
        );
    }
        }
