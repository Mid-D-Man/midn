// crates/midn-core/src/amf/state_machine.rs
//! AMF — dispatch layer over `registration`. Mirrors `mme::state_machine`'s
//! structure: entry point matches on the incoming `NgapMessage` variant and
//! either starts a new procedure directly (`InitialUeMessage`) or decodes
//! the NAS PDU inside `UplinkNasTransport` and routes on ITS variant.
//!
//! `Amf` owns its own `World`, `ImsiRegistry`, and `Hss` — a separate
//! instance from `Mme`'s, not shared. See `registration` module doc's
//! "AUSF/UDM simplification" section for why, and for the known
//! consequence (a subscriber needs provisioning into both if a scenario
//! ever runs LTE and 5G side by side).

use midn_ecs::{ImsiRegistry, World};
use midn_proto::nas5gs::{decode_nas5gs, decode_protected, Nas5gsPdu, NAS5GS_SHT_PLAIN};
use midn_proto::ngap::messages::{NgapMessage, NgapUplinkNasTransport};

use crate::amf::registration;
use crate::hss::Hss;

pub struct Amf {
    pub(crate) world: World,
    pub(crate) registry: ImsiRegistry,
    pub hss: Hss,
}

impl Amf {
    pub fn new() -> Self {
        Self { world: World::new(), registry: ImsiRegistry::new(), hss: Hss::new() }
    }

    pub fn hss_mut(&mut self) -> &mut Hss { &mut self.hss }

    pub fn subscriber_count(&self) -> usize { self.world.subscriber_count() }

    pub async fn process_ngap(&mut self, msg: NgapMessage) -> Vec<NgapMessage> {
        match msg {
            NgapMessage::InitialUeMessage(ium) => registration::start_registration(
                &mut self.world, ium.ran_ue_ngap_id, &ium.nas_pdu, ium.tai,
            ),
            NgapMessage::UplinkNasTransport(unt) => self.handle_uplink_nas(unt),
            _ => {
                tracing::debug!("process_ngap: unhandled NGAP message variant (out of scope for Phase A)");
                vec![]
            }
        }
    }

    /// Decode the NAS PDU inside an `UplinkNasTransport` — auto-detecting
    /// plain vs protected by security header type, same pattern
    /// `mme::state_machine::handle_uplink_nas` uses for LTE — then route on
    /// the decoded NAS message's own variant.
    ///
    /// 5G's security header type lives in byte[1]'s low nibble (byte[0] is
    /// the full-octet Extended Protocol Discriminator) — NOT byte[0]'s high
    /// nibble like NAS-EPS. See `nas5gs::codec` module doc for why the
    /// header shape genuinely differs, not just a width tweak.
    fn handle_uplink_nas(&mut self, unt: NgapUplinkNasTransport) -> Vec<NgapMessage> {
        let amf_ue_ngap_id = unt.amf_ue_ngap_id;
        let ran_ue_ngap_id = unt.ran_ue_ngap_id;

        let sht = unt.nas_pdu.get(1).map(|b| b & 0x0F).unwrap_or(0);

        let plain_pdu: Vec<u8> = if sht == NAS5GS_SHT_PLAIN {
            unt.nas_pdu.to_vec()
        } else {
            let ctx = match self.world.nas_security5g_mut(amf_ue_ngap_id) {
                Some(c) => c,
                None => {
                    tracing::warn!(amf_ue_ngap_id, "UplinkNasTransport: protected PDU but no NAS security context");
                    return vec![];
                }
            };
            match decode_protected(ctx, &unt.nas_pdu) {
                Some(inner) => inner,
                None => {
                    tracing::warn!(amf_ue_ngap_id, "UplinkNasTransport: NAS integrity check failed");
                    return vec![];
                }
            }
        };

        match decode_nas5gs(&plain_pdu) {
            Ok(Nas5gsPdu::IdentityResponse(_)) => registration::handle_identity_response(
                &mut self.world, &mut self.registry, &mut self.hss,
                ran_ue_ngap_id, amf_ue_ngap_id, &plain_pdu,
            ),
            Ok(Nas5gsPdu::AuthenticationResponse(_)) => registration::handle_auth_response(
                &mut self.world, ran_ue_ngap_id, amf_ue_ngap_id, &plain_pdu,
            ),
            Ok(Nas5gsPdu::SecurityModeComplete) => registration::handle_security_mode_complete(
                &mut self.world, ran_ue_ngap_id, amf_ue_ngap_id,
            ),
            Ok(Nas5gsPdu::RegistrationComplete) => registration::handle_registration_complete(
                &mut self.world, amf_ue_ngap_id,
            ),
            _ => {
                tracing::warn!(amf_ue_ngap_id, "UplinkNasTransport: unknown or unsupported NAS PDU");
                vec![]
            }
        }
    }
}

impl Default for Amf {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use midn_auth::keys::{Amf as MilenageAmf, Rand, Sqn};
    use midn_auth::{AuthKey, MilenageContext, OpCode};
    use midn_ecs::AuthState;
    use midn_proto::nas5gs::{encode_identity_response_suci, encode_registration_request, Suci};
    use midn_proto::ngap::messages::NgapInitialUeMessage;

    // Must round-trip through `registration::resolve_suci_to_imsi`'s 5-byte
    // MSIN-as-IMSI scheme (< 2^40 ≈ 1.0995e12 — see that function's doc).
    // The original 15-digit value here (901_700_000_000_001) silently
    // truncated on resolve (901700000000001 -> 100465223681), so the AMF
    // looked up a different subscriber than `Hss` was provisioned under and
    // dropped the IdentityResponse as unknown — the actual root cause of
    // this test's CI failure, not the protected-envelope direction bug
    // below (that one's real too, but this test never got far enough to
    // hit it). Trimmed to 12 digits, which fits.
    const TEST_IMSI: u64 = 901_700_000_001;
    const TEST_K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
    const TEST_OPC: &str = "cd63cb71954a9f4e48a5994e37a02baf";
    const TEST_PLMN: [u8; 3] = [0x00, 0x11, 0x22];
    const TEST_TAI: [u8; 6] = [0x00, 0x11, 0x22, 0x00, 0x00, 0x01];

    fn test_amf() -> Amf {
        let mut amf = Amf::new();
        amf.hss_mut().provision_hex(TEST_IMSI, TEST_K, TEST_OPC).expect("valid test hex");
        amf
    }

    /// Encode a null-scheme SUCI carrying `imsi` — the exact inverse of
    /// `registration::resolve_suci_to_imsi`. See that function's doc for
    /// why MSIN's 5 bytes are the whole story.
    fn suci_for_imsi(imsi: u64) -> Suci {
        let bytes = imsi.to_be_bytes();
        let mut msin = [0u8; 5];
        msin.copy_from_slice(&bytes[3..8]);
        Suci { mcc: [0, 0, 0], mnc: [0, 0, 0], routing_indicator: 0, protection_scheme: 0, home_network_pki: 0, msin }
    }

    fn initial_ue_message(ran_ue_ngap_id: u32) -> NgapMessage {
        let nas = encode_registration_request(1, 0, None, 0x00C0);
        NgapMessage::InitialUeMessage(NgapInitialUeMessage {
            ran_ue_ngap_id,
            nas_pdu: nas,
            tai: TEST_TAI,
            nr_cgi: [0u8; 9],
            rrc_establishment_cause: 0,
        })
    }

    fn uplink(ran_ue_ngap_id: u32, amf_ue_ngap_id: u32, nas_pdu: bytes::Bytes) -> NgapMessage {
        NgapMessage::UplinkNasTransport(NgapUplinkNasTransport {
            amf_ue_ngap_id, ran_ue_ngap_id, nas_pdu, tai: TEST_TAI, nr_cgi: [0u8; 9],
        })
    }

    /// Extract the single `NgapDownlinkNasTransport` from a one-message
    /// response, panicking with a useful message otherwise — every step in
    /// this procedure (Phase A) sends exactly zero or one message.
    fn expect_single_downlink(resp: Vec<NgapMessage>) -> (u32, u32, bytes::Bytes) {
        assert_eq!(resp.len(), 1, "expected exactly one response message");
        match resp.into_iter().next().unwrap() {
            NgapMessage::DownlinkNasTransport(dl) => (dl.amf_ue_ngap_id, dl.ran_ue_ngap_id, dl.nas_pdu),
            _ => panic!("expected DownlinkNasTransport"),
        }
    }

    #[tokio::test]
    async fn new_amf_has_no_subscribers() {
        let amf = Amf::new();
        assert_eq!(amf.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn start_registration_rejects_guti_based_request() {
        let mut amf = test_amf();
        let nas = encode_registration_request(1, 0, Some(&[0xABu8; 11]), 0x00C0);
        let msg = NgapMessage::InitialUeMessage(NgapInitialUeMessage {
            ran_ue_ngap_id: 1, nas_pdu: nas, tai: TEST_TAI, nr_cgi: [0u8; 9], rrc_establishment_cause: 0,
        });
        let resp = amf.process_ngap(msg).await;
        assert!(resp.is_empty(), "GUTI-based registration isn't supported — should be silently dropped, not crash");
        assert_eq!(amf.subscriber_count(), 0, "no entity should be spawned for an unsupported GUTI attempt");
    }

    #[tokio::test]
    async fn start_registration_sends_identity_request_and_spawns_entity() {
        let mut amf = test_amf();
        let resp = amf.process_ngap(initial_ue_message(7)).await;
        let (amf_ue_ngap_id, ran_ue_ngap_id, nas_pdu) = expect_single_downlink(resp);
        assert_eq!(ran_ue_ngap_id, 7);
        assert_eq!(amf.subscriber_count(), 1);

        match decode_nas5gs(&nas_pdu) {
            Ok(Nas5gsPdu::IdentityRequest { identity_type }) => {
                assert_eq!(identity_type, midn_proto::nas5gs::IDTYPE_SUCI);
            }
            other => panic!("expected IdentityRequest, got {other:?}"),
        }
        let _ = amf_ue_ngap_id;
    }

    #[tokio::test]
    async fn full_registration_flow_end_to_end() {
        let mut amf = test_amf();

        // Step 1: RegistrationRequest -> IdentityRequest
        let resp = amf.process_ngap(initial_ue_message(7)).await;
        let (amf_ue_ngap_id, ran_ue_ngap_id, id_req_pdu) = expect_single_downlink(resp);
        assert!(matches!(decode_nas5gs(&id_req_pdu), Ok(Nas5gsPdu::IdentityRequest { .. })));

        // Step 2: IdentityResponse(SUCI) -> AuthenticationRequest
        let id_resp_pdu = encode_identity_response_suci(&suci_for_imsi(TEST_IMSI));
        let resp = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, id_resp_pdu)).await;
        let (_, _, auth_req_pdu) = expect_single_downlink(resp);
        let (rand, _autn) = match decode_nas5gs(&auth_req_pdu) {
            Ok(Nas5gsPdu::AuthenticationRequest(d)) => (d.rand, d.autn),
            other => panic!("expected AuthenticationRequest, got {other:?}"),
        };

        // Mock UE side: independently run the SAME Milenage + 5G-AKA KDF
        // chain the AMF ran, to prove the whole loop actually closes — not
        // just that each half compiles in isolation. This is subscriber
        // #1's very first vector (freshly provisioned, SQN starts at 0),
        // so sqn_used = [0; 6] is a safe assumption here — matches
        // Hss's own doc/tests for a first-call vector.
        let mock_ctx = MilenageContext::new(
            AuthKey::from_hex(TEST_K).unwrap(),
            OpCode::from_hex(TEST_OPC).unwrap(),
        );
        let sqn_used = [0u8; 6];
        let milenage_amf = MilenageAmf([0x80, 0x00]);
        let vector = mock_ctx.generate_vector_with_rand(
            Sqn::from_bytes(&sqn_used), milenage_amf, Rand(rand),
        );
        let snn = crate::kdf::serving_network_name(&TEST_PLMN);
        let res_star = crate::kdf::derive_res_star(&vector.ck, &vector.ik, &snn, &rand, &vector.res);

        // Step 3: AuthenticationResponse(RES*) -> SecurityModeCommand
        let auth_resp_pdu = midn_proto::nas5gs::encode_auth_response(&res_star);
        let resp = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, auth_resp_pdu)).await;
        let (_, _, sec_cmd_pdu) = expect_single_downlink(resp);
        assert!(matches!(decode_nas5gs(&sec_cmd_pdu), Ok(Nas5gsPdu::SecurityModeCommand(_))));
        assert!(amf.world.is_authenticated(amf_ue_ngap_id));

        // Step 4: SecurityModeComplete -> ciphered RegistrationAccept.
        // Mock UE independently derives the same KAUSF -> KSEAF -> KAMF ->
        // NAS-key chain to build its own Nas5gsSecurityContext, proving
        // decode_protected actually opens what the AMF sent — not just
        // that encode_protected ran without panicking.
        let sec_complete_pdu = midn_proto::nas5gs::encode_sec_mode_complete();
        let resp = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, sec_complete_pdu)).await;
        let (_, _, accept_envelope) = expect_single_downlink(resp);

        let sqn_xor_ak: [u8; 6] = core::array::from_fn(|i| sqn_used[i] ^ vector.ak[i]);
        let kausf = crate::kdf::derive_kausf(&vector.ck, &vector.ik, &snn, &sqn_xor_ak);
        let kseaf = crate::kdf::derive_kseaf(&kausf, &snn);
        let supi = TEST_IMSI.to_string().into_bytes();
        let kamf = crate::kdf::derive_kamf(&kseaf, &supi, &[0x00, 0x00]);
        let mut mock_ue_nas_ctx = midn_proto::nas5gs::Nas5gsSecurityContext::new(&kamf, 2, 2);

        // AMF sent this via encode_protected (protect_downlink,
        // Direction::Downlink) — the mock UE must open it with the
        // DIRECTION-matched decode_protected_downlink (unprotect_downlink),
        // not decode_protected (unprotect_uplink). Using decode_protected
        // here was the protected-envelope half of this test's CI failure —
        // see nas5gs::codec::decode_protected_downlink's doc for why the
        // AMF-role pair can't be reused for the UE role.
        let accept_plain = midn_proto::nas5gs::decode_protected_downlink(&mut mock_ue_nas_ctx, &accept_envelope)
            .expect("mock UE must be able to decrypt+verify what the AMF sent");
        match decode_nas5gs(&accept_plain) {
            Ok(Nas5gsPdu::RegistrationAccept(d)) => assert_eq!(d.registration_result, 1),
            other => panic!("expected RegistrationAccept, got {other:?}"),
        }
        assert!(amf.world.nas_security5g(amf_ue_ngap_id).is_some());

        // Step 5: RegistrationComplete -> no response, subscriber is online.
        let complete_pdu = midn_proto::nas5gs::encode_registration_complete();
        let resp = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, complete_pdu)).await;
        assert!(resp.is_empty());
        assert!(amf.world.is_authenticated(amf_ue_ngap_id));
    }

    #[tokio::test]
    async fn handle_auth_response_rejects_wrong_res_star() {
        let mut amf = test_amf();
        let resp = amf.process_ngap(initial_ue_message(7)).await;
        let (amf_ue_ngap_id, ran_ue_ngap_id, _) = expect_single_downlink(resp);

        let id_resp_pdu = encode_identity_response_suci(&suci_for_imsi(TEST_IMSI));
        amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, id_resp_pdu)).await;

        let wrong_res_star = [0xFFu8; 16];
        let auth_resp_pdu = midn_proto::nas5gs::encode_auth_response(&wrong_res_star);
        let resp = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, auth_resp_pdu)).await;

        assert!(resp.is_empty(), "wrong RES* must not produce a SecurityModeCommand");
        assert_eq!(amf.world.auth_state(amf_ue_ngap_id), Some(AuthState::Failed(midn_ecs::AuthFailReason::ResMismatch)));
    }

    #[tokio::test]
    async fn unknown_subscriber_is_silently_dropped() {
        let mut amf = Amf::new(); // no provisioning at all
        let resp = amf.process_ngap(initial_ue_message(7)).await;
        let (amf_ue_ngap_id, ran_ue_ngap_id, _) = expect_single_downlink(resp);

        let id_resp_pdu = encode_identity_response_suci(&suci_for_imsi(999_999_999));
        let resp = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, id_resp_pdu)).await;
        assert!(resp.is_empty(), "unknown subscriber must not produce an AuthenticationRequest");
    }
}
