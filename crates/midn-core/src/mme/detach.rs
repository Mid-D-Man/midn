// crates/midn-core/src/mme/detach.rs
//! UE-initiated detach procedure — 3GPP TS 23.401 Section 5.3.8.2 /
//! TS 24.301 Section 5.5.2.2.
//!
//! ## Sequence
//!
//! ```text
//! UE → MME      : NAS DetachRequest          (via UplinkNasTransport)
//! MME → UE      : NAS DetachAccept            (skipped if switch_off — the UE
//!                                               is powering down and will not
//!                                               process a reply; protected if
//!                                               NAS security is already active)
//! MME → eNodeB  : S1AP UeContextReleaseCommand
//! eNodeB → MME  : S1AP UeContextReleaseComplete
//! ```
//!
//! The actual teardown (entity despawn, IMSI deregister, `UpfEvent::RemoveSession`,
//! TEID release) happens on `UeContextReleaseComplete`, handled by
//! `state_machine::Mme::handle_release_complete` — the SAME code path used for
//! network-initiated release. This module only drives the *trigger*: decode
//! the NAS request, optionally ack it (protected, if a NAS security context
//! exists for this subscriber — see `nas::security` module docs for when that
//! activates), and ask the eNodeB to release the S1/radio context. There is
//! exactly one teardown path in the system, no matter which side initiates it.

use midn_proto::nas::{
    decode_nas, encode_detach_accept, encode_protected,
    NasPdu, NAS_BEARER, SHT_INTEGRITY_CIPHERED,
};
use midn_proto::s1ap::{DownlinkNasTransport, S1apCause, S1apMessage};

use crate::mme::state_machine::World;

/// Process an `UplinkNasTransport` whose NAS PDU is a `DetachRequest`.
///
/// Returns the S1AP messages to send downstream. Never emits `UpfEvent`s —
/// session teardown only happens once `UeContextReleaseComplete` confirms the
/// eNodeB has actually released the radio context (see module docs above).
///
/// Takes `world: &mut World` (not `&World`) because protecting the
/// DetachAccept reply needs mutable access to the subscriber's
/// `NasSecurityContext` (advancing its downlink COUNT).
pub fn handle_detach_request(
    world:          &mut World,
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    nas_pdu:        &[u8],
) -> Vec<S1apMessage> {
    let switch_off = match decode_nas(nas_pdu) {
        Ok(NasPdu::DetachRequest(d)) => d.switch_off,
        _ => {
            tracing::warn!(mme_ue_s1ap_id, "handle_detach_request: bad NAS PDU");
            return vec![];
        }
    };

    if world.get_attach_context(mme_ue_s1ap_id).is_none() {
        tracing::warn!(mme_ue_s1ap_id, "handle_detach_request: no context for entity");
        return vec![];
    }

    let mut out = Vec::with_capacity(2);

    // Normal detach: ack before tearing down. Switch-off: UE is already gone,
    // sending a reply would just be wasted air time.
    if !switch_off {
        let detach_accept_plain = encode_detach_accept();

        // Protect the reply if NAS security is active for this subscriber —
        // by the time a detach happens, attach should already have completed
        // SecurityModeComplete, so this is normally always Some. Falls back
        // to plain only as a defensive no-context case.
        let nas_pdu_out = match world
            .get_attach_context_mut(mme_ue_s1ap_id)
            .and_then(|c| c.nas_security.as_mut())
        {
            Some(nas_ctx) => encode_protected(
                nas_ctx, SHT_INTEGRITY_CIPHERED, NAS_BEARER, &detach_accept_plain,
            ),
            None => {
                tracing::debug!(
                    mme_ue_s1ap_id,
                    "handle_detach_request: no NAS security context — sending DetachAccept plain"
                );
                detach_accept_plain
            }
        };

        out.push(S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
            enb_ue_s1ap_id,
            mme_ue_s1ap_id,
            nas_pdu: nas_pdu_out,
        }));
    }

    out.push(S1apMessage::UeContextReleaseCommand { cause: S1apCause::NasDetach });

    tracing::info!(
        mme_ue_s1ap_id, switch_off,
        "DetachRequest processed — UeContextReleaseCommand issued"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mme::state_machine::AttachContext;
    use midn_proto::nas::encode_detach_request;

    fn world_with_context(entity: u32) -> World {
        let mut w = World::new();
        w.insert_attach_context(entity, AttachContext {
            imsi: 1, enb_ue_s1ap_id: 0, mme_ue_s1ap_id: entity,
            rand: [0; 16], xres: [0; 8], ck: [0; 16], ik: [0; 16],
            ak: [0; 6], plmn: [0; 3],
            sqn_used: [0; 6], ue_ip: [0; 4], ul_teid: None,
            nas_security: None,
        });
        w
    }

    #[test]
    fn normal_detach_sends_accept_then_release_command() {
        let mut world = world_with_context(7);
        let nas_pdu   = encode_detach_request(1, false, 0, &[0; 10]);
        let out       = handle_detach_request(&mut world, 1, 7, &nas_pdu);

        assert_eq!(out.len(), 2, "expect DetachAccept + UeContextReleaseCommand");
        assert!(matches!(out[0], S1apMessage::DownlinkNasTransport(_)));
        assert!(matches!(
            out[1],
            S1apMessage::UeContextReleaseCommand { cause: S1apCause::NasDetach }
        ));
    }

    #[test]
    fn switch_off_detach_skips_accept() {
        let mut world = world_with_context(7);
        let nas_pdu   = encode_detach_request(1, true, 0, &[0; 10]);
        let out       = handle_detach_request(&mut world, 1, 7, &nas_pdu);

        assert_eq!(out.len(), 1, "switch-off skips DetachAccept");
        assert!(matches!(
            out[0],
            S1apMessage::UeContextReleaseCommand { cause: S1apCause::NasDetach }
        ));
    }

    #[test]
    fn detach_for_unknown_entity_is_noop() {
        let mut world = World::new(); // no context inserted
        let nas_pdu   = encode_detach_request(1, false, 0, &[0; 10]);
        let out       = handle_detach_request(&mut world, 1, 999, &nas_pdu);
        assert!(out.is_empty());
    }

    #[test]
    fn bad_nas_pdu_is_noop() {
        let mut world = world_with_context(7);
        let out       = handle_detach_request(&mut world, 1, 7, &[0xFF, 0xFF]);
        assert!(out.is_empty());
    }

    #[test]
    fn detach_accept_is_protected_when_nas_security_is_active() {
        use midn_proto::nas::{
            decode_nas, derive_nas_keys, eea2_apply, eia2_verify_mac, Direction,
            NasEeaAlgorithm, NasEiaAlgorithm, NasPdu, NasSecurityContext,
        };

        let kasme = [0x5Au8; 32];
        let mut world = World::new();
        let entity = 7u32;
        world.insert_attach_context(entity, AttachContext {
            imsi: 1, enb_ue_s1ap_id: 0, mme_ue_s1ap_id: entity,
            rand: [0; 16], xres: [0; 8], ck: [0; 16], ik: [0; 16],
            ak: [0; 6], plmn: [0; 3],
            sqn_used: [0; 6], ue_ip: [0; 4], ul_teid: None,
            nas_security: Some(NasSecurityContext::new(
                &kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2,
            )),
        });

        let nas_pdu = encode_detach_request(1, false, 0, &[0; 10]);
        let out     = handle_detach_request(&mut world, 1, entity, &nas_pdu);

        assert_eq!(out.len(), 2);
        let envelope = match &out[0] {
            S1apMessage::DownlinkNasTransport(m) => m.nas_pdu.clone(),
            _ => panic!("expected DownlinkNasTransport"),
        };

        // sht must be non-zero — confirms it actually went out protected, not plain.
        let sht = (envelope[0] >> 4) & 0x0F;
        assert_ne!(sht, 0, "DetachAccept should be protected once NAS security is active");

        // Verify "as the UE would": same keys, Downlink direction — this is a
        // message the MME SENT, so it must be checked with protect_downlink's
        // direction, not decode_protected (which is hardcoded for uplink).
        let mac_i: [u8; 4] = envelope[1..5].try_into().unwrap();
        let count          = envelope[5] as u32;
        let mut ciphertext = envelope[6..].to_vec();

        let (k_enc, k_int) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        assert!(eia2_verify_mac(&k_int, count, NAS_BEARER, Direction::Downlink, &ciphertext, &mac_i));

        eea2_apply(&k_enc, count, NAS_BEARER, Direction::Downlink, &mut ciphertext);
        assert!(matches!(decode_nas(&ciphertext).unwrap(), NasPdu::DetachAccept));
    }
        }
