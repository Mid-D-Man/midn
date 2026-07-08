// crates/midn-proto/src/ngap/codec.rs
//! NGAP-PDU PER encoder/decoder — built on `crate::per` + `ie_ids.rs`.
//!
//! Structurally identical to `s1ap::codec` — same PDU-wrapper shape, same
//! IE-container framing, same simplifications (see below) — because NGAP
//! and S1AP share the same underlying ALIGNED PER transport conventions.
//! If you're comparing the two files side by side, that similarity is
//! intentional, not copy-paste drift.
//!
//! ## Scope (this increment)
//!
//! Covers exactly the three messages that will drive the AMF state machine,
//! same set S1AP started with: `InitialUeMessage`, `UplinkNasTransport`,
//! `DownlinkNasTransport`. `InitialContextSetupRequest/Response`,
//! `UeContextRelease*`, `NgSetup*`, `PduSessionResourceSetup*` are NOT yet
//! implemented here — `encode_ngap_pdu` returns a `MalformedNgap` error for
//! those variants rather than silently producing wrong bytes.
//!
//! ## Wire shape
//!
//! ```text
//! NGAP-PDU ::= CHOICE { initiatingMessage, successfulOutcome, unsuccessfulOutcome }
//!   each one ::= SEQUENCE { procedureCode INTEGER(0..255),
//!                           criticality   Criticality,
//!                           value         OPEN TYPE }
//!   value    ::= SEQUENCE { protocolIEs ProtocolIE-Container }
//!   ProtocolIE-Container ::= SEQUENCE (SIZE(1..maxProtocolIEs)) OF ProtocolIE-Field
//!   ProtocolIE-Field ::= SEQUENCE { id ProtocolIE-ID, criticality Criticality, value OPEN TYPE }
//! ```
//!
//! Same simplification as `s1ap::codec` on the IE count field: real ALIGNED
//! PER would encode `SIZE(1..maxProtocolIEs)` as a fixed-width octet-aligned
//! constrained int; this uses the generic length-determinant instead. It's
//! internally consistent (round-trips against itself) but may not
//! byte-match a real gNB's framing of the count specifically.
//!
//! All three messages here are NGAP "Class 2" procedures (no response PDU
//! expected), so they're always `initiatingMessage` — same as S1AP's
//! equivalent trio — the PDU choice index is always written as 0.
//!
//! ## TAI + NR-CGI bundling
//!
//! `InitialUeMessage` and `UplinkNasTransport` both carry `tai` and
//! `nr_cgi` bundled into a single `ID_USER_LOCATION_INFO` IE — see
//! `ie_ids` module doc "Known structural simplification" for why, and
//! `write_user_location_info`/`read_user_location_info` below for the
//! concatenation order (`nr_cgi (9 bytes) || tai (6 bytes)`).

use bytes::Bytes;

use crate::error::{ProtoError, Result};
use crate::ngap::ie_ids as ie;
use crate::ngap::messages::{
    NgapDownlinkNasTransport, NgapInitialUeMessage, NgapMessage, NgapUplinkNasTransport,
};
use crate::per::{PerReader, PerWriter};

const PDU_CHOICE_INITIATING_MESSAGE: u64 = 0;

type IeEntry = (u32, u8, Vec<u8>);

// ── IE-container framing ──────────────────────────────────────────────────────
// Identical shape to s1ap::codec's — see that file's version for the fuller
// explanation of the count-field simplification.

fn write_ie_container(w: &mut PerWriter, entries: &[IeEntry]) {
    w.write_length_determinant(entries.len());
    for (id, crit, val) in entries {
        w.write_constrained_int(*id as u64, 0, ie::PROTOCOL_IE_ID_MAX);
        w.write_constrained_int(*crit as u64, 0, 2);
        w.write_octet_string(val);
    }
}

fn read_ie_container(r: &mut PerReader) -> Option<Vec<IeEntry>> {
    let count = r.read_length_determinant()?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let id = r.read_constrained_int(0, ie::PROTOCOL_IE_ID_MAX)? as u32;
        let crit = r.read_constrained_int(0, 2)? as u8;
        let val = r.read_octet_string()?;
        out.push((id, crit, val));
    }
    Some(out)
}

// ── PDU wrapper (choice + procedureCode + criticality + OPEN TYPE value) ─────

fn encode_pdu_wrapper(procedure_code: u32, criticality: u8, value_bytes: &[u8]) -> Bytes {
    let mut w = PerWriter::new();
    w.write_constrained_int(PDU_CHOICE_INITIATING_MESSAGE, 0, 2);
    w.write_constrained_int(procedure_code as u64, 0, ie::PROCEDURE_CODE_MAX);
    w.write_constrained_int(criticality as u64, 0, 2);
    w.write_octet_string(value_bytes);
    Bytes::from(w.into_bytes())
}

/// Returns `(procedure_code, criticality, value_bytes)`. Same non-branching
/// treatment of the PDU choice index as `s1ap::codec` — see that file.
fn decode_pdu_wrapper(buf: &[u8]) -> Option<(u32, u8, Vec<u8>)> {
    let mut r = PerReader::new(buf);
    let _choice = r.read_constrained_int(0, 2)?;
    let proc = r.read_constrained_int(0, ie::PROCEDURE_CODE_MAX)? as u32;
    let crit = r.read_constrained_int(0, 2)? as u8;
    let val = r.read_octet_string()?;
    Some((proc, crit, val))
}

// ── Bundled TAI + NR-CGI helper ───────────────────────────────────────────────
// See ie_ids module doc "Known structural simplification" and this file's
// module doc "TAI + NR-CGI bundling".

fn write_user_location_info(w: &mut PerWriter, nr_cgi: &[u8; 9], tai: &[u8; 6]) {
    w.write_octets(nr_cgi);
    w.write_octets(tai);
}

fn read_user_location_info(r: &mut PerReader) -> Option<([u8; 9], [u8; 6])> {
    let cgi_v = r.read_octets(9)?;
    let tai_v = r.read_octets(6)?;
    let mut nr_cgi = [0u8; 9];
    let mut tai = [0u8; 6];
    nr_cgi.copy_from_slice(&cgi_v);
    tai.copy_from_slice(&tai_v);
    Some((nr_cgi, tai))
}

// ── InitialUeMessage ──────────────────────────────────────────────────────────

pub fn encode_initial_ue_message(msg: &NgapInitialUeMessage) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(4);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.ran_ue_ngap_id as u64, 0, ie::RAN_UE_NGAP_ID_MAX);
        entries.push((ie::ID_RAN_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octet_string(&msg.nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        write_user_location_info(&mut w, &msg.nr_cgi, &msg.tai);
        entries.push((ie::ID_USER_LOCATION_INFO, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(
            msg.rrc_establishment_cause as u64,
            0,
            ie::RRC_ESTABLISHMENT_CAUSE_MAX,
        );
        entries.push((ie::ID_RRC_ESTABLISHMENT_CAUSE, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(ie::PROC_INITIAL_UE_MESSAGE, ie::CRITICALITY_IGNORE, &value_w.into_bytes())
}

fn decode_initial_ue_message(entries: &[IeEntry]) -> Result<NgapMessage> {
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;
    let mut location = None;
    let mut rrc_cause = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = r.read_constrained_int(0, ie::RAN_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            x if x == ie::ID_USER_LOCATION_INFO => {
                location = read_user_location_info(&mut r);
            }
            x if x == ie::ID_RRC_ESTABLISHMENT_CAUSE => {
                rrc_cause = r
                    .read_constrained_int(0, ie::RRC_ESTABLISHMENT_CAUSE_MAX)
                    .map(|v| v as u8);
            }
            _ => {} // unknown IE — ignore, consistent with Criticality::ignore semantics
        }
    }

    let (nr_cgi, tai) =
        location.ok_or(ProtoError::MalformedNgap { reason: "missing UserLocationInformation" })?;

    Ok(NgapMessage::InitialUeMessage(NgapInitialUeMessage {
        ran_ue_ngap_id: ran_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing RAN-UE-NGAP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedNgap { reason: "missing NAS-PDU" })?,
        ),
        tai,
        nr_cgi,
        rrc_establishment_cause: rrc_cause
            .ok_or(ProtoError::MalformedNgap { reason: "missing RRCEstablishmentCause" })?,
    }))
}

// ── UplinkNasTransport ────────────────────────────────────────────────────────

pub fn encode_uplink_nas_transport(msg: &NgapUplinkNasTransport) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(4);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.amf_ue_ngap_id as u64, 0, ie::AMF_UE_NGAP_ID_MAX);
        entries.push((ie::ID_AMF_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.ran_ue_ngap_id as u64, 0, ie::RAN_UE_NGAP_ID_MAX);
        entries.push((ie::ID_RAN_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octet_string(&msg.nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        write_user_location_info(&mut w, &msg.nr_cgi, &msg.tai);
        entries.push((ie::ID_USER_LOCATION_INFO, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(ie::PROC_UPLINK_NAS_TRANSPORT, ie::CRITICALITY_IGNORE, &value_w.into_bytes())
}

fn decode_uplink_nas_transport(entries: &[IeEntry]) -> Result<NgapMessage> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;
    let mut location = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = r.read_constrained_int(0, ie::AMF_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = r.read_constrained_int(0, ie::RAN_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            x if x == ie::ID_USER_LOCATION_INFO => {
                location = read_user_location_info(&mut r);
            }
            _ => {}
        }
    }

    let (nr_cgi, tai) =
        location.ok_or(ProtoError::MalformedNgap { reason: "missing UserLocationInformation" })?;

    Ok(NgapMessage::UplinkNasTransport(NgapUplinkNasTransport {
        amf_ue_ngap_id: amf_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing AMF-UE-NGAP-ID" })?,
        ran_ue_ngap_id: ran_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing RAN-UE-NGAP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedNgap { reason: "missing NAS-PDU" })?,
        ),
        tai,
        nr_cgi,
    }))
}

// ── DownlinkNasTransport ──────────────────────────────────────────────────────

pub fn encode_downlink_nas_transport(msg: &NgapDownlinkNasTransport) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(3);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.amf_ue_ngap_id as u64, 0, ie::AMF_UE_NGAP_ID_MAX);
        entries.push((ie::ID_AMF_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.ran_ue_ngap_id as u64, 0, ie::RAN_UE_NGAP_ID_MAX);
        entries.push((ie::ID_RAN_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octet_string(&msg.nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(ie::PROC_DOWNLINK_NAS_TRANSPORT, ie::CRITICALITY_IGNORE, &value_w.into_bytes())
}

fn decode_downlink_nas_transport(entries: &[IeEntry]) -> Result<NgapMessage> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = r.read_constrained_int(0, ie::AMF_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = r.read_constrained_int(0, ie::RAN_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            _ => {}
        }
    }

    Ok(NgapMessage::DownlinkNasTransport(NgapDownlinkNasTransport {
        amf_ue_ngap_id: amf_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing AMF-UE-NGAP-ID" })?,
        ran_ue_ngap_id: ran_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing RAN-UE-NGAP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedNgap { reason: "missing NAS-PDU" })?,
        ),
    }))
}

// ── Top-level dispatch ────────────────────────────────────────────────────────

/// Encode an `NgapMessage` to its ALIGNED PER wire bytes.
///
/// Returns `MalformedNgap` for any variant outside this increment's scope
/// (see module docs) rather than silently producing incorrect bytes.
pub fn encode_ngap_pdu(msg: &NgapMessage) -> Result<Bytes> {
    match msg {
        NgapMessage::InitialUeMessage(m) => Ok(encode_initial_ue_message(m)),
        NgapMessage::UplinkNasTransport(m) => Ok(encode_uplink_nas_transport(m)),
        NgapMessage::DownlinkNasTransport(m) => Ok(encode_downlink_nas_transport(m)),
        _ => Err(ProtoError::MalformedNgap {
            reason: "PER encoding not yet implemented for this NGAP message — \
                     only InitialUEMessage/Uplink/DownlinkNASTransport in this increment",
        }),
    }
}

/// Decode raw ALIGNED PER bytes into an `NgapMessage`.
pub fn decode_ngap_pdu(buf: &[u8]) -> Result<NgapMessage> {
    let (proc_code, _crit, value) = decode_pdu_wrapper(buf)
        .ok_or(ProtoError::MalformedNgap { reason: "failed to decode PDU wrapper" })?;

    let mut vr = PerReader::new(&value);
    let entries = read_ie_container(&mut vr)
        .ok_or(ProtoError::MalformedNgap { reason: "failed to decode IE container" })?;

    match proc_code {
        x if x == ie::PROC_INITIAL_UE_MESSAGE => decode_initial_ue_message(&entries),
        x if x == ie::PROC_UPLINK_NAS_TRANSPORT => decode_uplink_nas_transport(&entries),
        x if x == ie::PROC_DOWNLINK_NAS_TRANSPORT => decode_downlink_nas_transport(&entries),
        _ => Err(ProtoError::MalformedNgap {
            reason: "unsupported procedure code — only InitialUEMessage/Uplink/DownlinkNASTransport in this increment",
        }),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_ue_message_round_trip() {
        let msg = NgapInitialUeMessage {
            ran_ue_ngap_id: 0x0001_0001,
            nas_pdu: Bytes::from_static(&[0x7E, 0x00, 0x41]),
            tai: [0x00, 0x01, 0x02, 0x00, 0x00, 0x01],
            nr_cgi: [0x00, 0x01, 0x02, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            rrc_establishment_cause: 3,
        };

        let bytes = encode_ngap_pdu(&NgapMessage::InitialUeMessage(msg.clone())).unwrap();
        let decoded = decode_ngap_pdu(&bytes).unwrap();

        match decoded {
            NgapMessage::InitialUeMessage(d) => {
                assert_eq!(d.ran_ue_ngap_id, msg.ran_ue_ngap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
                assert_eq!(d.tai, msg.tai);
                assert_eq!(d.nr_cgi, msg.nr_cgi);
                assert_eq!(d.rrc_establishment_cause, msg.rrc_establishment_cause);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn uplink_nas_transport_round_trip() {
        let msg = NgapUplinkNasTransport {
            amf_ue_ngap_id: 0xCAFEBABE,
            ran_ue_ngap_id: 0x0001_0002,
            nas_pdu: Bytes::from_static(&[0x7E, 0x02, 0x08, 0xA5, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF]),
            tai: [1, 2, 3, 0, 0, 4],
            nr_cgi: [9, 8, 7, 6, 5, 4, 3, 2, 1],
        };

        let bytes = encode_ngap_pdu(&NgapMessage::UplinkNasTransport(msg.clone())).unwrap();
        let decoded = decode_ngap_pdu(&bytes).unwrap();

        match decoded {
            NgapMessage::UplinkNasTransport(d) => {
                assert_eq!(d.amf_ue_ngap_id, msg.amf_ue_ngap_id);
                assert_eq!(d.ran_ue_ngap_id, msg.ran_ue_ngap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
                assert_eq!(d.tai, msg.tai);
                assert_eq!(d.nr_cgi, msg.nr_cgi);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn downlink_nas_transport_round_trip() {
        let msg = NgapDownlinkNasTransport {
            amf_ue_ngap_id: 42,
            ran_ue_ngap_id: 7,
            nas_pdu: Bytes::from_static(&[0x7E, 0x00, 0x42, 0x01]),
        };

        let bytes = encode_ngap_pdu(&NgapMessage::DownlinkNasTransport(msg.clone())).unwrap();
        let decoded = decode_ngap_pdu(&bytes).unwrap();

        match decoded {
            NgapMessage::DownlinkNasTransport(d) => {
                assert_eq!(d.amf_ue_ngap_id, msg.amf_ue_ngap_id);
                assert_eq!(d.ran_ue_ngap_id, msg.ran_ue_ngap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn unsupported_variant_returns_error_not_garbage() {
        let result = encode_ngap_pdu(&NgapMessage::UeContextReleaseCommand {
            cause: crate::ngap::messages::NgapCause::NasNormalRelease,
        });
        assert!(result.is_err(), "out-of-scope variants must error, not silently mis-encode");
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        assert!(decode_ngap_pdu(&[0x00]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_procedure_code() {
        let mut value_w = PerWriter::new();
        write_ie_container(&mut value_w, &[]);
        let bytes = encode_pdu_wrapper(250, ie::CRITICALITY_IGNORE, &value_w.into_bytes());
        assert!(decode_ngap_pdu(&bytes).is_err());
    }

    #[test]
    fn user_location_info_round_trip() {
        let mut w = PerWriter::new();
        let nr_cgi = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        let tai = [10u8, 11, 12, 13, 14, 15];
        write_user_location_info(&mut w, &nr_cgi, &tai);
        let bytes = w.into_bytes();
        let mut r = PerReader::new(&bytes);
        let (d_cgi, d_tai) = read_user_location_info(&mut r).unwrap();
        assert_eq!(d_cgi, nr_cgi);
        assert_eq!(d_tai, tai);
    }
  }
