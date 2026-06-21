// crates/midn-proto/src/s1ap/codec.rs
//! S1AP-PDU PER encoder/decoder — built on `per.rs` + `ie_ids.rs`.
//!
//! ## Scope (this increment)
//!
//! Covers exactly the three messages that currently drive the MME state
//! machine: `InitialUeMessage`, `UplinkNasTransport`, `DownlinkNasTransport`.
//! `InitialContextSetupRequest/Response`, `UeContextRelease*`, `S1Setup*` are
//! NOT yet implemented here — `encode_s1ap_pdu` returns a `MalformedS1ap`
//! error for those variants rather than silently producing wrong bytes.
//! Same phased pattern as everywhere else in this codebase (NAS codec grew
//! the same way: Attach → Auth → SecMode → Detach → security, one increment
//! at a time).
//!
//! ## Wire shape
//!
//! Real S1AP is NOT "PER-encode the Rust struct directly" — it's an
//! IE-container format:
//!
//! ```text
//! S1AP-PDU ::= CHOICE { initiatingMessage, successfulOutcome, unsuccessfulOutcome }
//!   each one ::= SEQUENCE { procedureCode INTEGER(0..255),
//!                           criticality   Criticality,
//!                           value         OPEN TYPE }
//!   value    ::= SEQUENCE { protocolIEs ProtocolIE-Container }
//!   ProtocolIE-Container ::= SEQUENCE (SIZE(1..maxProtocolIEs)) OF ProtocolIE-Field
//!   ProtocolIE-Field ::= SEQUENCE { id ProtocolIE-ID, criticality Criticality, value OPEN TYPE }
//! ```
//!
//! This codec implements that shape. One simplification: the real spec's
//! `SIZE(1..maxProtocolIEs)` constraint on the IE count would, under strict
//! ALIGNED PER, encode as a fixed-width octet-aligned constrained int (since
//! maxProtocolIEs is a large explicit bound). We instead use the generic
//! `write_length_determinant`/`read_length_determinant` for the count — it's
//! internally consistent (round-trips correctly against itself, see tests
//! below) but may not byte-match a real eNodeB's encoding of the count field
//! specifically. If you're diffing against a real capture and everything
//! else matches except the IE count framing, this is the first place to look.
//!
//! All three messages we encode here are S1AP "Class 2" procedures (no
//! response PDU expected), so they're always `initiatingMessage` — the PDU
//! choice index is always written as 0 and not meaningfully branched on
//! decode beyond the procedure-code dispatch.

use bytes::Bytes;

use crate::error::{ProtoError, Result};
use crate::s1ap::ie_ids as ie;
use crate::s1ap::messages::{DownlinkNasTransport, InitialUeMessage, S1apMessage, UplinkNasTransport};
use crate::s1ap::per::{PerReader, PerWriter};

const PDU_CHOICE_INITIATING_MESSAGE: u64 = 0;

type IeEntry = (u32, u8, Vec<u8>);

// ── IE-container framing ──────────────────────────────────────────────────────

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

/// Returns `(procedure_code, criticality, value_bytes)`. The PDU choice
/// index is read (to keep the bit stream correctly positioned) but not
/// returned — see module docs on why it isn't meaningfully branched here.
fn decode_pdu_wrapper(buf: &[u8]) -> Option<(u32, u8, Vec<u8>)> {
    let mut r = PerReader::new(buf);
    let _choice = r.read_constrained_int(0, 2)?;
    let proc = r.read_constrained_int(0, ie::PROCEDURE_CODE_MAX)? as u32;
    let crit = r.read_constrained_int(0, 2)? as u8;
    let val = r.read_octet_string()?;
    Some((proc, crit, val))
}

// ── InitialUeMessage ──────────────────────────────────────────────────────────

pub fn encode_initial_ue_message(msg: &InitialUeMessage) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(5);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.enb_ue_s1ap_id as u64, 0, ie::ENB_UE_S1AP_ID_MAX);
        entries.push((ie::ID_ENB_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octet_string(&msg.nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octets(&msg.tai); // fixed-size, no length prefix needed
        entries.push((ie::ID_TAI, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octets(&msg.eutran_cgi);
        entries.push((ie::ID_EUTRAN_CGI, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.rrc_cause as u64, 0, ie::RRC_ESTABLISHMENT_CAUSE_MAX);
        entries.push((ie::ID_RRC_ESTABLISHMENT_CAUSE, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(ie::PROC_INITIAL_UE_MESSAGE, ie::CRITICALITY_IGNORE, &value_w.into_bytes())
}

fn decode_initial_ue_message(entries: &[IeEntry]) -> Result<S1apMessage> {
    let mut enb_ue_s1ap_id = None;
    let mut nas_pdu = None;
    let mut tai = None;
    let mut eutran_cgi = None;
    let mut rrc_cause = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = r.read_constrained_int(0, ie::ENB_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            x if x == ie::ID_TAI => {
                tai = r.read_octets(5).map(|v| {
                    let mut a = [0u8; 5];
                    a.copy_from_slice(&v);
                    a
                });
            }
            x if x == ie::ID_EUTRAN_CGI => {
                eutran_cgi = r.read_octets(7).map(|v| {
                    let mut a = [0u8; 7];
                    a.copy_from_slice(&v);
                    a
                });
            }
            x if x == ie::ID_RRC_ESTABLISHMENT_CAUSE => {
                rrc_cause = r
                    .read_constrained_int(0, ie::RRC_ESTABLISHMENT_CAUSE_MAX)
                    .map(|v| v as u8);
            }
            _ => {} // unknown IE — ignore, consistent with Criticality::ignore semantics
        }
    }

    Ok(S1apMessage::InitialUeMessage(InitialUeMessage {
        enb_ue_s1ap_id: enb_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing eNB-UE-S1AP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedS1ap { reason: "missing NAS-PDU" })?,
        ),
        tai: tai.ok_or(ProtoError::MalformedS1ap { reason: "missing TAI" })?,
        eutran_cgi: eutran_cgi.ok_or(ProtoError::MalformedS1ap { reason: "missing E-UTRAN CGI" })?,
        rrc_cause: rrc_cause
            .ok_or(ProtoError::MalformedS1ap { reason: "missing RRC-Establishment-Cause" })?,
    }))
}

// ── UplinkNasTransport ────────────────────────────────────────────────────────

pub fn encode_uplink_nas_transport(msg: &UplinkNasTransport) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(5);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.mme_ue_s1ap_id as u64, 0, ie::MME_UE_S1AP_ID_MAX);
        entries.push((ie::ID_MME_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.enb_ue_s1ap_id as u64, 0, ie::ENB_UE_S1AP_ID_MAX);
        entries.push((ie::ID_ENB_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octet_string(&msg.nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octets(&msg.tai);
        entries.push((ie::ID_TAI, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octets(&msg.eutran_cgi);
        entries.push((ie::ID_EUTRAN_CGI, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(ie::PROC_UPLINK_NAS_TRANSPORT, ie::CRITICALITY_IGNORE, &value_w.into_bytes())
}

fn decode_uplink_nas_transport(entries: &[IeEntry]) -> Result<S1apMessage> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut nas_pdu = None;
    let mut tai = None;
    let mut eutran_cgi = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = r.read_constrained_int(0, ie::MME_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = r.read_constrained_int(0, ie::ENB_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            x if x == ie::ID_TAI => {
                tai = r.read_octets(5).map(|v| {
                    let mut a = [0u8; 5];
                    a.copy_from_slice(&v);
                    a
                });
            }
            x if x == ie::ID_EUTRAN_CGI => {
                eutran_cgi = r.read_octets(7).map(|v| {
                    let mut a = [0u8; 7];
                    a.copy_from_slice(&v);
                    a
                });
            }
            _ => {}
        }
    }

    Ok(S1apMessage::UplinkNasTransport(UplinkNasTransport {
        mme_ue_s1ap_id: mme_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing MME-UE-S1AP-ID" })?,
        enb_ue_s1ap_id: enb_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing eNB-UE-S1AP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedS1ap { reason: "missing NAS-PDU" })?,
        ),
        tai: tai.ok_or(ProtoError::MalformedS1ap { reason: "missing TAI" })?,
        eutran_cgi: eutran_cgi.ok_or(ProtoError::MalformedS1ap { reason: "missing E-UTRAN CGI" })?,
    }))
}

// ── DownlinkNasTransport ──────────────────────────────────────────────────────

pub fn encode_downlink_nas_transport(msg: &DownlinkNasTransport) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(3);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.mme_ue_s1ap_id as u64, 0, ie::MME_UE_S1AP_ID_MAX);
        entries.push((ie::ID_MME_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.enb_ue_s1ap_id as u64, 0, ie::ENB_UE_S1AP_ID_MAX);
        entries.push((ie::ID_ENB_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
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

fn decode_downlink_nas_transport(entries: &[IeEntry]) -> Result<S1apMessage> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut nas_pdu = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = r.read_constrained_int(0, ie::MME_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = r.read_constrained_int(0, ie::ENB_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            _ => {}
        }
    }

    Ok(S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
        mme_ue_s1ap_id: mme_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing MME-UE-S1AP-ID" })?,
        enb_ue_s1ap_id: enb_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing eNB-UE-S1AP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedS1ap { reason: "missing NAS-PDU" })?,
        ),
    }))
}

// ── Top-level dispatch ────────────────────────────────────────────────────────

/// Encode an `S1apMessage` to its ALIGNED PER wire bytes.
///
/// Returns `MalformedS1ap` for any variant outside this increment's scope
/// (see module docs) rather than silently producing incorrect bytes.
pub fn encode_s1ap_pdu(msg: &S1apMessage) -> Result<Bytes> {
    match msg {
        S1apMessage::InitialUeMessage(m) => Ok(encode_initial_ue_message(m)),
        S1apMessage::UplinkNasTransport(m) => Ok(encode_uplink_nas_transport(m)),
        S1apMessage::DownlinkNasTransport(m) => Ok(encode_downlink_nas_transport(m)),
        _ => Err(ProtoError::MalformedS1ap {
            reason: "PER encoding not yet implemented for this S1AP message — \
                     only InitialUEMessage/Uplink/DownlinkNASTransport in this increment",
        }),
    }
}

/// Decode raw ALIGNED PER bytes into an `S1apMessage`.
pub fn decode_s1ap_pdu(buf: &[u8]) -> Result<S1apMessage> {
    let (proc_code, _crit, value) = decode_pdu_wrapper(buf)
        .ok_or(ProtoError::MalformedS1ap { reason: "failed to decode PDU wrapper" })?;

    let mut vr = PerReader::new(&value);
    let entries = read_ie_container(&mut vr)
        .ok_or(ProtoError::MalformedS1ap { reason: "failed to decode IE container" })?;

    match proc_code {
        x if x == ie::PROC_INITIAL_UE_MESSAGE => decode_initial_ue_message(&entries),
        x if x == ie::PROC_UPLINK_NAS_TRANSPORT => decode_uplink_nas_transport(&entries),
        x if x == ie::PROC_DOWNLINK_NAS_TRANSPORT => decode_downlink_nas_transport(&entries),
        _ => Err(ProtoError::MalformedS1ap {
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
        let msg = InitialUeMessage {
            enb_ue_s1ap_id: 0x0001_0001,
            nas_pdu: Bytes::from_static(&[0x07, 0x41, 0x00]),
            tai: [0x00, 0x01, 0x02, 0x00, 0x01],
            eutran_cgi: [0x00, 0x01, 0x02, 0x10, 0x20, 0x30, 0x40],
            rrc_cause: 3,
        };

        let bytes = encode_s1ap_pdu(&S1apMessage::InitialUeMessage(msg.clone())).unwrap();
        let decoded = decode_s1ap_pdu(&bytes).unwrap();

        match decoded {
            S1apMessage::InitialUeMessage(d) => {
                assert_eq!(d.enb_ue_s1ap_id, msg.enb_ue_s1ap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
                assert_eq!(d.tai, msg.tai);
                assert_eq!(d.eutran_cgi, msg.eutran_cgi);
                assert_eq!(d.rrc_cause, msg.rrc_cause);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn uplink_nas_transport_round_trip() {
        let msg = UplinkNasTransport {
            mme_ue_s1ap_id: 0xCAFEBABE,
            enb_ue_s1ap_id: 0x0001_0002,
            nas_pdu: Bytes::from_static(&[0x07, 0x53, 0x08, 0xA5, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF]),
            tai: [1, 2, 3, 4, 5],
            eutran_cgi: [9, 8, 7, 6, 5, 4, 3],
        };

        let bytes = encode_s1ap_pdu(&S1apMessage::UplinkNasTransport(msg.clone())).unwrap();
        let decoded = decode_s1ap_pdu(&bytes).unwrap();

        match decoded {
            S1apMessage::UplinkNasTransport(d) => {
                assert_eq!(d.mme_ue_s1ap_id, msg.mme_ue_s1ap_id);
                assert_eq!(d.enb_ue_s1ap_id, msg.enb_ue_s1ap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
                assert_eq!(d.tai, msg.tai);
                assert_eq!(d.eutran_cgi, msg.eutran_cgi);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn downlink_nas_transport_round_trip() {
        let msg = DownlinkNasTransport {
            mme_ue_s1ap_id: 42,
            enb_ue_s1ap_id: 7,
            nas_pdu: Bytes::from_static(&[0x07, 0x5D, 0x24, 0x70]),
        };

        let bytes = encode_s1ap_pdu(&S1apMessage::DownlinkNasTransport(msg.clone())).unwrap();
        let decoded = decode_s1ap_pdu(&bytes).unwrap();

        match decoded {
            S1apMessage::DownlinkNasTransport(d) => {
                assert_eq!(d.mme_ue_s1ap_id, msg.mme_ue_s1ap_id);
                assert_eq!(d.enb_ue_s1ap_id, msg.enb_ue_s1ap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn unsupported_variant_returns_error_not_garbage() {
        let result = encode_s1ap_pdu(&S1apMessage::UeContextReleaseCommand {
            cause: crate::s1ap::messages::S1apCause::NasNormalRelease,
        });
        assert!(result.is_err(), "out-of-scope variants must error, not silently mis-encode");
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        assert!(decode_s1ap_pdu(&[0x00]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_procedure_code() {
        // Hand-build a PDU wrapper with a bogus procedure code (250) and an
        // empty IE container, to confirm the dispatcher actually checks it.
        let mut value_w = PerWriter::new();
        write_ie_container(&mut value_w, &[]);
        let bytes = encode_pdu_wrapper(250, ie::CRITICALITY_IGNORE, &value_w.into_bytes());
        assert!(decode_s1ap_pdu(&bytes).is_err());
    }
}
