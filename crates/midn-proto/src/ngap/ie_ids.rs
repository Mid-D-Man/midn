// crates/midn-proto/src/ngap/ie_ids.rs
//! ProcedureCode / ProtocolIE-ID / Criticality constants — 3GPP TS 38.413.
//!
//! ⚠️ CONFIDENCE LEVELS — read before trusting these against a real gNB.
//!
//! Same policy as `s1ap::ie_ids`: these come from memory of the public NGAP
//! ASN.1 module (`NGAP-Constants`), not a fetched copy of TS 38.413 in this
//! session. **Overall confidence here is LOWER than the S1AP file** — S1AP's
//! most commonly-used IE-IDs (MME-UE-S1AP-ID=0, eNB-UE-S1AP-ID=8, NAS-PDU=26)
//! show up constantly enough in public material that recalling them
//! correctly is fairly reliable. NGAP's equivalents are less universally
//! quoted, so treat every constant below as "best recollection, unverified"
//! rather than picking out a confident subset the way the S1AP file does.
//! A wrong value here is a one-line fix — it doesn't touch the shared PER
//! engine (`crate::per`) or the IE-container framing (`codec.rs`) at all.
//!
//! Before connecting to real gNB equipment: capture a real NGAP exchange
//! (Wireshark dissects it) and diff against what this codec produces/expects.
//!
//! ## Known structural simplification: bundled UserLocationInformation
//!
//! Real NGAP conveys TAI + NR-CGI together inside a single
//! `UserLocationInformation` IE (a CHOICE, with the NR branch being
//! `UserLocationInformationNR { nrCGI, tai, ... }`) — NOT as two independent
//! top-level ProtocolIE-Field entries the way S1AP keeps TAI and E-UTRAN-CGI
//! separate. This codec models that bundling: `ID_USER_LOCATION_INFO` covers
//! one IE whose value is `nr_cgi (9 bytes) || tai (6 bytes)` concatenated,
//! written/read together in `codec.rs`. This is closer to the real wire
//! shape than pretending they're separate IEs, but the exact field order and
//! any CHOICE-tag framing inside `UserLocationInformationNR` itself is not
//! modeled — this is still a simplification, not a byte-exact rendering of
//! that IE. Flag if diffing against a real capture.

// ── Criticality (NGAP-CommonDataTypes) ───────────────────────────────────────
// Criticality ::= ENUMERATED { reject, ignore, notify } — same generic ASN.1
// pattern as S1AP (and X2AP); confident this 3-value order is consistent
// across the sibling protocols.
pub const CRITICALITY_REJECT: u8 = 0;
pub const CRITICALITY_IGNORE: u8 = 1;
pub const CRITICALITY_NOTIFY: u8 = 2;

// ── ProcedureCode (NGAP-Constants) ────────────────────────────────────────────
// UNVERIFIED — best recollection only, see module doc.
pub const PROC_DOWNLINK_NAS_TRANSPORT: u32 = 4;
pub const PROC_INITIAL_UE_MESSAGE: u32 = 15;
pub const PROC_UPLINK_NAS_TRANSPORT: u32 = 46;

// ── ProtocolIE-ID (NGAP-Constants) ────────────────────────────────────────────
// UNVERIFIED — best recollection only, see module doc.
pub const ID_AMF_UE_NGAP_ID: u32 = 10;
pub const ID_RAN_UE_NGAP_ID: u32 = 85;
pub const ID_NAS_PDU: u32 = 38;
/// Bundled TAI+NR-CGI — see module doc "Known structural simplification".
pub const ID_USER_LOCATION_INFO: u32 = 121;
pub const ID_RRC_ESTABLISHMENT_CAUSE: u32 = 90;

// ── Field range constants ─────────────────────────────────────────────────────
// Real spec types, ranges as commonly documented:
//   RAN-UE-NGAP-ID  INTEGER (0..4294967295) — full 32-bit (NGAP widened this
//                    relative to S1AP's 24-bit ENB-UE-S1AP-ID — moderate
//                    confidence this widening is real, it's a commonly-cited
//                    4G→5G NGAP delta, but unverified against spec text here)
//   AMF-UE-NGAP-ID  INTEGER (0..4294967295) — full 32-bit, same as S1AP's
//                    MME-UE-S1AP-ID range.
pub const RAN_UE_NGAP_ID_MAX: u64 = 4_294_967_295;
pub const AMF_UE_NGAP_ID_MAX: u64 = 4_294_967_295;

// RRCEstablishmentCause modeled the same simplified way as S1AP's
// RRC-EstablishmentCause: a plain constrained range rather than a typed
// enum of the ~10-12 named cause values in the real spec.
pub const RRC_ESTABLISHMENT_CAUSE_MAX: u64 = 15;

// ProtocolIE-ID itself is INTEGER (0..65535) in the real spec — same generic
// range as S1AP, this part isn't NGAP-specific.
pub const PROTOCOL_IE_ID_MAX: u64 = 65_535;
// ProcedureCode is INTEGER (0..255) — same generic range as S1AP.
pub const PROCEDURE_CODE_MAX: u64 = 255;
