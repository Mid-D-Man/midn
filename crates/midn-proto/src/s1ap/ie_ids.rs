// crates/midn-proto/src/s1ap/ie_ids.rs
//! ProcedureCode / ProtocolIE-ID / Criticality constants — 3GPP TS 36.413.
//!
//! ⚠️ CONFIDENCE LEVELS — read before trusting these against real hardware.
//!
//! These numeric IDs come from memory of the public S1AP ASN.1 module
//! (`S1AP-Constants`), not from a fetched copy of TS 36.413 in this session.
//! Same caution this project already applies to crypto test vectors: I'm not
//! going to dress up "best recollection" as "verified spec fact". Each
//! constant below is tagged with how confident I actually am. A wrong value
//! here is a one-line fix in this file — it doesn't touch the PER bit-packing
//! engine (`per.rs`) or the IE-container framing (`codec.rs`) at all.
//!
//! Before connecting to real RAN equipment: capture a real S1AP exchange
//! (Wireshark dissects it natively) and diff against what this codec
//! produces/expects, starting with the `// UNVERIFIED` entries.

// ── Criticality (S1AP-CommonDataTypes) ───────────────────────────────────────
// Criticality ::= ENUMERATED { reject, ignore, notify } — confident, this
// 3-value enum order is widely and consistently referenced.
pub const CRITICALITY_REJECT: u8 = 0;
pub const CRITICALITY_IGNORE: u8 = 1;
pub const CRITICALITY_NOTIFY: u8 = 2;

// ── ProcedureCode (S1AP-Constants) ────────────────────────────────────────────
// Reasonably confident — these four show up constantly in S1AP material.
pub const PROC_DOWNLINK_NAS_TRANSPORT: u32 = 11;
pub const PROC_INITIAL_UE_MESSAGE: u32 = 12;
pub const PROC_UPLINK_NAS_TRANSPORT: u32 = 13;

// ── ProtocolIE-ID (S1AP-Constants) ────────────────────────────────────────────
// High confidence — MME-UE-S1AP-ID=0 and eNB-UE-S1AP-ID=8 are near-universal
// reference points; NAS-PDU=26 likewise.
pub const ID_MME_UE_S1AP_ID: u32 = 0;
pub const ID_ENB_UE_S1AP_ID: u32 = 8;
pub const ID_NAS_PDU: u32 = 26;

// UNVERIFIED — lower confidence, prioritize checking these against a real
// capture or the actual ASN.1 module before relying on them for interop.
pub const ID_TAI: u32 = 67;
pub const ID_EUTRAN_CGI: u32 = 100;
pub const ID_RRC_ESTABLISHMENT_CAUSE: u32 = 134;

// ── Field range constants ─────────────────────────────────────────────────────
// Real spec types, ranges as commonly documented:
//   ENB-UE-S1AP-ID  INTEGER (0..16777215)   — 24-bit
//   MME-UE-S1AP-ID  INTEGER (0..4294967295) — 32-bit
pub const ENB_UE_S1AP_ID_MAX: u64 = 16_777_215;
pub const MME_UE_S1AP_ID_MAX: u64 = 4_294_967_295;

// RRC-EstablishmentCause is a real ENUMERATED with ~10-12 named values in the
// spec; this codebase models it as a plain `u8` rather than a typed enum, so
// we just give it a generously-sized constrained range (4 bits) rather than
// pretending to enumerate exact cause values we haven't modeled in Rust yet.
pub const RRC_ESTABLISHMENT_CAUSE_MAX: u64 = 15;

// ProtocolIE-ID itself is INTEGER (0..65535) in the real spec.
pub const PROTOCOL_IE_ID_MAX: u64 = 65_535;
// ProcedureCode is INTEGER (0..255).
pub const PROCEDURE_CODE_MAX: u64 = 255;
