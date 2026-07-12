// crates/midn-proto/src/nas5gs/mod.rs
//! NAS-5GS — 5G Non-Access Stratum (3GPP TS 24.501)
//!
//! Structural sibling of `nas` (NAS-EPS, TS 24.301) — carried inside
//! NGAP's `nas_pdu` field the same way NAS-EPS rides inside S1AP's, and
//! reusing the same TLV/LV byte-oriented IE encoding (TS 24.007 §11) rather
//! than NGAP's own ASN.1 PER. See `messages` module doc for the specific
//! deltas from the NAS-EPS message set this mirrors.
//!
//! ## Status
//!
//! `messages` — message shapes only, this increment.
//! `codec`    — wire encode/decode, NOT yet implemented (next increment,
//!              mirrors `nas::codec`'s byte-format pattern).
//! `security` — 5G NAS ciphering/integrity, NOT yet implemented. Reuses
//!              `nas::security`'s EEA2/EIA2 primitives directly (5G's
//!              128-5G-EA2/128-5G-IA2 are the same algorithms, TS 33.501
//!              §5.11 explicitly reuses the TS 33.401 cipher/integrity
//!              set) — only the KAMF → NAS-key KDF differs (TS 33.501
//!              Annex A.8 vs TS 33.401 Annex A.7), and that KDF needs real
//!              spec text before it's implemented, same never-fabricate
//!              policy as `midn-auth`'s TUAK stub and `midn-core`'s Kasme
//!              KDF was built against.

pub mod messages;

pub use messages::{
    AuthenticationRequest, AuthenticationResponse, IdentityResponse, Nas5gsMessage,
    RegistrationAccept, RegistrationRequest, SecurityModeCommand, Suci,
};
