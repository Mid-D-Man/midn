// crates/midn-core/src/amf/mod.rs
//! AMF — Access and Mobility Function (3GPP TS 23.501 / 38.413)
//!
//! 5G NR counterpart to the LTE MME. Communicates with gNodeBs via NGAP.
//!
//! Key differences from MME:
//!   - Registration replaces Attach (more lightweight)
//!   - PDU Sessions replace EPS Bearers (more flexible QoS)
//!   - AUSF/UDM replace HSS (separated in real 5G; collapsed into one `Hss`
//!     here — see `registration` module doc's "AUSF/UDM simplification")
//!   - SMF handles session management (split from AMF)
//!
//! ## Status
//!
//! `registration` — 5G Registration procedure, Phase A: full flow through
//! RegistrationComplete, real 5G-AKA (Milenage via `Hss` + the TS 33.501
//! Annex A KAUSF/KSEAF/KAMF chain in `midn_core::kdf`), real NAS security
//! activation. No PDU Session Establishment, no TEID/UPF interaction, no
//! `InitialContextSetupRequest` — see `registration` module doc's
//! "Phase A vs Phase B" for exactly why and what Phase B adds.

pub mod registration;
pub mod state_machine;

pub use state_machine::Amf;
