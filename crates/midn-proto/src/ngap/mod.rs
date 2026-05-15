// crates/midn-proto/src/ngap/mod.rs
//! NGAP — NG Application Protocol (3GPP TS 38.413)
//!
//! 5G NR equivalent of S1AP. The gNodeB communicates with the AMF
//! via NGAP instead of S1AP. Key differences:
//!   - UE context is called "NG-U" context, not E-RAB
//!   - PDU Sessions replace EPS Bearers
//!   - AMF replaces MME; UPF replaces P-GW/S-GW split
//!
//! ## Phase 3 target
//!
//! Implement after S1AP and MME are stable and tested.
//! Start with Registration, Authentication, and PDU Session Establishment.

pub mod messages;

pub use messages::NgapMessage;
