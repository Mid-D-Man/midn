// crates/midn-core/src/amf/mod.rs
//! AMF — Access and Mobility Function (3GPP TS 23.501 / 38.413)
//!
//! 5G NR counterpart to the LTE MME. Communicates with gNodeBs via NGAP.
//!
//! Key differences from MME:
//!   - Registration replaces Attach (more lightweight)
//!   - PDU Sessions replace EPS Bearers (more flexible QoS)
//!   - AUSF/UDM replace HSS (separated auth and subscriber data)
//!   - SMF handles session management (split from AMF)
//!
//! ## Phase 3 target
//!
//! Implement 5G Registration and PDU Session Establishment after
//! the LTE MME attach procedure is complete and tested.

pub mod registration;
pub mod state_machine;

pub use state_machine::Amf;
