//! AMF — Access and Mobility Function (5G NR)
//!
//! 5G counterpart to the LTE MME. Communicates with gNodeB via NGAP.
//! Priority 3 — implement after MME is stable.

pub mod state_machine;
pub mod registration;

pub use state_machine::Amf;
