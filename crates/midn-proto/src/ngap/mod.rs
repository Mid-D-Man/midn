//! NGAP — NG Application Protocol
//!
//! Control plane between gNodeB (5G NR) and AMF.
//! Based on 3GPP TS 38.413.
//! Priority 3 — implement after S1AP is stable.

pub mod messages;

pub use messages::NgapMessage;
