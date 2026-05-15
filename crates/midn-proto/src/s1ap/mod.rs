//! S1AP — S1 Application Protocol
//!
//! Control plane between eNodeB (LTE base station) and MME.
//! Based on 3GPP TS 36.413. Uses ASN.1 PER encoding.

pub mod messages;

pub use messages::S1apMessage;
