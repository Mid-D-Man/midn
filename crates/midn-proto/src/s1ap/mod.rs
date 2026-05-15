// crates/midn-proto/src/s1ap/mod.rs
//! S1AP — S1 Application Protocol (3GPP TS 36.413)
//!
//! Control plane between the eNodeB (LTE base station) and the MME.
//! Transported over SCTP (Stream Control Transmission Protocol) for
//! reliability and multi-streaming.
//!
//! ## Key procedures
//!
//! - **S1 Setup**: eNodeB registers with MME on startup
//! - **Initial UE**: eNodeB forwards first NAS PDU from new UE
//! - **Downlink/Uplink NAS Transport**: ongoing NAS message relay
//! - **Initial Context Setup**: MME tells eNodeB to establish radio bearer
//! - **UE Context Release**: bearer teardown on detach/handover
//!
//! ## Encoding
//!
//! S1AP uses ASN.1 PER (Packed Encoding Rules). Full ASN.1 parsing
//! is a Phase 2 target. Initial implementation uses hand-rolled
//! encoding for the critical path messages.

pub mod messages;

pub use messages::S1apMessage;
