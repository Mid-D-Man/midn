// crates/midn-proto/src/nas/mod.rs
//! NAS — Non-Access Stratum (3GPP TS 24.301 / 24.501)
//!
//! The signaling protocol between the UE and the MME (LTE) or AMF (5G).
//! NAS messages are transported inside S1AP / NGAP as opaque PDUs —
//! the base station never looks inside them.
//!
//! ## LTE message flow (simplified)
//!
//! ```text
//! UE → MME  : AttachRequest
//! MME → UE  : AuthenticationRequest   (RAND + AUTN from Milenage)
//! UE → MME  : AuthenticationResponse  (RES)
//! MME → UE  : SecurityModeCommand     (algorithm selection)
//! UE → MME  : SecurityModeComplete
//! MME → UE  : AttachAccept            (GUTI + IP)
//! UE → MME  : AttachComplete
//! ```

pub mod messages;
pub mod security;

pub use messages::NasMessage;
