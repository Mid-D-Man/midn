//! NAS — Non-Access Stratum
//!
//! The signaling protocol between UE and MME (LTE) or AMF (5G).
//! Handles Attach, Authentication, Security Mode, PDN Connectivity.

pub mod messages;
pub mod security;

pub use messages::NasMessage;
