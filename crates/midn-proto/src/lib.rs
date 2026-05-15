//! midn-proto — LTE/5G protocol stack
//!
//! Implements the signaling and data plane protocols:
//!   NAS  — Non-Access Stratum (UE ↔ MME/AMF)
//!   S1AP — eNodeB control plane interface (LTE)
//!   NGAP — gNodeB control plane interface (5G NR)
//!   GTP-U — User plane tunneling protocol

pub mod nas;
pub mod s1ap;
pub mod ngap;
pub mod gtp;

pub use nas::NasMessage;
pub use gtp::GtpuHeader;
