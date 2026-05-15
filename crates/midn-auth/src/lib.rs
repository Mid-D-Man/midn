//! midn-auth — Subscriber authentication for LTE/5G
//!
//! Implements Milenage (3GPP TS 35.206) and TUAK (3GPP TS 35.231)
//! authentication algorithms for the AKA (Authentication and Key Agreement)
//! procedure.
//!
//! SECURITY: All secret material (Ki, OPc) is wrapped in Zeroize types.
//! All comparisons use constant-time operations via the subtle crate.

pub mod milenage;
pub mod tuak;
pub mod keys;
pub mod ffi;

pub use keys::{AuthKey, AuthVector, OpCode, Plmn, Rand, Sqn};
pub use milenage::MilenageContext;
