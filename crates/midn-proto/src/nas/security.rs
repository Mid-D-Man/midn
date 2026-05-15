// crates/midn-proto/src/nas/security.rs
//! NAS security — ciphering and integrity protection.
//!
//! ## Ciphering algorithms (EEA)
//!   EEA0 — null cipher (no encryption, for emergency calls)
//!   EEA1 — SNOW 3G based (128-bit key)
//!   EEA2 — AES-CTR based (128-bit key)  ← recommended
//!   EEA3 — ZUC based (128-bit key)
//!
//! ## Integrity algorithms (EIA)
//!   EIA0 — null integrity (forbidden for normal NAS)
//!   EIA1 — SNOW 3G based CMAC
//!   EIA2 — AES-CMAC (128-bit key)  ← recommended
//!   EIA3 — ZUC based MAC
//!
//! ## Phase 2 target
//!
//! Implement EEA2 (AES-CTR) and EIA2 (AES-CMAC) as the default pair.
//! These are the mandatory algorithms in LTE and most common in practice.
//!
//! Reference: 3GPP TS 33.401 Section 5.1.3
//!            ETSI TS 135 202 (SNOW 3G spec)

// Auto-generated stub — Phase 2 target
