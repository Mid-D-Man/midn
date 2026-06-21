// crates/midn-auth/src/lib.rs
//! midn-auth — Milenage / TUAK AKA authentication.
//!
//! Primary exports:
//!   - [`AuthKey`]       — 128-bit subscriber key K (Milenage)
//!   - [`OpCode`]        — 128-bit OPc = OP ⊕ E_K(OP) (Milenage)
//!   - [`AuthVector`]    — All seven Milenage outputs (f1/f1*/f2/f3/f4/f5/f5*)
//!   - [`MilenageContext`] — Per-subscriber Milenage computation context
//!   - [`tuak`]          — TUAK algorithm set (Keccak-based). Primitive
//!     layer (Keccak-f[1600] + sponge) is real and tested; the TUAK-specific
//!     construction is stubbed pending the actual TS 35.231 spec text —
//!     see `tuak` module docs.

pub mod ffi;
pub mod keys;
pub mod milenage;
pub mod tuak;

// Re-export at crate root so midn_auth::AuthVector and
// midn_auth::milenage::AuthVector resolve to the same type.
// Without this, HssAuthInfo.vector (typed midn_auth::AuthVector) and
// generate_vector's return (midn_auth::milenage::AuthVector) are distinct.
pub use keys::{AuthKey, OpCode};
pub use milenage::{AuthVector, MilenageContext};
