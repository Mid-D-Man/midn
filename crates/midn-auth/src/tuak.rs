// crates/midn-auth/src/tuak.rs
//! TUAK — 3GPP TS 35.231 / 35.232 AKA algorithm set (Keccak-based).
//!
//! ## Status: primitive layer real + tested, TUAK-specific math stubbed
//!
//! Same honesty policy this project already applies to crypto test vectors
//! (see `milenage.rs` test vectors, `midn-proto/src/nas/security.rs`
//! official vector stub) extended one level further: I won't fabricate the
//! TUAK-specific byte-level construction either (TOPC derivation, the
//! per-function domain-separation constants for f1/f1*/f2/f3/f4/f5/f5*, the
//! exact input/output bit-length defaults) and present it as verified when
//! it's actually "best recollection of a spec I don't have open in front of
//! me". Getting an AKA algorithm subtly wrong is worse than not
//! implementing it — it compiles, it round-trips against itself, and it's
//! silently wrong.
//!
//! What IS implemented and trustworthy:
//!   - [`keccak_p`] — the standard Keccak-f[1600] permutation, via the
//!     RustCrypto `keccak` crate (not hand-rolled — same reasoning as using
//!     the `aes` crate for Milenage instead of hand-rolling AES).
//!   - [`sponge`] — the generic Keccak sponge construction (pad10*1
//!     multi-rate padding, absorb, squeeze) on top of that permutation.
//!     Standard Keccak/SHA-3-family plumbing, not TUAK-specific, and
//!     unit-tested for the properties that ARE verifiable without official
//!     test vectors (determinism, input sensitivity, exact output length,
//!     incremental-squeeze-equals-one-shot).
//!
//! What is STUBBED (`todo!()`, `#[ignore]`d tests):
//!   - [`algorithm`] — TOPC derivation and the seven TUAK functions
//!     themselves. Each stub names the exact TS 35.231 section it
//!     implements.
//!
//! ## Next step
//!
//! Send the TS 35.231 §6/§7 algorithm definition (input formatting per
//! function, the domain-separation/instance bytes, output extraction) and
//! `algorithm.rs` gets filled in. TS 35.232 test vectors go straight into
//! the `#[ignore]`-removed tests once that's done, same pattern as
//! `milenage.rs::tests::test_set_1`..`test_set_6`.

pub mod algorithm;
pub mod keccak_p;
pub mod sponge;

pub use algorithm::{TuakAuthVector, TuakConfig, TuakContext, TuakKey, TuakTop, TuakTopc};
