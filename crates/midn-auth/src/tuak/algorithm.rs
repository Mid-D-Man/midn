// crates/midn-auth/src/tuak/algorithm.rs
//! TUAK-specific construction — 3GPP TS 35.231 §6 (algorithm definition),
//! TS 35.232 (test data).
//!
//! ## ⚠️ STUBBED — see `tuak` module docs
//!
//! Everything here that would determine actual cryptographic correctness
//! (TOPC derivation, the domain-separation/instance bytes that distinguish
//! f1 from f1* from f2..f5*, the exact input record layout per function,
//! output truncation per the configured KEY/MAC/RES/CK/IK lengths) is
//! `todo!()`. I don't have TS 35.231 open in front of me and won't
//! fabricate these values — same policy this project already applies to
//! crypto test vectors, extended to algorithm-internal constants too.
//!
//! Fill in by sending the relevant TS 35.231 section text. Test vectors
//! (TS 35.232) go into the `#[ignore]`-removed tests at the bottom, same
//! pattern as `milenage.rs::tests::test_set_1..6`.
//!
//! ## Parameter set (TS 35.231 §5 — names recalled with reasonable
//! confidence, values left as caller-supplied fields rather than a
//! hardcoded "default" I'm not sure about)
//!
//! | Field | Typical options |
//! |---|---|
//! | Key length (K, TOP, TOPC) | 128 or 256 bits |
//! | MAC length (MAC-A, MAC-S) | 64, 128, or 256 bits |
//! | RES length | 32, 64, 128, or 256 bits |
//! | CK / IK length | 128 or 256 bits |

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::{Amf, Rand, Sqn};

/// TUAK subscriber key (K). Length depends on [`TuakConfig::key_len_bytes`]
/// (16 or 32 bytes per TS 35.231 §5). Stored as `Vec<u8>` rather than a
/// fixed-size array because the length is configurable, unlike Milenage's
/// fixed 128-bit `AuthKey`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TuakKey(pub Vec<u8>);

/// TUAK operator variant configuration field (TOP) — the TUAK equivalent
/// of Milenage's OP. Same configurable length as [`TuakKey`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TuakTop(pub Vec<u8>);

/// Derived operator variant (TOPC) — the TUAK equivalent of Milenage's OPc.
/// Derivation from (K, TOP) is part of the stubbed construction below.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TuakTopc(pub Vec<u8>);

/// TUAK parameter set — explicit fields, no hardcoded "default" (see
/// module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TuakConfig {
    pub key_len_bytes: usize,
    pub mac_len_bytes: usize,
    pub res_len_bytes: usize,
    pub ck_ik_len_bytes: usize,
}

/// All seven TUAK function outputs for one (RAND, SQN, AMF) triple — same
/// shape as Milenage's [`crate::milenage::AuthVector`], lengths follow
/// [`TuakConfig`] instead of being fixed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TuakAuthVector {
    pub mac_a: Vec<u8>,
    pub mac_s: Vec<u8>,
    pub res: Vec<u8>,
    pub ck: Vec<u8>,
    pub ik: Vec<u8>,
    pub ak: Vec<u8>,
    pub ak_star: Vec<u8>,
}

impl core::fmt::Debug for TuakAuthVector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the actual key material — same redaction pattern as
        // milenage::AuthVector and nas::security::NasSecurityContext.
        f.debug_struct("TuakAuthVector")
            .field("mac_a", &"[REDACTED]")
            .field("mac_s", &"[REDACTED]")
            .field("res", &"[REDACTED]")
            .field("ck", &"[REDACTED]")
            .field("ik", &"[REDACTED]")
            .field("ak", &"[REDACTED]")
            .field("ak_star", &"[REDACTED]")
            .finish()
    }
}

/// Per-subscriber TUAK computation context — mirrors
/// [`crate::milenage::MilenageContext`]'s shape and call pattern so MME/HSS
/// call sites can eventually swap algorithms without reshaping their
/// call pattern.
pub struct TuakContext {
    k: TuakKey,
    topc: TuakTopc,
    config: TuakConfig,
}

impl TuakContext {
    /// Construct from a pre-derived TOPC (mirrors `MilenageContext::new`).
    pub fn new(k: TuakKey, topc: TuakTopc, config: TuakConfig) -> Self {
        Self { k, topc, config }
    }

    /// Construct from raw TOP, deriving TOPC internally (mirrors
    /// `MilenageContext::with_op`).
    ///
    /// STUB: TOPC derivation (TS 35.231 §6, exact subsection not confirmed)
    /// is `todo!()`.
    pub fn with_top(_k: TuakKey, _top: &TuakTop, _config: TuakConfig) -> Self {
        todo!(
            "TS 35.231 TOPC derivation from (K, TOP) via the Keccak sponge — \
             needs the actual spec section for the input record layout and \
             domain-separation byte(s)"
        )
    }

    pub fn config(&self) -> TuakConfig {
        self.config
    }

    /// Full production path — fresh RAND via OS CSPRNG, then TUAK compute.
    /// Mirrors `MilenageContext::generate_vector`'s signature exactly.
    pub fn generate_vector(&self, sqn: Sqn, amf: Amf) -> (Rand, TuakAuthVector) {
        let rand_bytes: [u8; 16] = rand::random();
        let av = self.compute(&rand_bytes, &sqn.to_bytes(), &amf.0);
        (Rand(rand_bytes), av)
    }

    /// Deterministic path — caller-provided RAND. Mirrors
    /// `MilenageContext::generate_vector_with_rand`.
    pub fn generate_vector_with_rand(&self, sqn: Sqn, amf: Amf, rand: Rand) -> TuakAuthVector {
        self.compute(&rand.0, &sqn.to_bytes(), &amf.0)
    }

    /// STUB: the actual f1/f1*/f2/f3/f4/f5/f5* construction.
    ///
    /// TS 35.231 §6 defines each function as a Keccak sponge call over a
    /// specific input record built from: INSTANCE byte, ALGONAME ("TUAK"
    /// in some fixed encoding), K, TOPC, RAND, SQN, AMF, and a per-function
    /// domain-separation constant analogous to Milenage's c1..c5/r1..r5 — I
    /// don't have the exact byte values memorized reliably enough to ship
    /// as correct, so this stays `todo!()`.
    ///
    /// Trustworthy primitive to build this on:
    /// `crate::tuak::sponge::KeccakSponge::absorb_and_squeeze(rate, input, len)`
    fn compute(&self, _rand: &[u8; 16], _sqn: &[u8; 6], _amf: &[u8; 2]) -> TuakAuthVector {
        let _ = (&self.k, &self.topc, self.config); // used once construction is filled in
        todo!(
            "TS 35.231 §6 — f1/f1*/f2/f3/f4/f5/f5* input record construction \
             over the Keccak sponge. Send the spec section and this becomes \
             a straightforward fill-in, same as milenage.rs's original \
             Phase 1 stub."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors `milenage.rs`'s pattern: stays `#[ignore]`d until the actual
    /// TS 35.231 construction lands, then becomes the home for TS 35.232's
    /// official (K, TOP, RAND, SQN, AMF) → (MAC-A, MAC-S, RES, CK, IK, AK,
    /// AK*) test vectors.
    #[test]
    #[ignore = "TS 35.231 algorithm construction not yet implemented — see module docs"]
    fn official_ts35232_test_vectors() {
        todo!()
    }

    #[test]
    fn config_is_plain_data() {
        let cfg = TuakConfig {
            key_len_bytes: 16,
            mac_len_bytes: 8,
            res_len_bytes: 8,
            ck_ik_len_bytes: 16,
        };
        let cfg2 = cfg;
        assert_eq!(cfg, cfg2);
    }
                   }
