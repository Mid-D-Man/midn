// crates/midn-auth/src/milenage.rs
//! Milenage authentication algorithm — 3GPP TS 35.205 / 35.206
//!
//! Milenage is the default 3GPP authentication algorithm, built on
//! AES-128 as a pseudorandom function. It produces five outputs:
//!
//!   f1  → MAC-A (8 bytes): network authentication token
//!   f2  → RES   (8 bytes): expected UE response
//!   f3  → CK    (16 bytes): cipher key
//!   f4  → IK    (16 bytes): integrity key
//!   f5  → AK    (6 bytes): anonymity key (hides SQN in AUTN)
//!   f1* → MAC-S (8 bytes): re-sync MAC
//!   f5* → AK*   (6 bytes): re-sync anonymity key
//!
//! ## Phase 1 target
//!
//! Implement f1..f5 and validate against all 3GPP TS 35.207 test sets.
//! Performance target: < 10 µs per auth vector (Criterion bench).
//!
//! ## Implementation note
//!
//! Use the `aes` crate (with the `zeroize` feature) for the AES-128 core.
//! Add to Cargo.toml:
//!   aes = { version = "0.8", features = ["zeroize"] }
//!
//! The operator constant OP is pre-processed into OPc once at setup time:
//!   OPc = AES_Ki(OP) XOR OP
//! This avoids repeated computation and allows OPc to be stored instead of OP.

use subtle::ConstantTimeEq;
use crate::keys::{Amf, AuthKey, AuthVector, OpCode, Rand, Sqn};

/// Milenage AKA context bound to a single subscriber (Ki + OPc).
///
/// Create one per subscriber in the HSS/UDM. Reuse across multiple
/// `generate_vector` calls (one per authentication attempt).
pub struct MilenageContext {
    ki:  AuthKey,
    opc: OpCode,
}

impl MilenageContext {
    /// Bind to a subscriber's Ki and OPc.
    ///
    /// Both are cloned in — the originals may be dropped after construction.
    pub fn new(ki: AuthKey, opc: OpCode) -> Self {
        Self { ki, opc }
    }

    /// Generate a complete authentication vector for one AKA round.
    ///
    /// # Arguments
    /// * `sqn` — current sequence number (monotonically increasing)
    /// * `amf` — operator AMF field (use `Amf::STANDARD` for most setups)
    ///
    /// # Returns
    /// `AuthVector` containing (RAND, AUTN, XRES, CK, IK).
    /// The caller sends (RAND, AUTN) to the UE and keeps XRES for comparison.
    ///
    /// # Panics
    /// Panics with `todo!()` until Phase 1 implementation is complete.
    pub fn generate_vector(&self, sqn: Sqn, amf: Amf) -> AuthVector {
        let rand = Self::generate_rand();
        let _ = (&self.ki, &self.opc, sqn, amf);
        // TODO Phase 1: implement AES-128 core, then f1..f5
        // Step 1: temp_value = AES_Ki(RAND XOR OPc)
        // Step 2: f1  → compute MAC-A using temp_value
        // Step 3: f2  → RES (lower 8 bytes)
        // Step 4: f3  → CK
        // Step 5: f4  → IK
        // Step 6: f5  → AK (6 bytes, XORed with SQN in AUTN)
        // Step 7: AUTN = (SQN XOR AK) || AMF || MAC-A
        todo!("Phase 1: implement Milenage f1..f5 — see 3GPP TS 35.206 Section 4")
    }

    /// Verify the RES received from the UE against the stored XRES.
    ///
    /// MUST use constant-time comparison — timing difference reveals whether
    /// guess is close, enabling a timing oracle attack.
    #[inline]
    pub fn verify_res(xres: &[u8; 8], res: &[u8; 8]) -> bool {
        xres.ct_eq(res).into()
    }

    /// Generate a cryptographically random 128-bit RAND challenge.
    fn generate_rand() -> Rand {
        Rand(rand::random())
    }
}

impl Drop for MilenageContext {
    fn drop(&mut self) {
        // Ki and OPc are ZeroizeOnDrop — they wipe themselves.
        // Nothing extra needed here, but the explicit Drop makes intent clear.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 3GPP TS 35.207 Official Test Set 1 ───────────────────────────────────
    // These are the authoritative test vectors. ALL must pass before
    // Phase 1 is considered complete.
    //
    // K    = 465b5ce8b199b49faa5f0a2ee238a6bc
    // OP   = cdc202d5123e20f62b6d676ac72cb318
    // OPc  = cd63cb71954a9f4e48a5994e37a02baf
    // RAND = 23553cbe9637a89d218ae64dae47bf35
    // SQN  = ff9bb4d0b607
    // AMF  = b9b9
    //
    // Expected:
    //   MAC-A = 4a9ffac354dfafb3
    //   RES   = a54211d5e3ba50bf
    //   CK    = b40ba9a3c58b2a05bbf0d987b21bf8cb
    //   IK    = f769bcd751044604127672711c6d3441
    //   AK    = aa689c648370
    //   AUTN  = aa689c6483700000b9b94a9ffac354df (SQN XOR AK || AMF || MAC-A)

    #[test]
    #[ignore = "Phase 1 implementation required — uncomment when f1..f5 are done"]
    fn test_set_1_mac_a() {
        let ki  = AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
        let opc = OpCode::from_hex("cd63cb71954a9f4e48a5994e37a02baf").unwrap();
        let _ctx = MilenageContext::new(ki, opc);
        // TODO: fix RAND and SQN, call generate_vector, check AUTN/XRES/CK/IK
    }

    #[test]
    fn verify_res_constant_time_correct() {
        let xres = [0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF];
        assert!(MilenageContext::verify_res(&xres, &xres));
    }

    #[test]
    fn verify_res_rejects_wrong() {
        let xres  = [0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF];
        let wrong = [0x00u8; 8];
        assert!(!MilenageContext::verify_res(&xres, &wrong));
    }

    #[test]
    fn generate_rand_not_all_zeros() {
        // Probabilistic — chance of failure is 2^-128, negligible.
        let r = MilenageContext::generate_rand();
        assert_ne!(r.0, [0u8; 16]);
    }
}
