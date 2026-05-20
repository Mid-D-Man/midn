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
//! ## Implementation plan
//!
//! Add to Cargo.toml:
//!   aes = { version = "0.8", features = ["zeroize"] }
//!
//! Then:
//!   1. `fn aes128(key: &[u8;16], input: &[u8;16]) -> [u8;16]`
//!   2. `fn compute_opc(ki: &[u8;16], op: &[u8;16]) -> [u8;16]`
//!   3. Implement f1..f5 per 3GPP TS 35.206 Section 4
//!   4. Un-ignore the test set tests below
//!   5. All 6 official test sets must pass before Phase 1 closes

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
    pub fn new(ki: AuthKey, opc: OpCode) -> Self {
        Self { ki, opc }
    }

    /// Generate a complete authentication vector for one AKA round.
    ///
    /// # Arguments
    /// * `sqn` — current sequence number (monotonically increasing per subscriber)
    /// * `amf` — operator AMF field (use `Amf::STANDARD` for most deployments)
    ///
    /// # Returns
    /// `AuthVector` containing (RAND, AUTN, XRES, CK, IK).
    /// Caller sends (RAND, AUTN) to the UE and stores XRES for comparison.
    ///
    /// # Panics
    /// `todo!()` until Phase 1 implementation is complete.
    pub fn generate_vector(&self, sqn: Sqn, amf: Amf) -> AuthVector {
        // Suppress unused variable warnings — these will be used once f1..f5
        // are implemented. The underscore prefix documents intent.
        let _rand = Self::generate_rand();
        let _     = (&self.ki, &self.opc, sqn, amf);

        // TODO Phase 1: implement AES-128 core, then f1..f5
        // Step 1: temp_value = AES_Ki(RAND XOR OPc)
        // Step 2: f1  → MAC-A  (AUTN network auth token)
        // Step 3: f2  → RES    (8 bytes, lower half of 16-byte output)
        // Step 4: f3  → CK     (cipher key)
        // Step 5: f4  → IK     (integrity key)
        // Step 6: f5  → AK     (6 bytes, anonymity key XORed with SQN in AUTN)
        // Step 7: AUTN = (SQN XOR AK) || AMF || MAC-A
        todo!("Phase 1: implement Milenage f1..f5 — see 3GPP TS 35.206 Section 4")
    }

    /// Verify the RES received from the UE against the stored XRES.
    ///
    /// Uses constant-time comparison — MUST NOT use `==` or `memcmp`.
    /// Timing differences reveal whether a guess is close, enabling
    /// a timing oracle attack on the authentication path.
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
        // Ki and OPc are ZeroizeOnDrop — they wipe on drop automatically.
        // Explicit Drop makes the security contract visible at the call site.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AuthKey;

    // ── 3GPP TS 35.207 Official Test Set 1 ───────────────────────────────────
    //
    // K    = 465b5ce8b199b49faa5f0a2ee238a6bc
    // OPc  = cd63cb71954a9f4e48a5994e37a02baf
    // RAND = 23553cbe9637a89d218ae64dae47bf35
    // SQN  = ff9bb4d0b607   AMF = b9b9
    //
    // Expected:
    //   MAC-A = 4a9ffac354dfafb3
    //   RES   = a54211d5e3ba50bf
    //   CK    = b40ba9a3c58b2a05bbf0d987b21bf8cb
    //   IK    = f769bcd751044604127672711c6d3441
    //   AK    = aa689c648370

    #[test]
    #[ignore = "Phase 1 implementation required — un-ignore when f1..f5 are done"]
    fn test_set_1_official_vectors() {
        let ki  = AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
        let opc = crate::keys::OpCode::from_hex("cd63cb71954a9f4e48a5994e37a02baf").unwrap();
        let sqn = Sqn::from_bytes(&[0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07]);
        let amf = Amf([0xB9, 0xB9]);
        let _ctx = MilenageContext::new(ki, opc);
        let _    = (sqn, amf);
        // TODO: call generate_vector, assert AUTN, XRES, CK, IK match spec
    }

    #[test]
    fn verify_res_accepts_matching() {
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
    fn verify_res_rejects_off_by_one() {
        let xres  = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let close = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xFF];
        assert!(!MilenageContext::verify_res(&xres, &close));
    }

    #[test]
    fn generate_rand_not_all_zeros() {
        // Probabilistic — failure probability 2^-128, negligible.
        let r = MilenageContext::generate_rand();
        assert_ne!(r.0, [0u8; 16]);
    }
}
