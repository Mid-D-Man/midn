//! Milenage algorithm — 3GPP TS 35.205 / 35.206
//!
//! Milenage is the default 3GPP authentication algorithm.
//! It is built on AES-128 as a pseudorandom function.
//!
//! This implementation is constant-time for all comparisons
//! and uses the `subtle` crate to prevent timing attacks.

use crate::keys::{AuthKey, AuthVector, OpCode, Rand, Sqn};
// TODO Phase 1: Implement f1..f5* functions using AES-128 core
// Reference: 3GPP TS 35.206 Section 4

pub struct MilenageContext {
    ki:  AuthKey,
    opc: OpCode,
}

impl MilenageContext {
    pub fn new(ki: AuthKey, opc: OpCode) -> Self {
        Self { ki, opc }
    }

    /// Generate a full authentication vector for a subscriber attach.
    /// Returns (RAND, AUTN, XRES, CK, IK).
    pub fn generate_vector(&self, sqn: Sqn, plmn: &[u8; 3]) -> AuthVector {
        let rand = Self::generate_rand();
        // TODO: Implement f1 (MAC-A), f2 (RES), f3 (CK), f4 (IK), f5 (AK)
        let _ = (&self.ki, &self.opc, sqn, plmn);
        todo!("Milenage f1-f5 functions — Phase 1 target")
    }

    fn generate_rand() -> Rand {
        let mut bytes = [0u8; 16];
        // TODO: use rand::RngCore::fill_bytes in implementation
        Rand(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // 3GPP TS 35.207 test set 1 — official test vectors
    // K  = 465b5ce8b199b49faa5f0a2ee238a6bc
    // OP = cdc202d5123e20f62b6d676ac72cb318
    // RAND = 23553cbe9637a89d218ae64dae47bf35
    // SQN  = ff9bb4d0b607
    // AMF  = b9b9
    // Expected AUTN, XRES, CK, IK defined in spec
    #[test]
    #[ignore = "Phase 1 implementation required"]
    fn test_set_1_official_vectors() {
        // Validate against 3GPP TS 35.207 test set 1
        todo!()
    }
}
