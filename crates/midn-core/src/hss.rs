// crates/midn-core/src/hss.rs
//! In-memory Home Subscriber Server (HSS) — Phase 2 stub.
//!
//! In a real LTE/5G network, the HSS is a separate node accessed via
//! the S6a interface (Diameter protocol). For Phase 2, we embed a simple
//! HashMap-based HSS that the MME calls directly.
//!
//! Phase 3 target: replace this with an actual S6a Diameter client.
//!
//! ## Subscriber lifecycle
//!
//! 1. Provision subscriber at startup (or via test setup):
//!    `hss.provision(imsi, ki, opc)`
//! 2. MME calls `hss.get_auth_vector(imsi)` during attach
//! 3. HSS increments SQN and returns (RAND, AUTN, XRES, CK, IK)
//! 4. On attach completion, MME calls `hss.confirm_sync(imsi, sqn)` (future)

use std::collections::HashMap;
use midn_auth::keys::{Amf, AuthKey, AuthVector, OpCode, Sqn};
use midn_auth::milenage::MilenageContext;

/// Provisioned subscriber record in the HSS.
struct HssRecord {
    ki:  AuthKey,
    opc: OpCode,
    sqn: Sqn,
}

/// Result of an HSS authentication information request.
pub struct HssAuthInfo {
    pub vector: AuthVector,
    pub sqn_used: Sqn,
}

/// In-memory HSS — maps IMSI to subscriber credentials.
pub struct Hss {
    records: HashMap<u64, HssRecord>,
}

impl Hss {
    pub fn new() -> Self {
        Self { records: HashMap::new() }
    }

    /// Provision a subscriber. Ki and OPc are stored; OP is never stored.
    ///
    /// If the IMSI already exists, the record is overwritten.
    pub fn provision(&mut self, imsi: u64, ki: AuthKey, opc: OpCode) {
        self.records.insert(imsi, HssRecord { ki, opc, sqn: Sqn::ZERO });
    }

    /// Provision a subscriber using hex strings (convenience for tests/config).
    pub fn provision_hex(
        &mut self,
        imsi: u64,
        ki_hex:  &str,
        opc_hex: &str,
    ) -> Result<(), hex::FromHexError> {
        let ki  = AuthKey::from_hex(ki_hex)?;
        let opc = OpCode::from_hex(opc_hex)?;
        self.provision(imsi, ki, opc);
        Ok(())
    }

    /// Generate an authentication vector for a subscriber (called during attach).
    ///
    /// Increments the stored SQN to prevent replay attacks.
    /// Returns `None` if the IMSI is not provisioned.
    pub fn get_auth_vector(&mut self, imsi: u64) -> Option<HssAuthInfo> {
        let record = self.records.get_mut(&imsi)?;
        let sqn    = record.sqn.increment();
        record.sqn = sqn;

        let ctx    = MilenageContext::new(record.ki.clone(), record.opc.clone());
        let vector = ctx.generate_vector(sqn, Amf::STANDARD);

        Some(HssAuthInfo { vector, sqn_used: sqn })
    }

    /// Returns true if the IMSI is provisioned.
    pub fn has_subscriber(&self, imsi: u64) -> bool {
        self.records.contains_key(&imsi)
    }

    pub fn subscriber_count(&self) -> usize {
        self.records.len()
    }
}

impl Default for Hss { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use midn_auth::milenage::MilenageContext;

    #[test]
    fn provision_and_get_vector() {
        let mut hss = Hss::new();
        hss.provision_hex(
            234_15_1234567890_u64,
            "465b5ce8b199b49faa5f0a2ee238a6bc",
            "cd63cb71954a9f4e48a5994e37a02baf",
        ).expect("valid hex");

        let info = hss.get_auth_vector(234_15_1234567890_u64)
            .expect("subscriber exists");

        // AUTN should be 16 bytes, RAND should be 16 bytes
        assert_eq!(info.vector.rand.0.len(), 16);
        assert_eq!(info.vector.autn.len(),   16);
        assert_eq!(info.vector.xres.len(),   8);
        assert_eq!(info.vector.ck.len(),     16);
        assert_eq!(info.vector.ik.len(),     16);
    }

    #[test]
    fn sqn_increments_between_calls() {
        let mut hss = Hss::new();
        hss.provision_hex(1, "465b5ce8b199b49faa5f0a2ee238a6bc",
                             "cd63cb71954a9f4e48a5994e37a02baf").unwrap();
        let v1 = hss.get_auth_vector(1).unwrap();
        let v2 = hss.get_auth_vector(1).unwrap();
        assert_ne!(v1.sqn_used.0, v2.sqn_used.0, "SQN must increment between auth requests");
        // Each RAND should be different (probabilistically)
        assert_ne!(v1.vector.rand.0, v2.vector.rand.0, "RAND should be freshly generated");
    }

    #[test]
    fn unknown_imsi_returns_none() {
        let mut hss = Hss::new();
        assert!(hss.get_auth_vector(999_99_9999999999_u64).is_none());
    }
  }
