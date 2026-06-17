// crates/midn-core/src/hss.rs
//! In-memory Home Subscriber Server (HSS).
//!
//! Stores subscriber credentials (K, OPc, SQN) and generates Milenage
//! authentication vectors on demand.
//!
//! ## Method summary
//!
//! | Method               | Bench/caller       | Notes                              |
//! |----------------------|--------------------|------------------------------------|
//! | `provision`          | core_bench         | takes `AuthKey` + `OpCode` newtypes|
//! | `provision_hex`      | core_bench         | hex strings, returns `Result`      |
//! | `provision_with_op`  | tests              | derives OPc internally             |
//! | `has_subscriber`     | core_bench         | O(1) existence check               |
//! | `contains`           | internal tests     | alias kept for compat              |
//! | `generate_auth_vector` | MME/attach       | returns `HssAuthInfo`              |

use std::collections::HashMap;

use midn_auth::{AuthKey, AuthVector, MilenageContext, OpCode};
use midn_auth::keys::{Amf, Sqn};

// ── HssAuthInfo ───────────────────────────────────────────────────────────────

/// Authentication material returned to the MME for one AKA attempt.
#[derive(Debug)]
pub struct HssAuthInfo {
    /// 128-bit random challenge — sent to UE in Authentication Request.
    pub rand:     [u8; 16],
    /// All seven Milenage outputs: MAC-A/S, RES, CK, IK, AK, AK*.
    pub vector:   AuthVector,
    /// 48-bit SQN used for this vector — needed for AUTN construction:
    /// `AUTN = (SQN ⊕ AK) ∥ AMF ∥ MAC-A`.
    pub sqn_used: [u8; 6],
}

// ── SubscriberRecord ──────────────────────────────────────────────────────────

struct SubscriberRecord {
    ctx: MilenageContext,
    /// SQN counter — 48-bit range enforced on write.
    sqn: u64,
}

impl SubscriberRecord {
    fn sqn_bytes(&self) -> [u8; 6] {
        let b = self.sqn.to_be_bytes();
        [b[2], b[3], b[4], b[5], b[6], b[7]]
    }
}

// ── Hss ───────────────────────────────────────────────────────────────────────

/// In-memory HSS.
///
/// Not internally synchronised — wrap in `Arc<Mutex<Hss>>` for concurrent use.
pub struct Hss {
    subscribers: HashMap<u64, SubscriberRecord>,
}

impl Hss {
    pub fn new() -> Self {
        Self { subscribers: HashMap::new() }
    }

    // ── Provisioning ──────────────────────────────────────────────────────────

    /// Add a subscriber from a pre-computed OPc.
    ///
    /// Matches what `core_bench.rs` calls:
    /// ```ignore
    /// hss.provision(imsi, AuthKey::from_hex("...")?, OpCode::from_hex("...")?)
    /// ```
    pub fn provision(&mut self, imsi: u64, k: AuthKey, opc: OpCode) {
        let ctx = MilenageContext::new(k, opc);
        self.subscribers.insert(imsi, SubscriberRecord { ctx, sqn: 0 });
    }

    /// Add a subscriber from hex strings — convenience wrapper used by
    /// `core_bench.rs` and tests.
    ///
    /// ```ignore
    /// hss.provision_hex(imsi, "465b5ce8...", "cd63cb71...")?;
    /// ```
    pub fn provision_hex(
        &mut self,
        imsi:    u64,
        k_hex:   &str,
        opc_hex: &str,
    ) -> Result<(), hex::FromHexError> {
        let k   = AuthKey::from_hex(k_hex)?;
        let opc = OpCode::from_hex(opc_hex)?;
        self.provision(imsi, k, opc);
        Ok(())
    }

    /// Add a subscriber from operator OP (OPc = OP ⊕ E_K(OP) derived here).
    pub fn provision_with_op(&mut self, imsi: u64, k: AuthKey, op: [u8; 16]) {
        let ctx = MilenageContext::with_op(k, &op);
        self.subscribers.insert(imsi, SubscriberRecord { ctx, sqn: 0 });
    }

    /// Remove a subscriber. Returns `true` if the IMSI was present.
    pub fn deprovision(&mut self, imsi: u64) -> bool {
        self.subscribers.remove(&imsi).is_some()
    }

    /// Return `true` if a subscriber with this IMSI is provisioned.
    ///
    /// Used by `core_bench.rs` as `hss.has_subscriber(imsi)`.
    #[inline]
    pub fn has_subscriber(&self, imsi: u64) -> bool {
        self.subscribers.contains_key(&imsi)
    }

    /// Alias for `has_subscriber` — kept for internal test compat.
    #[inline]
    pub fn contains(&self, imsi: u64) -> bool {
        self.has_subscriber(imsi)
    }

    // ── Auth vector generation ─────────────────────────────────────────────────

    /// Generate a Milenage authentication vector for `imsi`.
    ///
    /// Returns `None` if the IMSI is unknown.
    ///
    /// On success:
    ///   - Generates a fresh 128-bit RAND via OS entropy (`generate_vector`).
    ///   - Runs Milenage f1/f1*/f2/f3/f4/f5/f5*.
    ///   - Increments and masks the stored SQN to 48 bits.
    ///   - Returns [`HssAuthInfo`] with RAND, the full vector, and the SQN
    ///     bytes used (caller constructs AUTN = (SQN ⊕ AK) ∥ AMF ∥ MAC-A).
    pub fn generate_auth_vector(&mut self, imsi: u64) -> Option<HssAuthInfo> {
        let sub = self.subscribers.get_mut(&imsi)?;

        let sqn_used = sub.sqn_bytes();

        // AMF fixed at [0x80, 0x00] for simulation.
        // Bit 0 of AMF[0] = 1 signals "UMTS AKA" to the UE per TS 33.102.
        let (rand_newtype, vector) = sub.ctx.generate_vector(
            Sqn::from_bytes(&sqn_used),
            Amf([0x80, 0x00]),
        );

        // Increment SQN; mask to 48 bits.
        sub.sqn = sub.sqn.wrapping_add(1) & 0x0000_FFFF_FFFF_FFFF;

        Some(HssAuthInfo { rand: rand_newtype.0, vector, sqn_used })
    }

    // ── SQN management ────────────────────────────────────────────────────────

    /// Overwrite the stored SQN for `imsi` (used after a resync procedure).
    pub fn update_sqn(&mut self, imsi: u64, new_sqn: u64) -> bool {
        match self.subscribers.get_mut(&imsi) {
            Some(sub) => {
                sub.sqn = new_sqn & 0x0000_FFFF_FFFF_FFFF;
                true
            }
            None => false,
        }
    }

    /// Return the current SQN counter for `imsi` (for test inspection).
    pub fn sqn(&self, imsi: u64) -> Option<u64> {
        self.subscribers.get(&imsi).map(|s| s.sqn)
    }
}

impl Default for Hss {
    fn default() -> Self { Self::new() }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hss() -> Hss {
        let mut hss = Hss::new();
        hss.provision_hex(
            901_700_000_000_001,
            "465b5ce8b199b49faa5f0a2ee238a6bc",
            "cd63cb71954a9f4e48a5994e37a02baf",
        ).expect("valid test hex");
        hss
    }

    #[test]
    fn provision_and_contains() {
        let hss = test_hss();
        assert!(hss.contains(901_700_000_000_001));
        assert!(!hss.contains(999));
    }

    #[test]
    fn has_subscriber_matches_contains() {
        let hss = test_hss();
        let imsi = 901_700_000_000_001;
        assert_eq!(hss.has_subscriber(imsi), hss.contains(imsi));
        assert!(!hss.has_subscriber(12345));
    }

    #[test]
    fn provision_hex_rejects_bad_hex() {
        let mut hss = Hss::new();
        assert!(hss.provision_hex(1, "notvalidhex!!!", "cd63cb71954a9f4e48a5994e37a02baf").is_err());
    }

    #[test]
    fn generate_auth_vector_unknown_imsi_returns_none() {
        let mut hss = Hss::new();
        assert!(hss.generate_auth_vector(999).is_none());
    }

    #[test]
    fn generate_auth_vector_returns_some() {
        let mut hss = test_hss();
        assert!(hss.generate_auth_vector(901_700_000_000_001).is_some());
    }

    #[test]
    fn rand_is_16_bytes_nonzero_probable() {
        let mut hss = test_hss();
        let info = hss.generate_auth_vector(901_700_000_000_001).unwrap();
        assert_ne!(info.rand, [0u8; 16]);
    }

    #[test]
    fn sqn_increments_after_each_vector() {
        let mut hss = test_hss();
        let imsi = 901_700_000_000_001;
        assert_eq!(hss.sqn(imsi), Some(0));
        hss.generate_auth_vector(imsi).unwrap();
        assert_eq!(hss.sqn(imsi), Some(1));
        hss.generate_auth_vector(imsi).unwrap();
        assert_eq!(hss.sqn(imsi), Some(2));
    }

    #[test]
    fn sqn_used_matches_counter_before_increment() {
        let mut hss = test_hss();
        let imsi = 901_700_000_000_001;
        let info = hss.generate_auth_vector(imsi).unwrap();
        assert_eq!(info.sqn_used, [0u8; 6]);
        let info2 = hss.generate_auth_vector(imsi).unwrap();
        assert_eq!(info2.sqn_used, [0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn two_vectors_have_different_rand() {
        let mut hss = test_hss();
        let imsi = 901_700_000_000_001;
        let a = hss.generate_auth_vector(imsi).unwrap();
        let b = hss.generate_auth_vector(imsi).unwrap();
        assert_ne!(a.rand, b.rand);
    }

    #[test]
    fn deprovision_removes_subscriber() {
        let mut hss = test_hss();
        let imsi = 901_700_000_000_001;
        assert!(hss.deprovision(imsi));
        assert!(!hss.contains(imsi));
        assert!(!hss.deprovision(imsi));
    }

    #[test]
    fn update_sqn_works() {
        let mut hss = test_hss();
        let imsi = 901_700_000_000_001;
        assert!(hss.update_sqn(imsi, 42));
        assert_eq!(hss.sqn(imsi), Some(42));
    }

    #[test]
    fn update_sqn_unknown_imsi_returns_false() {
        let mut hss = Hss::new();
        assert!(!hss.update_sqn(999, 0));
    }

    #[test]
    fn provision_with_op_generates_vector() {
        let mut hss = Hss::new();
        hss.provision_with_op(
            42,
            AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap(),
            {
                let mut b = [0u8; 16];
                hex::decode_to_slice("cdc202d5123e20f62b6d676ac72cb318", &mut b).unwrap();
                b
            },
        );
        assert!(hss.generate_auth_vector(42).is_some());
    }

    #[test]
    fn provision_newtype_api() {
        let mut hss = Hss::new();
        let k   = AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
        let opc = OpCode::from_hex("cd63cb71954a9f4e48a5994e37a02baf").unwrap();
        hss.provision(123, k, opc);
        assert!(hss.has_subscriber(123));
        assert!(hss.generate_auth_vector(123).is_some());
    }
}
