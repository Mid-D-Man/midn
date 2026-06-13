// crates/midn-core/src/hss.rs
//! In-memory Home Subscriber Server (HSS).
//!
//! Stores subscriber credentials (K, OPc, SQN) and generates Milenage
//! authentication vectors on demand. In production this is replaced by a
//! Diameter/LDAP HSS — for simulation and testing this in-memory version
//! provides full EPS-AKA functionality.
//!
//! ## RAND generation
//!
//! RAND is 128 bits of OS-seeded ChaCha12 entropy from `rand::thread_rng`.
//! The HSS returns RAND alongside the auth vector so the MME can include it
//! verbatim in the Authentication Request NAS message.
//!
//! ## SQN management
//!
//! SQN is held as `u64` and converted to 6-byte big-endian on each call.
//! It is incremented after every successful `generate_auth_vector`. The
//! 48-bit ceiling is enforced by masking with `0x0000_FFFF_FFFF_FFFF`.
//! Resync (AUTS-based SQN recovery) is Phase 2+ scope.
//!
//! ## AMF
//!
//! Authentication Management Field is fixed at `[0x80, 0x00]` for
//! simulation (TS 33.102 §6.3.3 leaves the value operator-defined).

use std::collections::HashMap;

use midn_auth::{AuthKey, AuthVector, MilenageContext, OpCode};
use rand::RngCore;

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
        // u64 is 8 bytes big-endian; SQN uses the lower 6 bytes.
        let b = self.sqn.to_be_bytes();
        [b[2], b[3], b[4], b[5], b[6], b[7]]
    }
}

// ── Hss ───────────────────────────────────────────────────────────────────────

/// In-memory HSS.
///
/// Not internally synchronized — wrap in `Arc<Mutex<Hss>>` for concurrent use.
pub struct Hss {
    subscribers: HashMap<u64, SubscriberRecord>,
}

impl Hss {
    pub fn new() -> Self {
        Self { subscribers: HashMap::new() }
    }

    // ── Provisioning ──────────────────────────────────────────────────────────

    /// Add a subscriber from a pre-computed OPc.
    pub fn provision(&mut self, imsi: u64, k: [u8; 16], opc: [u8; 16]) {
        let ctx = MilenageContext::new(AuthKey(k), OpCode(opc));
        self.subscribers.insert(imsi, SubscriberRecord { ctx, sqn: 0 });
    }

    /// Add a subscriber from operator OP (OPc = OP ⊕ E_K(OP) derived here).
    pub fn provision_with_op(&mut self, imsi: u64, k: [u8; 16], op: [u8; 16]) {
        let ctx = MilenageContext::with_op(AuthKey(k), &op);
        self.subscribers.insert(imsi, SubscriberRecord { ctx, sqn: 0 });
    }

    /// Remove a subscriber. Returns `true` if the IMSI was present.
    pub fn deprovision(&mut self, imsi: u64) -> bool {
        self.subscribers.remove(&imsi).is_some()
    }

    /// Check whether a subscriber is provisioned.
    pub fn contains(&self, imsi: u64) -> bool {
        self.subscribers.contains_key(&imsi)
    }

    // ── Auth vector generation ─────────────────────────────────────────────────

    /// Generate a Milenage authentication vector for `imsi`.
    ///
    /// Returns `None` if the IMSI is unknown.
    ///
    /// On success:
    ///   - Generates a fresh 128-bit RAND via OS entropy.
    ///   - Runs Milenage f1/f1*/f2/f3/f4/f5/f5* with the stored K, OPc, SQN.
    ///   - Increments the stored SQN.
    ///   - Returns [`HssAuthInfo`] containing RAND, the full vector, and the
    ///     SQN bytes used (for AUTN construction by the MME).
    pub fn generate_auth_vector(&mut self, imsi: u64) -> Option<HssAuthInfo> {
        let sub = self.subscribers.get_mut(&imsi)?;

        // 128-bit random challenge (OS-seeded ChaCha12).
        let mut rand = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut rand);

        let sqn_used = sub.sqn_bytes();

        // AMF fixed at [0x80, 0x00] for simulation.
        // Bit 0 of AMF[0] = 1 signals "UMTS AKA" to the UE per TS 33.102.
        let amf = [0x80u8, 0x00];

        // Generate the Milenage auth vector.
        // Fixed: was generate_vector(sqn, Amf::STANDARD) — 2 newtype args.
        // Now:   generate_vector(&rand, &sqn, &amf)      — 3 raw-slice args.
        let vector = sub.ctx.generate_vector(&rand, &sqn_used, &amf);

        // Increment SQN; mask to 48 bits.
        sub.sqn = sub.sqn.wrapping_add(1) & 0x0000_FFFF_FFFF_FFFF;

        Some(HssAuthInfo { rand, vector, sqn_used })
    }

    // ── SQN resync ────────────────────────────────────────────────────────────

    /// Overwrite the stored SQN for `imsi` (used after a resync procedure).
    ///
    /// Returns `true` if the subscriber was found and updated.
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
        // Test Set 1 subscriber — K and OPc from 3GPP TS 35.208 §4.3.1.
        hss.provision(
            901_700_000_000_001,
            hex("465b5ce8b199b49faa5f0a2ee238a6bc"),
            hex("cd63cb71954a9f4e48a5994e37a02baf"),
        );
        hss
    }

    #[test]
    fn provision_and_contains() {
        let hss = test_hss();
        assert!(hss.contains(901_700_000_000_001));
        assert!(!hss.contains(999));
    }

    #[test]
    fn generate_auth_vector_unknown_imsi_returns_none() {
        let mut hss = Hss::new();
        assert!(hss.generate_auth_vector(999).is_none());
    }

    #[test]
    fn generate_auth_vector_returns_some() {
        let mut hss = test_hss();
        let info = hss.generate_auth_vector(901_700_000_000_001);
        assert!(info.is_some());
    }

    #[test]
    fn rand_is_16_bytes_nonzero_probable() {
        let mut hss = test_hss();
        let info = hss.generate_auth_vector(901_700_000_000_001).unwrap();
        // A randomly generated RAND has astronomically low probability of
        // being all-zero; treat as a sanity check only.
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
        // SQN was 0 before generation — sqn_used should be [0,0,0,0,0,0].
        assert_eq!(info.sqn_used, [0u8; 6]);
        // SQN is now 1.
        let info2 = hss.generate_auth_vector(imsi).unwrap();
        assert_eq!(info2.sqn_used, [0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn two_vectors_have_different_rand() {
        let mut hss = test_hss();
        let imsi = 901_700_000_000_001;
        let a = hss.generate_auth_vector(imsi).unwrap();
        let b = hss.generate_auth_vector(imsi).unwrap();
        // Statistically guaranteed to differ with overwhelming probability.
        assert_ne!(a.rand, b.rand);
    }

    #[test]
    fn deprovision_removes_subscriber() {
        let mut hss = test_hss();
        let imsi = 901_700_000_000_001;
        assert!(hss.deprovision(imsi));
        assert!(!hss.contains(imsi));
        assert!(!hss.deprovision(imsi)); // second call returns false
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
            hex("465b5ce8b199b49faa5f0a2ee238a6bc"),
            hex("cdc202d5123e20f62b6d676ac72cb318"),
        );
        let info = hss.generate_auth_vector(42);
        assert!(info.is_some());
    }

    fn hex(s: &str) -> [u8; 16] {
        let digits: Vec<char> = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let mut arr = [0u8; 16];
        for (i, chunk) in digits.chunks(2).enumerate() {
            arr[i] = (chunk[0].to_digit(16).unwrap() as u8) << 4
                   | (chunk[1].to_digit(16).unwrap() as u8);
        }
        arr
    }
}
