// crates/midn-core/src/kdf.rs
//! Generic 3GPP key derivation function (TS 33.220 Annex B) and the
//! specific Kasme derivation (TS 33.401 Annex A.2).
//!
//! Replaces the `CK ‖ IK` concatenation placeholder that used to live in
//! `mme::attach::derive_kasme` — flagged as a known gap since the NAS
//! security wiring increment.
//!
//! ## Confidence notes — same honesty policy as everywhere else in this project
//!
//! - The GENERIC KDF construction (HMAC-SHA-256 over S = FC ‖ P0 ‖ L0 ‖ ... ‖
//!   Pn ‖ Ln, Key = the algorithm-specific input key) is HIGH confidence —
//!   identical shape to `midn_proto::nas::security::kdf_nas_key` (TS 33.401
//!   Annex A.7), already live and structurally tested.
//! - `FC = 0x10` for Kasme derivation, and the parameter assignment
//!   (P0 = SN Id, P1 = SQN ⊕ AK) — MODERATE confidence. Widely cited in
//!   public EPS-AKA material, but not verified byte-for-byte against TS
//!   33.401 Annex A.2 in this session. A reference implementation (srsRAN,
//!   open5gs, free5GC all implement this) is worth a diff before trusting
//!   Kasme values for real interop.
//! - Output: the full 256-bit HMAC-SHA-256 result IS Kasme — no truncation
//!   (unlike the NAS-key KDF, which keeps only the 128 least-significant
//!   bits). HIGH confidence — the most consistently-cited fact about this
//!   specific call.
//! - SN Id encoding: taken here as the raw 3-octet PLMN identity (same
//!   shape as `Gummei.plmn` elsewhere in this codebase) — i.e. assuming
//!   EPS SN Id == PLMN-Id, no extra wrapping. This matches LTE/EPS-AKA
//!   specifically; 5G's SUCI-based SN Id is a different, string-based
//!   construction and is NOT what's modeled here.

use hmac::Mac;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// FC value for Kasme derivation — TS 33.401 Annex A.2.
const FC_KASME_DERIVATION: u8 = 0x10;

/// Generic 3GPP KDF (TS 33.220 Annex B): HMAC-SHA-256(key, S), full 256-bit
/// output. Each entry in `params` is appended to `S` as-is, followed by its
/// own 2-byte big-endian length — the standard P_i ‖ L_i pairing used
/// throughout the 3GPP KDF family.
fn kdf_generic(key: &[u8], fc: u8, params: &[&[u8]]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 accepts any key length");
    mac.update(&[fc]);
    for p in params {
        mac.update(p);
        mac.update(&(p.len() as u16).to_be_bytes());
    }
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// Derive Kasme from CK, IK, the serving network identity (PLMN, 3 octets),
/// and SQN ⊕ AK (6 octets) — TS 33.401 Annex A.2.
///
/// `Key = CK ‖ IK` (32 bytes). `S = FC ‖ SN-Id ‖ len(SN-Id) ‖ (SQN⊕AK) ‖
/// len(SQN⊕AK)`. Output is the full 256-bit HMAC-SHA-256 result.
///
/// See module docs for confidence levels on `FC` and the SN-Id encoding.
pub fn derive_kasme(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_id: &[u8; 3],
    sqn_xor_ak: &[u8; 6],
) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    kdf_generic(&key, FC_KASME_DERIVATION, &[sn_id, sqn_xor_ak])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_kasme_is_deterministic() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let sn_id = [0x46, 0x00, 0x01];
        let sqn_xor_ak = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(
            derive_kasme(&ck, &ik, &sn_id, &sqn_xor_ak),
            derive_kasme(&ck, &ik, &sn_id, &sqn_xor_ak)
        );
    }

    #[test]
    fn derive_kasme_changes_with_ck() {
        let ik = [0x22u8; 16];
        let sn_id = [0x46, 0x00, 0x01];
        let sqn_xor_ak = [0; 6];
        let a = derive_kasme(&[0x11; 16], &ik, &sn_id, &sqn_xor_ak);
        let b = derive_kasme(&[0x12; 16], &ik, &sn_id, &sqn_xor_ak);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_kasme_changes_with_ik() {
        let ck = [0x11u8; 16];
        let sn_id = [0x46, 0x00, 0x01];
        let sqn_xor_ak = [0; 6];
        let a = derive_kasme(&ck, &[0x22; 16], &sn_id, &sqn_xor_ak);
        let b = derive_kasme(&ck, &[0x23; 16], &sn_id, &sqn_xor_ak);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_kasme_changes_with_sn_id() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let sqn_xor_ak = [0; 6];
        let a = derive_kasme(&ck, &ik, &[0x46, 0x00, 0x01], &sqn_xor_ak);
        let b = derive_kasme(&ck, &ik, &[0x46, 0x00, 0x02], &sqn_xor_ak);
        assert_ne!(a, b, "different serving network must produce different Kasme");
    }

    #[test]
    fn derive_kasme_changes_with_sqn_xor_ak() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let sn_id = [0x46, 0x00, 0x01];
        let a = derive_kasme(&ck, &ik, &sn_id, &[0; 6]);
        let b = derive_kasme(&ck, &ik, &sn_id, &[0, 0, 0, 0, 0, 1]);
        assert_ne!(a, b, "different SQN must produce different Kasme — re-sync protection");
    }

    #[test]
    fn derive_kasme_output_is_full_256_bits_not_truncated() {
        let out = derive_kasme(&[0; 16], &[0; 16], &[0; 3], &[0; 6]);
        assert_eq!(out.len(), 32);
    }

    #[test]
    #[ignore = "TS 33.401 Annex A.2 official Kasme test vector not yet sourced — \
                fill in real (CK, IK, SN-Id, SQN⊕AK) -> Kasme values from spec or a \
                known-good reference implementation"]
    fn official_ts33401_annex_a2_test_vector() {
        todo!()
    }
}
