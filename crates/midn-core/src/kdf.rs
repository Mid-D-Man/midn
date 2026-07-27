// crates/midn-core/src/kdf.rs
//! Generic 3GPP key derivation function (TS 33.220 Annex B), the LTE Kasme
//! derivation (TS 33.401 Annex A.2), and the 5G-AKA key hierarchy (TS
//! 33.501 Annex A.2/A.4/A.6/A.7).
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
//!   construction — see `serving_network_name` below, which is where that
//!   difference actually gets modeled.
//!
//! ## 5G-AKA chain (TS 33.501 Annex A) — confidence, function by function
//!
//! Every FC value below was checked against real sources this session, not
//! recalled from memory alone:
//!
//! - **`derive_kausf`** (Annex A.2, FC = 0x6A) and **`derive_kamf`** (Annex
//!   A.7, FC = 0x6D) — HIGH confidence. Both FC values and their exact
//!   P0/P1/L0/L1 assignments are confirmed against directly-quoted TS
//!   33.501 spec text (independently corroborated by a real reference
//!   implementation's source for good measure).
//! - **`derive_res_star`** (Annex A.4, FC = 0x6B) and **`derive_kseaf`**
//!   (Annex A.6, FC = 0x6C) — MODERATE-HIGH confidence. Taken from
//!   free5GC's actual UDM/KDF source (`util/ueauth/ueauth.go`,
//!   `udm/internal/sbi/processor/generate_auth_data.go`) — a real, widely
//!   deployed open-source 5G core, not a guess — one tier below the
//!   direct-spec-quote confirmation the other two got.
//! - **`serving_network_name`** — MODERATE confidence on the shape, but a
//!   DELIBERATE SIMPLIFICATION on content: see that function's doc comment.
//!   This project's `plmn: [u8; 3]` is treated as an opaque identifier
//!   everywhere else in this codebase (same as `derive_kasme`'s `sn_id`
//!   parameter above) — nothing here BCD-decodes it into the decimal
//!   MCC/MNC digit string the real spec's SNN format requires. Real
//!   BCD-to-decimal PLMN decoding is fiddly (2-digit vs 3-digit MNC
//!   filler-nibble handling trips up many implementations) and out of
//!   scope for this increment.
//! - **RES*/XRES\* and KAUSF/KSEAF/KAMF truncation/width**: RES*/XRES* keep
//!   the 128 least-significant bits of the 256-bit KDF output (same
//!   truncation convention as every narrower-than-256-bit key in this
//!   family). KAUSF/KSEAF/KAMF stay full 256-bit HMAC-SHA-256 output, same
//!   as Kasme. HIGH confidence — consistently described this way across
//!   every source consulted.
//!
//! None of this is an official 3GPP test vector — see the `#[ignore]`d
//! tests at the bottom of this file for what's still needed from Su before
//! any of these outputs can be trusted byte-for-byte.

use hmac::Mac;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// FC value for Kasme derivation — TS 33.401 Annex A.2.
const FC_KASME_DERIVATION: u8 = 0x10;

/// FC values for the 5G-AKA key hierarchy — TS 33.501 Annex A. See module
/// doc for the per-function confidence breakdown.
const FC_KAUSF_DERIVATION: u8 = 0x6A;
const FC_RES_STAR_DERIVATION: u8 = 0x6B;
const FC_KSEAF_DERIVATION: u8 = 0x6C;
const FC_KAMF_DERIVATION: u8 = 0x6D;

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

// ── 5G-AKA key hierarchy (TS 33.501 Annex A) ────────────────────────────────

/// Construct a Serving Network Name byte string for the 5G-AKA KDF family
/// (TS 33.501 §6.1.1.4 defines this as an ASCII string shaped like
/// `"5G:mnc012.mcc345.3gppnetwork.org"`).
///
/// SIMPLIFICATION: this project's `plmn: [u8; 3]` is treated as an opaque
/// identifier everywhere else in this codebase (same as `derive_kasme`'s
/// `sn_id` parameter) — nothing here BCD-decodes it into the decimal
/// MCC/MNC digits the real spec string requires. Real BCD-to-decimal PLMN
/// decoding is fiddly (2-digit vs 3-digit MNC filler-nibble handling trips
/// up many implementations) and out of scope for this increment. This
/// produces a deterministic, PLMN-bound byte string with the KDF-relevant
/// binding property intact — different PLMN in, different SNN out, so
/// KAUSF/RES*/KSEAF still correctly bind to the serving network within
/// this simulator — but it will NOT byte-match a real network's SNN
/// string. Fix by BCD-decoding `plmn` into decimal digits per TS
/// 24.301/23.003 if real interop with the string ever matters.
pub fn serving_network_name(plmn: &[u8; 3]) -> Vec<u8> {
    let mut snn = b"5G:mnc-mcc.".to_vec();
    snn.extend_from_slice(plmn);
    snn.extend_from_slice(b".3gppnetwork.org");
    snn
}

/// Derive KAUSF from CK, IK, the serving network name, and SQN ⊕ AK — TS
/// 33.501 Annex A.2. This clause applies to 5G-AKA specifically (a
/// different construction from EAP-AKA's CK'/IK' derivation, which this
/// project doesn't model — 5G-AKA is the only method implemented here).
///
/// `Key = CK ‖ IK` (32 bytes — the literal 5G-AKA fork point: same
/// Milenage CK/IK output `derive_kasme` uses, routed to a different KDF).
/// `S = FC(0x6A) ‖ SNN ‖ len(SNN) ‖ (SQN⊕AK) ‖ len(SQN⊕AK)`.
///
/// Confidence: HIGH — see module doc.
pub fn derive_kausf(ck: &[u8; 16], ik: &[u8; 16], snn: &[u8], sqn_xor_ak: &[u8; 6]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    kdf_generic(&key, FC_KAUSF_DERIVATION, &[snn, sqn_xor_ak])
}

/// Derive RES* (UE side) / XRES* (network side) from CK, IK, the serving
/// network name, RAND, and the legacy 8-byte RES/XRES — TS 33.501 Annex
/// A.4. Output is the 128 least-significant bits of the KDF result.
///
/// Confidence: MODERATE-HIGH — see module doc (free5GC reference
/// implementation, not a fetched spec quote for this one specifically).
pub fn derive_res_star(
    ck: &[u8; 16],
    ik: &[u8; 16],
    snn: &[u8],
    rand: &[u8; 16],
    res: &[u8; 8],
) -> [u8; 16] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    let full = kdf_generic(&key, FC_RES_STAR_DERIVATION, &[snn, rand, res]);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[16..]);
    out
}

/// Derive KSEAF from KAUSF and the serving network name — TS 33.501 Annex
/// A.6.
///
/// Confidence: MODERATE-HIGH — see module doc (free5GC reference
/// implementation).
pub fn derive_kseaf(kausf: &[u8; 32], snn: &[u8]) -> [u8; 32] {
    kdf_generic(kausf, FC_KSEAF_DERIVATION, &[snn])
}

/// Derive KAMF from KSEAF, SUPI, and the ABBA parameter — TS 33.501 Annex
/// A.7. `abba` defaults to `[0x00, 0x00]` per the spec's default value
/// unless the caller has a real ABBA to bind.
///
/// `supi` here is the ASCII decimal-digit string of the IMSI (e.g.
/// `imsi.to_string().into_bytes()`) — matches how a real SUPI-as-IMSI is
/// fed into this KDF (confirmed against free5GC's source, which treats
/// SUPI as its literal digit-string form for this exact call).
///
/// Confidence: HIGH — see module doc.
pub fn derive_kamf(kseaf: &[u8; 32], supi: &[u8], abba: &[u8; 2]) -> [u8; 32] {
    kdf_generic(kseaf, FC_KAMF_DERIVATION, &[supi, abba])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Kasme (pre-existing) ───────────────────────────────────────────────

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

    // ── serving_network_name ───────────────────────────────────────────────

    #[test]
    fn serving_network_name_is_deterministic() {
        let plmn = [0x23, 0x41, 0x5F];
        assert_eq!(serving_network_name(&plmn), serving_network_name(&plmn));
    }

    #[test]
    fn serving_network_name_changes_with_plmn() {
        let a = serving_network_name(&[0x23, 0x41, 0x5F]);
        let b = serving_network_name(&[0x23, 0x41, 0x60]);
        assert_ne!(a, b);
    }

    // ── derive_kausf ────────────────────────────────────────────────────────

    #[test]
    fn derive_kausf_is_deterministic() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let snn = serving_network_name(&[0x23, 0x41, 0x5F]);
        let sqn_xor_ak = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(
            derive_kausf(&ck, &ik, &snn, &sqn_xor_ak),
            derive_kausf(&ck, &ik, &snn, &sqn_xor_ak)
        );
    }

    #[test]
    fn derive_kausf_changes_with_snn() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let sqn_xor_ak = [0; 6];
        let a = derive_kausf(&ck, &ik, &serving_network_name(&[1, 2, 3]), &sqn_xor_ak);
        let b = derive_kausf(&ck, &ik, &serving_network_name(&[1, 2, 4]), &sqn_xor_ak);
        assert_ne!(a, b, "different serving network must produce different KAUSF");
    }

    #[test]
    fn derive_kausf_changes_with_sqn_xor_ak() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let snn = serving_network_name(&[1, 2, 3]);
        let a = derive_kausf(&ck, &ik, &snn, &[0; 6]);
        let b = derive_kausf(&ck, &ik, &snn, &[0, 0, 0, 0, 0, 1]);
        assert_ne!(a, b, "different SQN must produce different KAUSF — re-sync protection");
    }

    #[test]
    fn derive_kausf_differs_from_derive_kasme_for_same_inputs() {
        // Same CK/IK/SQN⊕AK, different FC and different SN-Id encoding —
        // must never collide with the LTE anchor key.
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let sqn_xor_ak = [0; 6];
        let kasme = derive_kasme(&ck, &ik, &[1, 2, 3], &sqn_xor_ak);
        let kausf = derive_kausf(&ck, &ik, &serving_network_name(&[1, 2, 3]), &sqn_xor_ak);
        assert_ne!(kasme, kausf);
    }

    // ── derive_res_star ─────────────────────────────────────────────────────

    #[test]
    fn derive_res_star_is_deterministic() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let snn = serving_network_name(&[1, 2, 3]);
        let rand = [0x33u8; 16];
        let res = [0x44u8; 8];
        assert_eq!(
            derive_res_star(&ck, &ik, &snn, &rand, &res),
            derive_res_star(&ck, &ik, &snn, &rand, &res)
        );
    }

    #[test]
    fn derive_res_star_changes_with_rand() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let snn = serving_network_name(&[1, 2, 3]);
        let res = [0x44u8; 8];
        let a = derive_res_star(&ck, &ik, &snn, &[0x33; 16], &res);
        let b = derive_res_star(&ck, &ik, &snn, &[0x34; 16], &res);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_res_star_changes_with_res() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let snn = serving_network_name(&[1, 2, 3]);
        let rand = [0x33u8; 16];
        let a = derive_res_star(&ck, &ik, &snn, &rand, &[0x44; 8]);
        let b = derive_res_star(&ck, &ik, &snn, &rand, &[0x45; 8]);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_res_star_output_is_16_bytes_not_8() {
        let out = derive_res_star(&[0; 16], &[0; 16], b"snn", &[0; 16], &[0; 8]);
        assert_eq!(out.len(), 16, "RES*/XRES* must be 16 bytes — see nas5gs::messages doc");
    }

    // ── derive_kseaf ────────────────────────────────────────────────────────

    #[test]
    fn derive_kseaf_is_deterministic() {
        let kausf = [0x55u8; 32];
        let snn = serving_network_name(&[1, 2, 3]);
        assert_eq!(derive_kseaf(&kausf, &snn), derive_kseaf(&kausf, &snn));
    }

    #[test]
    fn derive_kseaf_changes_with_kausf() {
        let snn = serving_network_name(&[1, 2, 3]);
        let a = derive_kseaf(&[0x55; 32], &snn);
        let b = derive_kseaf(&[0x56; 32], &snn);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_kseaf_changes_with_snn() {
        let kausf = [0x55u8; 32];
        let a = derive_kseaf(&kausf, &serving_network_name(&[1, 2, 3]));
        let b = derive_kseaf(&kausf, &serving_network_name(&[1, 2, 4]));
        assert_ne!(a, b);
    }

    // ── derive_kamf ─────────────────────────────────────────────────────────

    #[test]
    fn derive_kamf_is_deterministic() {
        let kseaf = [0x66u8; 32];
        let supi = b"234155550001";
        let abba = [0x00, 0x00];
        assert_eq!(
            derive_kamf(&kseaf, supi, &abba),
            derive_kamf(&kseaf, supi, &abba)
        );
    }

    #[test]
    fn derive_kamf_changes_with_kseaf() {
        let supi = b"234155550001";
        let abba = [0x00, 0x00];
        let a = derive_kamf(&[0x66; 32], supi, &abba);
        let b = derive_kamf(&[0x67; 32], supi, &abba);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_kamf_changes_with_supi() {
        let kseaf = [0x66u8; 32];
        let abba = [0x00, 0x00];
        let a = derive_kamf(&kseaf, b"234155550001", &abba);
        let b = derive_kamf(&kseaf, b"234155550002", &abba);
        assert_ne!(a, b, "different subscriber must produce different KAMF");
    }

    #[test]
    fn derive_kamf_changes_with_abba() {
        let kseaf = [0x66u8; 32];
        let supi = b"234155550001";
        let a = derive_kamf(&kseaf, supi, &[0x00, 0x00]);
        let b = derive_kamf(&kseaf, supi, &[0x00, 0x01]);
        assert_ne!(a, b, "ABBA binds algorithm/feature set — must affect KAMF");
    }

    #[test]
    fn derive_kamf_output_is_full_256_bits() {
        let out = derive_kamf(&[0; 32], b"1", &[0; 2]);
        assert_eq!(out.len(), 32);
    }

    // ── Full chain composition sanity ──────────────────────────────────────

    #[test]
    fn full_5g_aka_chain_is_deterministic_end_to_end() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let plmn = [0x23, 0x41, 0x5F];
        let snn = serving_network_name(&plmn);
        let sqn_xor_ak = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let imsi: u64 = 234_15_5550001;
        let supi = imsi.to_string().into_bytes();

        let run = || {
            let kausf = derive_kausf(&ck, &ik, &snn, &sqn_xor_ak);
            let kseaf = derive_kseaf(&kausf, &snn);
            derive_kamf(&kseaf, &supi, &[0x00, 0x00])
        };

        assert_eq!(run(), run());
    }

    #[test]
    fn full_5g_aka_chain_kamf_differs_from_lte_kasme_for_equivalent_inputs() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let plmn = [0x23, 0x41, 0x5F];
        let sqn_xor_ak = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let imsi: u64 = 234_15_5550001;
        let supi = imsi.to_string().into_bytes();

        let kasme = derive_kasme(&ck, &ik, &plmn, &sqn_xor_ak);

        let snn = serving_network_name(&plmn);
        let kausf = derive_kausf(&ck, &ik, &snn, &sqn_xor_ak);
        let kseaf = derive_kseaf(&kausf, &snn);
        let kamf = derive_kamf(&kseaf, &supi, &[0x00, 0x00]);

        assert_ne!(kasme, kamf, "4G and 5G anchor keys must never collide");
    }

    #[test]
    #[ignore = "TS 33.501 Annex A.2/A.4/A.6/A.7 official 5G-AKA test vectors not yet \
                sourced — fill in real (CK, IK, SNN, SQN⊕AK, RAND, RES, SUPI, ABBA) -> \
                (KAUSF, XRES*, KSEAF, KAMF) values from spec Annex A or a known-good \
                reference implementation (free5GC/Open5GS test suites are a reasonable \
                place to look, given they're already what corroborated the FC values \
                above)"]
    fn official_ts33501_annex_a_5g_aka_test_vectors() {
        todo!()
    }
}
