// crates/midn-proto/src/nas5gs/security.rs
//! NAS-5GS security — 128-5G-EA2 ciphering and 128-5G-IA2 integrity.
//!
//! TS 33.501 §5.11 explicitly reuses the SAME EEA2/EIA2 primitives TS
//! 33.401 defines for LTE (128-5G-EA2/128-5G-IA2 ARE 128-EEA2/128-EIA2 —
//! same AES-128-CTR / AES-128-CMAC constructions, same COUNT‖BEARER‖
//! DIRECTION input). This module reuses `nas::security::{eea2_apply,
//! eia2_compute_mac, eia2_verify_mac, reconstruct_count}` directly rather
//! than reimplementing them — there is nothing 5G-specific about the
//! cipher/MAC primitives themselves.
//!
//! ## Update: the KAMF → NAS-key KDF is now implemented
//!
//! Previously stubbed pending spec text. That text (TS 33.501 Annex A.8,
//! "Algorithm key derivation functions") turned out to be directly
//! quotable and matches TS 33.401 Annex A.7's construction almost exactly
//! — same P0 = algorithm type distinguisher / P1 = algorithm identity
//! shape `nas::security::kdf_nas_key` already implements for LTE, just a
//! different FC (0x69 vs LTE's 0x15) and distinguisher values (0x01 =
//! N-NAS-enc-alg, 0x02 = N-NAS-int-alg — TS 33.501 Table A.8-1). HIGH
//! confidence: confirmed against directly-quoted spec text, independently
//! corroborated by a second public source. See `derive_nas_keys` below.
//!
//! What's still genuinely unimplemented, upstream of this file: KAMF
//! itself has to come from somewhere. That chain (KAUSF → KSEAF → KAMF,
//! TS 33.501 Annex A.2/A.6/A.7) now lives in `midn_core::kdf`, alongside
//! the LTE Kasme derivation it sits next to — see that module's doc for
//! the full confidence breakdown on each step.
//!
//! ## Algorithm representation
//!
//! `nas5gs::messages::SecurityModeCommand` deliberately stores
//! `nas_cipher_alg`/`nas_integrity_alg` as raw `u8` rather than the LTE
//! `NasEeaAlgorithm`/`NasEiaAlgorithm` enum (see `nas5gs::codec`'s module
//! doc for why). This context mirrors that: `0` means null (5G-EA0/5G-IA0),
//! anything else means 128-5G-EA2/128-5G-IA2 — the only real 5G NAS
//! cipher/integrity algorithm this codebase implements.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::nas::security::{
    eea2_apply, eia2_compute_mac, eia2_verify_mac, reconstruct_count, Direction, NAS_BEARER,
};

/// Result of protecting one outbound 5GS NAS message.
#[derive(Debug, Clone)]
pub struct ProtectedNas5gs {
    pub count: u32,
    pub mac_i: [u8; 4],
    pub payload: Vec<u8>,
}

/// Per-subscriber 5GS NAS security state. Structurally identical to
/// `nas::security::NasSecurityContext`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Nas5gsSecurityContext {
    pub k_nas_enc: [u8; 16],
    pub k_nas_int: [u8; 16],
    /// Raw 5GS cipher algorithm ID, as carried in `SecurityModeCommand` —
    /// see module doc. `0` = null (5G-EA0); anything else uses 128-5G-EA2.
    #[zeroize(skip)]
    pub nas_cipher_alg: u8,
    /// Same convention as `nas_cipher_alg`, for integrity (5G-IA0 vs
    /// 128-5G-IA2).
    #[zeroize(skip)]
    pub nas_integrity_alg: u8,
    dl_count: u32,
    ul_count: u32,
}

impl Nas5gsSecurityContext {
    /// Build a context by deriving NAS session keys from KAMF — mirrors
    /// `nas::security::NasSecurityContext::new`'s relationship to
    /// `derive_nas_keys` exactly, one level up the key hierarchy.
    pub fn new(kamf: &[u8; 32], nas_cipher_alg: u8, nas_integrity_alg: u8) -> Self {
        let (k_nas_enc, k_nas_int) = derive_nas_keys(kamf, nas_cipher_alg, nas_integrity_alg);
        Self { k_nas_enc, k_nas_int, nas_cipher_alg, nas_integrity_alg, dl_count: 0, ul_count: 0 }
    }

    /// Build a context directly from already-derived NAS keys — useful for
    /// tests that want fixed keys without running the full KDF chain.
    pub fn new_from_keys(
        k_nas_enc: [u8; 16],
        k_nas_int: [u8; 16],
        nas_cipher_alg: u8,
        nas_integrity_alg: u8,
    ) -> Self {
        Self { k_nas_enc, k_nas_int, nas_cipher_alg, nas_integrity_alg, dl_count: 0, ul_count: 0 }
    }

    pub fn dl_count(&self) -> u32 { self.dl_count }
    pub fn ul_count(&self) -> u32 { self.ul_count }

    fn cipher_is_null(&self) -> bool { self.nas_cipher_alg == 0 }
    fn integrity_is_null(&self) -> bool { self.nas_integrity_alg == 0 }

    /// Protect an outbound (AMF → UE) message. Consumes and advances the
    /// downlink COUNT.
    pub fn protect_downlink(&mut self, plain: &[u8]) -> ProtectedNas5gs {
        let count = self.dl_count;
        self.dl_count = self.dl_count.wrapping_add(1);
        self.protect(count, Direction::Downlink, plain)
    }

    /// Verify and decrypt an inbound (UE → AMF) message. Same reconstructed-
    /// COUNT / monotonic-advance approach as `nas::security`'s LTE
    /// equivalent — see that module's doc for the exact tradeoff versus the
    /// full TS 24.501 replay window.
    pub fn unprotect_uplink(
        &mut self,
        seq_byte: u8,
        mac_i: [u8; 4],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let count = reconstruct_count(self.ul_count, seq_byte);
        let plain = self.unprotect(count, Direction::Uplink, mac_i, ciphertext)?;
        self.ul_count = count.wrapping_add(1);
        Some(plain)
    }

    fn protect(&self, count: u32, dir: Direction, plain: &[u8]) -> ProtectedNas5gs {
        let mut payload = plain.to_vec();
        if !self.cipher_is_null() {
            eea2_apply(&self.k_nas_enc, count, NAS_BEARER, dir, &mut payload);
        }
        let mac_i = if !self.integrity_is_null() {
            eia2_compute_mac(&self.k_nas_int, count, NAS_BEARER, dir, &payload)
        } else {
            [0u8; 4]
        };
        ProtectedNas5gs { count, mac_i, payload }
    }

    fn unprotect(
        &self,
        count: u32,
        dir: Direction,
        mac_i: [u8; 4],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        if !self.integrity_is_null()
            && !eia2_verify_mac(&self.k_nas_int, count, NAS_BEARER, dir, ciphertext, &mac_i)
        {
            return None;
        }
        let mut payload = ciphertext.to_vec();
        if !self.cipher_is_null() {
            eea2_apply(&self.k_nas_enc, count, NAS_BEARER, dir, &mut payload);
        }
        Some(payload)
    }
}

impl core::fmt::Debug for Nas5gsSecurityContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print k_nas_enc/k_nas_int — same redaction pattern as
        // nas::security::NasSecurityContext and midn-auth's AuthVector.
        f.debug_struct("Nas5gsSecurityContext")
            .field("nas_cipher_alg", &self.nas_cipher_alg)
            .field("nas_integrity_alg", &self.nas_integrity_alg)
            .field("dl_count", &self.dl_count)
            .field("ul_count", &self.ul_count)
            .field("k_nas_enc", &"[REDACTED]")
            .field("k_nas_int", &"[REDACTED]")
            .finish()
    }
}

// ── KAMF → NAS-key KDF (TS 33.501 Annex A.8) ────────────────────────────────

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// FC = 0x69 (TS 33.501 Annex A.8) — different number from LTE's FC = 0x15
/// (TS 33.401 Annex A.7, `nas::security::FC_NAS_ALGO_KEY_DERIVATION`) even
/// though the construction shape is identical. Different specs, adjacent
/// but independently assigned FC number spaces — confirmed, not assumed.
const FC_5G_ALGO_KEY_DERIVATION: u8 = 0x69;
/// TS 33.501 Table A.8-1.
const ALGO_DISTINGUISHER_NAS_ENC: u8 = 0x01;
const ALGO_DISTINGUISHER_NAS_INT: u8 = 0x02;

/// KDF(KAMF, S) → 256 bits; the derived 128-bit NAS key is the 128 LEAST
/// significant bits of that output — TS 33.501 Annex A.8, same truncation
/// convention as its LTE counterpart `nas::security::kdf_nas_key`.
///
/// `S = FC ‖ P0 ‖ L0 ‖ P1 ‖ L1`:
///   FC = 0x69 (algorithm key derivation)
///   P0 = algorithm type distinguisher (0x01 enc / 0x02 int), L0 = 0x0001
///   P1 = algorithm identity (e.g. 2 for *EA2/*IA2),           L1 = 0x0001
fn kdf_5g_nas_key(kamf: &[u8; 32], algorithm_distinguisher: u8, algorithm_identity: u8) -> [u8; 16] {
    use hmac::Mac;

    let mut s = Vec::with_capacity(7);
    s.push(FC_5G_ALGO_KEY_DERIVATION);
    s.push(algorithm_distinguisher);
    s.extend_from_slice(&1u16.to_be_bytes()); // L0 = len(P0) = 1 byte
    s.push(algorithm_identity);
    s.extend_from_slice(&1u16.to_be_bytes()); // L1 = len(P1) = 1 byte

    let mut mac = HmacSha256::new_from_slice(kamf)
        .expect("HMAC-SHA-256 accepts a 32-byte key");
    mac.update(&s);
    let out = mac.finalize().into_bytes(); // 32 bytes

    let mut key = [0u8; 16];
    key.copy_from_slice(&out[16..32]); // least-significant 128 bits
    key
}

/// Derive `(k_nas_enc, k_nas_int)` from KAMF for the negotiated 5G NAS
/// algorithm pair — TS 33.501 Annex A.8. Algorithm IDs are raw `u8` (see
/// module doc) — `nas_cipher_alg`/`nas_integrity_alg` straight off
/// `SecurityModeCommand`, no enum conversion needed.
///
/// Confidence: HIGH — see module doc.
pub fn derive_nas_keys(kamf: &[u8; 32], nas_cipher_alg: u8, nas_integrity_alg: u8) -> ([u8; 16], [u8; 16]) {
    let k_nas_enc = kdf_5g_nas_key(kamf, ALGO_DISTINGUISHER_NAS_ENC, nas_cipher_alg);
    let k_nas_int = kdf_5g_nas_key(kamf, ALGO_DISTINGUISHER_NAS_INT, nas_integrity_alg);
    (k_nas_enc, k_nas_int)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> [u8; 16] { [0x2Bu8; 16] }

    #[test]
    fn context_protect_downlink_is_verifiable_independently() {
        let mut ctx = Nas5gsSecurityContext::new_from_keys(k(), k(), 2, 2);
        let plain = b"5GS RegistrationAccept goes here".to_vec();

        let protected = ctx.protect_downlink(&plain);
        assert_eq!(protected.count, 0);
        assert_eq!(ctx.dl_count(), 1, "dl_count must advance after protect");

        assert!(eia2_verify_mac(
            &k(), protected.count, NAS_BEARER, Direction::Downlink,
            &protected.payload, &protected.mac_i,
        ));

        let mut recovered = protected.payload.clone();
        eea2_apply(&k(), protected.count, NAS_BEARER, Direction::Downlink, &mut recovered);
        assert_eq!(recovered, plain);
    }

    #[test]
    fn context_unprotect_uplink_round_trip() {
        let mut ctx = Nas5gsSecurityContext::new_from_keys(k(), k(), 2, 2);
        let plain = b"5GS AuthenticationResponse RES* goes here".to_vec();

        let count = 0u32;
        let mut ciphertext = plain.clone();
        eea2_apply(&k(), count, NAS_BEARER, Direction::Uplink, &mut ciphertext);
        let mac_i = eia2_compute_mac(&k(), count, NAS_BEARER, Direction::Uplink, &ciphertext);

        let recovered = ctx
            .unprotect_uplink(count as u8, mac_i, &ciphertext)
            .expect("valid MAC should verify");
        assert_eq!(recovered, plain);
        assert_eq!(ctx.ul_count(), 1, "ul_count must advance after successful unprotect");
    }

    #[test]
    fn context_unprotect_uplink_rejects_bad_mac() {
        let mut ctx = Nas5gsSecurityContext::new_from_keys(k(), k(), 2, 2);
        let plain = b"tampered message".to_vec();

        let mut ciphertext = plain.clone();
        eea2_apply(&k(), 0, NAS_BEARER, Direction::Uplink, &mut ciphertext);

        let bad_mac = [0xFFu8; 4];
        assert!(ctx.unprotect_uplink(0, bad_mac, &ciphertext).is_none());
        assert_eq!(ctx.ul_count(), 0, "ul_count must NOT advance on a rejected message");
    }

    #[test]
    fn null_algorithms_pass_through_unciphered() {
        let mut ctx = Nas5gsSecurityContext::new_from_keys(k(), k(), 0, 0);
        let plain = b"null algorithms still envelope correctly".to_vec();

        let protected = ctx.protect_downlink(&plain);
        assert_eq!(protected.payload, plain, "null cipher must not touch payload");
        assert_eq!(protected.mac_i, [0u8; 4], "null integrity must produce a zero MAC-I");
    }

    // ── derive_nas_keys (TS 33.501 Annex A.8) ──────────────────────────────

    #[test]
    fn derive_nas_keys_is_deterministic() {
        let kamf = [0x77u8; 32];
        assert_eq!(derive_nas_keys(&kamf, 2, 2), derive_nas_keys(&kamf, 2, 2));
    }

    #[test]
    fn derive_nas_keys_enc_and_int_differ() {
        let kamf = [0x77u8; 32];
        let (enc, int) = derive_nas_keys(&kamf, 2, 2);
        assert_ne!(enc, int, "enc/int distinguisher must produce different keys even with the same algorithm identity");
    }

    #[test]
    fn derive_nas_keys_changes_with_kamf() {
        let (a, _) = derive_nas_keys(&[0x77; 32], 2, 2);
        let (b, _) = derive_nas_keys(&[0x78; 32], 2, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_nas_keys_changes_with_algorithm_id() {
        let kamf = [0x77u8; 32];
        let (a, _) = derive_nas_keys(&kamf, 1, 2);
        let (b, _) = derive_nas_keys(&kamf, 2, 2);
        assert_ne!(a, b, "different negotiated algorithm must produce a different session key");
    }

    #[test]
    fn new_derives_same_keys_new_from_keys_would_need_precomputed() {
        let kamf = [0x77u8; 32];
        let (enc, int) = derive_nas_keys(&kamf, 2, 2);
        let via_new = Nas5gsSecurityContext::new(&kamf, 2, 2);
        let via_from_keys = Nas5gsSecurityContext::new_from_keys(enc, int, 2, 2);
        assert_eq!(via_new.k_nas_enc, via_from_keys.k_nas_enc);
        assert_eq!(via_new.k_nas_int, via_from_keys.k_nas_int);
    }

    #[test]
    #[ignore = "TS 33.501 Annex A.8 official test vectors not yet sourced — \
                fill in real (KAMF, algorithm distinguisher, algorithm identity) -> \
                key values from spec Annex A.8 or a known-good reference implementation"]
    fn kamf_kdf_official_test_vectors() {
        todo!()
    }
}
