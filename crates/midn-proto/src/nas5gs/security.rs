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
//! What IS 5G-specific, and NOT implemented here: the KAMF → NAS-key KDF
//! (TS 33.501 Annex A.8). This is presumably structurally similar to TS
//! 33.401 Annex A.7 (the LTE Kasme → NAS-key KDF `nas::security` already
//! implements in `kdf_nas_key`) but the exact FC byte value and S-string
//! construction are NOT confirmed against spec text, so per this project's
//! standing policy (see `midn-auth`'s TUAK stub, `midn-core`'s original
//! Kasme placeholder) this is `#[ignore]`-stubbed rather than guessed. See
//! `derive_5g_nas_keys` below.
//!
//! `Nas5gsSecurityContext` therefore takes already-derived
//! `k_nas_enc`/`k_nas_int` directly (`new_from_keys`) rather than deriving
//! them from KAMF internally the way `nas::security::NasSecurityContext::new`
//! derives from Kasme — swap in `derive_5g_nas_keys`'s real output once
//! that KDF exists, no other change needed here.
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
/// `nas::security::NasSecurityContext` — see module doc for why key
/// derivation is NOT wired the same way (KAMF KDF stubbed, not real yet).
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
    /// Build a context directly from already-derived NAS keys. Use this
    /// until `derive_5g_nas_keys` is real; once it is, add a
    /// `Nas5gsSecurityContext::new(kamf, cipher_alg, integrity_alg)` that
    /// calls it internally — same shape as
    /// `nas::security::NasSecurityContext::new`'s relationship to
    /// `derive_nas_keys`.
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

// ── KAMF → NAS-key KDF (TS 33.501 Annex A.8) — NOT IMPLEMENTED ──────────────

/// Derive `(k_nas_enc, k_nas_int)` from KAMF for the negotiated 5G NAS
/// algorithm pair — TS 33.501 Annex A.8.
///
/// STUBBED. The FC byte value and exact S-string construction for this KDF
/// are not confirmed against spec text — this project's standing policy is
/// to never hand-type 3GPP cryptographic constants from memory. Fill this
/// in against TS 33.501 Annex A.8 directly, then wire a
/// `Nas5gsSecurityContext::new(kamf, cipher_alg, integrity_alg)` that calls
/// it — mirroring `nas::security::NasSecurityContext::new`'s relationship
/// to `derive_nas_keys` exactly. Also note: deriving KAMF itself (TS 33.501
/// Annex A.7, from Kseaf) is a SEPARATE unimplemented step upstream of this
/// one — see `how_far_from_full_software_simulation` item 2 in the project
/// handover (AMF registration procedure) for where that fits.
#[allow(dead_code)]
fn derive_5g_nas_keys(_kamf: &[u8; 32], _cipher_alg: u8, _integrity_alg: u8) -> ([u8; 16], [u8; 16]) {
    todo!("TS 33.501 Annex A.8 KAMF -> NAS-key KDF — needs real spec text, see module doc")
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

    #[test]
    #[ignore = "TS 33.501 Annex A.8 KAMF -> NAS-key KDF not implemented — see derive_5g_nas_keys"]
    fn kamf_kdf_official_test_vectors() {
        // Pull real KAMF/algorithm-pair/expected-key values from TS 33.501
        // Annex A.8 (or an official test set) and assert against them here,
        // same pattern as nas::security's own official_3gpp_test_vectors
        // stub and midn-auth::milenage's test_set_4..6.
        todo!()
    }
  }
