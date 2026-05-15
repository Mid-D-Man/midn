// crates/midn-auth/src/keys.rs
//! Cryptographic key types for subscriber authentication.
//!
//! All secret types implement `Zeroize` + `ZeroizeOnDrop` so key material
//! is wiped from memory when dropped. Never store Ki in a plain `[u8; N]`.

use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Secret types ──────────────────────────────────────────────────────────────

/// 128-bit subscriber authentication key (Ki).
///
/// Stored on the SIM card and in the HSS/UDM. NEVER transmitted over the air.
/// Always zeroize before drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AuthKey(pub [u8; 16]);

impl AuthKey {
    /// Parse from a 32-character hex string (e.g. config file).
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut out = [0u8; 16];
        hex::decode_to_slice(s, &mut out)?;
        Ok(Self(out))
    }
}

/// 128-bit Operator Code variant (OPc).
///
/// Derived by the operator from OP and Ki: OPc = AES_Ki(OP) XOR OP.
/// Stored in the HSS. Safer to store than raw OP.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OpCode(pub [u8; 16]);

impl OpCode {
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut out = [0u8; 16];
        hex::decode_to_slice(s, &mut out)?;
        Ok(Self(out))
    }
}

// ── Public / non-secret types ─────────────────────────────────────────────────

/// 128-bit random challenge (RAND). Generated fresh per authentication.
/// Sent to the UE along with AUTN.
///
/// Not secret — but zeroizes to keep AuthVector consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct Rand(pub [u8; 16]);

/// 48-bit Sequence Number (SQN). Monotonically increasing per subscriber.
///
/// Top 48 bits of the u64 are used. SQN prevents replay attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sqn(pub u64);

impl Sqn {
    pub const ZERO: Self = Self(0);

    /// Extract the 6-byte big-endian wire encoding.
    #[inline]
    pub fn to_bytes(self) -> [u8; 6] {
        let b = self.0.to_be_bytes();
        [b[2], b[3], b[4], b[5], b[6], b[7]]
    }

    /// Parse from 6-byte big-endian wire encoding.
    #[inline]
    pub fn from_bytes(b: &[u8; 6]) -> Self {
        Self(u64::from_be_bytes([0, 0, b[0], b[1], b[2], b[3], b[4], b[5]]))
    }

    #[inline]
    pub fn increment(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

/// PLMN identity — 3 bytes encoding MCC + MNC (3GPP TS 23.003 Section 12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plmn(pub [u8; 3]);

/// Authentication Management Field (AMF) — 2 bytes set by the operator.
///
/// Included in f1/f1* to bind the authentication vector to the operator's
/// network. Bit 0 of byte 1 is the separation bit (0 = authentication,
/// 1 = re-sync).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Amf(pub [u8; 2]);

impl Amf {
    /// Standard AMF value used by most operators: 0x8000.
    pub const STANDARD: Self = Self([0x80, 0x00]);
}

// ── Output ────────────────────────────────────────────────────────────────────

/// Authentication vector output from the AKA procedure.
///
/// Produced by `MilenageContext::generate_vector` and consumed by the MME/AMF
/// to authenticate the subscriber and establish session keys.
///
/// All fields are zeroized on drop — CK, IK, XRES are session secrets.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthVector {
    /// The RAND challenge sent to the UE.
    pub rand: Rand,
    /// Network authentication token sent to the UE (AK XOR SQN || AMF || MAC-A).
    pub autn: [u8; 16],
    /// Expected response — compared against UE's RES using constant-time eq.
    pub xres: [u8; 8],
    /// Cipher key (CK) — used to derive Kasme in LTE.
    pub ck:   [u8; 16],
    /// Integrity key (IK) — used to derive Kasme in LTE.
    pub ik:   [u8; 16],
}

impl core::fmt::Debug for AuthVector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print CK/IK/XRES — they are session secrets.
        f.debug_struct("AuthVector")
            .field("rand", &hex::encode(self.rand.0))
            .field("autn", &hex::encode(self.autn))
            .field("xres", &"[REDACTED]")
            .field("ck",   &"[REDACTED]")
            .field("ik",   &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqn_round_trip() {
        let sqn = Sqn(0x_0000_FF9B_B4D0_B607);
        let bytes = sqn.to_bytes();
        let parsed = Sqn::from_bytes(&bytes);
        assert_eq!(sqn, parsed);
    }

    #[test]
    fn sqn_increment_wraps() {
        let sqn = Sqn(u64::MAX);
        let next = sqn.increment();
        assert_eq!(next.0, 0);
    }

    #[test]
    fn auth_key_from_hex_roundtrip() {
        let hex_str = "465b5ce8b199b49faa5f0a2ee238a6bc";
        let key = AuthKey::from_hex(hex_str).expect("valid hex");
        assert_eq!(hex::encode(key.0), hex_str);
    }

    #[test]
    fn auth_key_from_hex_rejects_short() {
        assert!(AuthKey::from_hex("deadbeef").is_err());
    }
}
