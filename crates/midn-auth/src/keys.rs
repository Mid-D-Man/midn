//! Cryptographic key types for subscriber authentication.
//!
//! All secret types implement Zeroize so key material is wiped from
//! memory when they go out of scope. Never store Ki in plain fields.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// 128-bit subscriber authentication key (Ki).
/// Stored on the SIM and in the HSS/UDM. NEVER transmitted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AuthKey(pub [u8; 16]);

/// 128-bit Operator Code variant (OPc).
/// Derived from OP and Ki. Stored in the HSS.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OpCode(pub [u8; 16]);

/// 128-bit random challenge (RAND). Generated per-authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rand(pub [u8; 16]);

/// 48-bit Sequence Number (SQN). Monotonically increasing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sqn(pub u64); // top 48 bits used

/// PLMN identity (MCC + MNC, 3 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plmn(pub [u8; 3]);

/// Authentication vector output from Milenage/TUAK.
/// RES, CK, IK, AUTN as defined in 3GPP TS 33.401.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthVector {
    /// Expected response (sent to UE for comparison)
    pub rand: Rand,
    /// Network authentication token sent to UE
    pub autn: [u8; 16],
    /// Expected response from UE (32-bit for LTE)
    pub xres: [u8; 8],
    /// Cipher key
    pub ck:   [u8; 16],
    /// Integrity key
    pub ik:   [u8; 16],
}
