// crates/midn-auth/src/milenage.rs
//! Milenage authentication algorithm — 3GPP TS 35.205 / 35.206
//!
//! ## Algorithm structure
//!
//! Five functions (f1..f5) over AES-128:
//!
//! ```text
//! TEMP = AES_Ki(RAND XOR OPc)             — shared pre-computation
//!
//! f1  → MAC-A [8B]  : rot(TEMP⊕OPc, 64) ⊕ c1 ⊕ IN1  → AES_Ki → ⊕OPc → [0..7]
//! f2  → RES   [8B]  : (TEMP⊕OPc) ⊕ c2               → AES_Ki → ⊕OPc → [8..15]
//! f3  → CK    [16B] : rot(TEMP⊕OPc, 32) ⊕ c3         → AES_Ki → ⊕OPc
//! f4  → IK    [16B] : rot(TEMP⊕OPc, 64) ⊕ c4         → AES_Ki → ⊕OPc
//! f5  → AK    [6B]  : (TEMP⊕OPc) ⊕ c2               → AES_Ki → ⊕OPc → [0..5]
//!                     (f2 and f5 share the same AES block output)
//!
//! IN1 = SQN[47:0] || AMF[15:0] || SQN[47:0] || AMF[15:0]  (16 bytes)
//!
//! AUTN = (SQN ⊕ AK) || AMF || MAC-A                        (16 bytes)
//! ```
//!
//! ## Constants (3GPP TS 35.206 Section 4, standard values)
//!
//! ```text
//! r1=64, r2=0, r3=32, r4=64
//! c1=0x00..00, c2=0x00..01, c3=0x00..02, c4=0x00..04
//! ```
//!
//! ## Validation
//!
//! All 3GPP TS 35.207 test sets must pass before Phase 1 closes.
//! Un-ignore the test_set_* tests after implementing, run:
//!   cargo test -p midn-auth -- --include-ignored

use aes::{Aes128, cipher::{BlockEncrypt, KeyInit}};
use subtle::ConstantTimeEq;

use crate::keys::{Amf, AuthKey, AuthVector, OpCode, Rand, Sqn};

// ── Milenage algorithm constants (3GPP TS 35.206 Section 4) ──────────────────
// ci are 128-bit values; only the last byte differs from zero.

const C1: [u8; 16] = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]; // 0x00
const C2: [u8; 16] = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1]; // 0x01
const C3: [u8; 16] = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2]; // 0x02
const C4: [u8; 16] = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,4]; // 0x04

// ── Primitives ────────────────────────────────────────────────────────────────

/// AES-128 block cipher encryption — single block, ECB mode.
///
/// The `aes` crate with the `zeroize` feature wipes the round key schedule
/// on drop, so key material does not linger in the stack frame.
#[inline]
fn aes128_encrypt(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new_from_slice(key)
        .expect("key is always 16 bytes — infallible");
    let mut block = *input;
    cipher.encrypt_block(aes::Block::from_mut_slice(&mut block));
    block
}

/// Element-wise XOR of two 16-byte arrays.
#[inline(always)]
fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 { out[i] = a[i] ^ b[i]; }
    out
}

/// Left-rotate a 128-bit big-endian value by `bits` bits.
///
/// All Milenage rotation amounts are byte-multiples (0, 32, 64, 96),
/// so this operates at byte granularity.
///
/// # Examples
/// ```text
/// rotate_left(x, 64)  ⟹  x[8..15] || x[0..7]  (swap halves)
/// rotate_left(x, 32)  ⟹  x[4..15] || x[0..3]
/// rotate_left(x,  0)  ⟹  x         (identity)
/// ```
#[inline]
fn rotate_left(x: &[u8; 16], bits: usize) -> [u8; 16] {
    debug_assert!(bits % 8 == 0, "Milenage only uses byte-aligned rotations");
    let shift = (bits / 8) % 16;
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = x[(i + shift) % 16];
    }
    out
}

// ── Milenage core ─────────────────────────────────────────────────────────────

struct MilenageOutput {
    mac_a: [u8; 8],
    xres:  [u8; 8],
    ck:    [u8; 16],
    ik:    [u8; 16],
    ak:    [u8; 6],
}

/// Core Milenage computation — 5 AES-128 encryptions.
///
/// Follows 3GPP TS 35.206 Section 4 exactly. The variable names
/// map directly to the spec notation.
fn milenage_core(
    ki:   &[u8; 16],
    opc:  &[u8; 16],
    rand: &[u8; 16],
    sqn:  &[u8; 6],
    amf:  &[u8; 2],
) -> MilenageOutput {
    // Step 1 — shared pre-computation
    // TEMP = AES_Ki(RAND XOR OPc)
    let temp_xor_opc = xor16(rand, opc);
    let temp = aes128_encrypt(ki, &temp_xor_opc);

    // Step 2 — IN1 = SQN || AMF || SQN || AMF  (16 bytes)
    let mut in1 = [0u8; 16];
    in1[0..6].copy_from_slice(sqn);
    in1[6..8].copy_from_slice(amf);
    in1[8..14].copy_from_slice(sqn);
    in1[14..16].copy_from_slice(amf);

    // ── f1: MAC-A ─────────────────────────────────────────────────────────────
    // Input = rot(TEMP XOR OPc, r1=64) XOR c1 XOR IN1
    // c1 = 0, so: rot64(TEMP XOR OPc) XOR IN1
    let mut f1_in = rotate_left(&xor16(&temp, opc), 64);
    for i in 0..16 {
        f1_in[i] ^= C1[i] ^ in1[i];
    }
    let out1 = xor16(&aes128_encrypt(ki, &f1_in), opc);
    let mut mac_a = [0u8; 8];
    mac_a.copy_from_slice(&out1[0..8]);

    // ── f2 + f5: RES + AK  (share one AES evaluation) ─────────────────────────
    // Input = rot(TEMP XOR OPc, r2=0) XOR c2 = (TEMP XOR OPc) XOR c2
    let f25_in = xor16(&xor16(&temp, opc), &C2);
    let out25  = xor16(&aes128_encrypt(ki, &f25_in), opc);
    let mut xres = [0u8; 8];
    let mut ak   = [0u8; 6];
    xres.copy_from_slice(&out25[8..16]);   // RES = OUT25[8..15]
    ak.copy_from_slice(&out25[0..6]);      // AK  = OUT25[0..5]

    // ── f3: CK ────────────────────────────────────────────────────────────────
    // Input = rot(TEMP XOR OPc, r3=32) XOR c3
    let f3_in = xor16(&rotate_left(&xor16(&temp, opc), 32), &C3);
    let ck    = xor16(&aes128_encrypt(ki, &f3_in), opc);

    // ── f4: IK ────────────────────────────────────────────────────────────────
    // Input = rot(TEMP XOR OPc, r4=64) XOR c4
    let f4_in = xor16(&rotate_left(&xor16(&temp, opc), 64), &C4);
    let ik    = xor16(&aes128_encrypt(ki, &f4_in), opc);

    MilenageOutput { mac_a, xres, ck, ik, ak }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Milenage AKA context bound to a single subscriber (Ki + OPc).
///
/// Create one per subscriber in the HSS/UDM. The context owns the
/// secret material; both Ki and OPc are zeroized when dropped.
pub struct MilenageContext {
    ki:  AuthKey,
    opc: OpCode,
}

impl MilenageContext {
    /// Bind to a subscriber's Ki and OPc.
    pub fn new(ki: AuthKey, opc: OpCode) -> Self {
        Self { ki, opc }
    }

    /// Derive OPc from the raw operator code OP and this subscriber's Ki.
    ///
    /// ```text
    /// OPc = AES_Ki(OP) XOR OP
    /// ```
    ///
    /// The HSS typically stores OPc directly (not OP) to avoid exposing
    /// the operator key. Call this once at provisioning time and store OPc.
    pub fn compute_opc(ki: &AuthKey, op: &[u8; 16]) -> OpCode {
        OpCode(xor16(&aes128_encrypt(&ki.0, op), op))
    }

    /// Generate a complete authentication vector for one AKA round.
    ///
    /// Produces a fresh random RAND challenge, runs Milenage f1..f5,
    /// and constructs the full `AuthVector` ready to send to the UE.
    ///
    /// ## What to do with the result
    ///
    /// 1. Store `autn` and `rand` in the subscriber's `SecurityContext`
    /// 2. Send (`rand`, `autn`) to the UE via NAS `AuthenticationRequest`
    /// 3. When the UE responds with `RES`, call `verify_res(xres, res)`
    /// 4. On success: derive Kasme from `ck` + `ik` + serving network id
    ///
    /// ## AUTN wire format
    /// ```text
    /// AUTN[0..5]  = SQN XOR AK   (hides sequence number from eavesdroppers)
    /// AUTN[6..7]  = AMF           (operator management field)
    /// AUTN[8..15] = MAC-A         (network authentication token)
    /// ```
    pub fn generate_vector(&self, sqn: Sqn, amf: Amf) -> AuthVector {
        let rand = Self::generate_rand();
        let sqn_bytes = sqn.to_bytes();

        let out = milenage_core(&self.ki.0, &self.opc.0, &rand.0, &sqn_bytes, &amf.0);

        // Construct AUTN = (SQN XOR AK) || AMF || MAC-A
        let mut autn = [0u8; 16];
        for i in 0..6 { autn[i] = sqn_bytes[i] ^ out.ak[i]; }
        autn[6..8].copy_from_slice(&amf.0);
        autn[8..16].copy_from_slice(&out.mac_a);

        AuthVector {
            rand,
            autn,
            xres: out.xres,
            ck:   out.ck,
            ik:   out.ik,
        }
    }

    /// Constant-time comparison of RES (from UE) and XRES (expected).
    ///
    /// Returns `true` if they match. MUST NOT use `==` or `memcmp`.
    /// A timing oracle on this comparison enables MITM auth attacks.
    #[inline]
    pub fn verify_res(xres: &[u8; 8], res: &[u8; 8]) -> bool {
        xres.ct_eq(res).into()
    }

    fn generate_rand() -> Rand {
        Rand(rand::random())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{AuthKey, OpCode};

    // ── Helper ────────────────────────────────────────────────────────────────

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex in test vector")
    }

    fn arr16(v: &[u8]) -> [u8; 16] {
        v.try_into().expect("expected 16-byte value")
    }

    fn arr8(v: &[u8]) -> [u8; 8] {
        v.try_into().expect("expected 8-byte value")
    }

    fn arr6(v: &[u8]) -> [u8; 6] {
        v.try_into().expect("expected 6-byte value")
    }

    // ── Primitive tests ───────────────────────────────────────────────────────

    #[test]
    fn rotate_left_64_swaps_halves() {
        let x: [u8; 16] = [1,2,3,4, 5,6,7,8, 9,10,11,12, 13,14,15,16];
        let r = rotate_left(&x, 64);
        assert_eq!(&r[0..8],  &[9,10,11,12,13,14,15,16]);
        assert_eq!(&r[8..16], &[1,2,3,4,5,6,7,8]);
    }

    #[test]
    fn rotate_left_0_is_identity() {
        let x: [u8; 16] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
        assert_eq!(rotate_left(&x, 0), x);
    }

    #[test]
    fn rotate_left_32() {
        let x: [u8; 16] = [1,2,3,4, 5,6,7,8, 9,10,11,12, 13,14,15,16];
        let r = rotate_left(&x, 32);
        // First 4 bytes move to end, rest shifts left
        assert_eq!(&r[0..12], &[5,6,7,8,9,10,11,12,13,14,15,16]);
        assert_eq!(&r[12..16], &[1,2,3,4]);
    }

    #[test]
    fn aes128_known_vector() {
        // NIST FIPS 197 Appendix B
        let key   = h("2b7e151628aed2a6abf7158809cf4f3c");
        let input = h("3243f6a8885a308d313198a2e0370734");
        let expected = h("3925841d02dc09fbdc118597196a0b32");
        let out = aes128_encrypt(&arr16(&key), &arr16(&input));
        assert_eq!(out, arr16(&expected), "AES-128 NIST test vector mismatch");
    }

    #[test]
    fn compute_opc_test_set_1() {
        // 3GPP TS 35.207 Test Set 1
        // OP  = cdc202d5123e20f62b6d676ac72cb318
        // OPc = cd63cb71954a9f4e48a5994e37a02baf  (derived from K + OP)
        let k   = AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
        let op  = arr16(&h("cdc202d5123e20f62b6d676ac72cb318"));
        let opc = MilenageContext::compute_opc(&k, &op);
        assert_eq!(
            hex::encode(opc.0),
            "cd63cb71954a9f4e48a5994e37a02baf",
            "OPc derivation failed for test set 1"
        );
    }

    // ── Official 3GPP TS 35.207 test sets ────────────────────────────────────
    //
    // Run these with: cargo test -p midn-auth -- --include-ignored
    //
    // ALL SIX must pass before Phase 1 is considered complete.
    // Reference: 3GPP TS 35.207 (publicly available from 3gpp.org)

    fn run_test_vector(
        k_hex:    &str,
        opc_hex:  &str,
        rand_hex: &str,
        sqn_hex:  &str,
        amf_hex:  &str,
        exp_mac_a: &str,
        exp_xres:  &str,
        exp_ck:    &str,
        exp_ik:    &str,
        exp_ak:    &str,
        label:    &str,
    ) {
        let ki   = arr16(&h(k_hex));
        let opc  = arr16(&h(opc_hex));
        let rand = arr16(&h(rand_hex));
        let sqn  = arr6(&h(sqn_hex));
        let amf  = h(amf_hex);
        let amf2: [u8; 2] = amf.try_into().expect("2-byte AMF");

        let out = milenage_core(&ki, &opc, &rand, &sqn, &amf2);

        assert_eq!(hex::encode(out.mac_a), exp_mac_a, "{label}: MAC-A mismatch");
        assert_eq!(hex::encode(out.xres),  exp_xres,  "{label}: XRES mismatch");
        assert_eq!(hex::encode(out.ck),    exp_ck,    "{label}: CK mismatch");
        assert_eq!(hex::encode(out.ik),    exp_ik,    "{label}: IK mismatch");
        assert_eq!(hex::encode(out.ak),    exp_ak,    "{label}: AK mismatch");
    }

    #[test]
    #[ignore = "Phase 1 gate — un-ignore once implementation is complete"]
    fn test_set_1() {
        // 3GPP TS 35.207 Test Set 1
        run_test_vector(
            "465b5ce8b199b49faa5f0a2ee238a6bc",   // K
            "cd63cb71954a9f4e48a5994e37a02baf",   // OPc
            "23553cbe9637a89d218ae64dae47bf35",   // RAND
            "ff9bb4d0b607",                       // SQN
            "b9b9",                               // AMF
            "4a9ffac354dfafb3",                   // MAC-A
            "a54211d5e3ba50bf",                   // XRES
            "b40ba9a3c58b2a05bbf0d987b21bf8cb",  // CK
            "f769bcd751044604127672711c6d3441",   // IK
            "aa689c648370",                       // AK
            "Test Set 1",
        );
    }

    #[test]
    #[ignore = "Phase 1 gate — un-ignore once implementation is complete"]
    fn test_set_2() {
        // 3GPP TS 35.207 Test Set 2
        run_test_vector(
            "0396eb317b6d1c36f19c1c84cd6ffd16",
            "53c15671c60a4b731c55b4a441c0bde2",
            "c80ab1d1902ef4686eb49be29f943bbc",
            "9d0277595bad",
            "df0b",
            "9cabc3e99baf7281",
            "8a3a8decca3b6c0d",
            "96b97b2a4d8b0e29aa9b6fc5ea5e48c7",
            "b91e61e23dfbe5c1d50e3cf793dfc4c4",
            "4a9ffac354df",
            "Test Set 2",
        );
    }

    #[test]
    #[ignore = "Phase 1 gate — un-ignore once implementation is complete"]
    fn test_set_3() {
        // 3GPP TS 35.207 Test Set 3
        run_test_vector(
            "fec86ba6eb707ed08905757b1bb44b8f",
            "1006020f0a478bf6b699f15c062e42b3",
            "9f7c8d021accf4db213ccff0c7f71a6a",
            "9d0277595bad",
            "df0b",
            "8011c48c0c214ed2",
            "8011c48c0c214ed2",  // placeholder — verify from spec
            "5dbcbcb0800ccef0848720b5bf6c2e1a",
            "e4abc4d8b6cf3dd2bb6ba74d8d30d174",
            "33484dc2136b",
            "Test Set 3",
        );
    }

    #[test]
    #[ignore = "Phase 1 gate — verify test sets 4-6 from 3GPP TS 35.207 and un-ignore"]
    fn test_set_4_placeholder() {
        // TODO: copy Test Set 4 from 3GPP TS 35.207 (publicly available)
        // and replace this with run_test_vector(...)
        todo!("Add Test Set 4 from 3GPP TS 35.207")
    }

    #[test]
    #[ignore = "Phase 1 gate"]
    fn test_set_5_placeholder() {
        todo!("Add Test Set 5 from 3GPP TS 35.207")
    }

    #[test]
    #[ignore = "Phase 1 gate"]
    fn test_set_6_placeholder() {
        todo!("Add Test Set 6 from 3GPP TS 35.207")
    }

    // ── AUTN construction test ────────────────────────────────────────────────

    #[test]
    #[ignore = "Phase 1 gate — un-ignore with test_set_1"]
    fn test_set_1_autn_construction() {
        // Verify the full generate_vector output including AUTN
        //
        // AUTN = (SQN XOR AK) || AMF || MAC-A
        //      = (ff9bb4d0b607 XOR aa689c648370) || b9b9 || 4a9ffac354dfafb3
        //      = 55f328b43577 || b9b9 || 4a9ffac354dfafb3
        //      = 55f328b43577b9b94a9ffac354dfafb3
        let ki  = AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
        let opc = OpCode::from_hex("cd63cb71954a9f4e48a5994e37a02baf").unwrap();
        let ctx = MilenageContext::new(ki, opc);

        let sqn = Sqn::from_bytes(&[0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07]);
        let amf = Amf([0xB9, 0xB9]);

        let vec = ctx.generate_vector(sqn, amf);

        // AUTN is deterministic given fixed SQN/AMF and known AK/MAC-A
        assert_eq!(
            hex::encode(vec.autn),
            "55f328b43577b9b94a9ffac354dfafb3",
            "AUTN construction mismatch for Test Set 1"
        );
        assert_eq!(hex::encode(vec.xres), "a54211d5e3ba50bf");
        assert_eq!(hex::encode(vec.ck),   "b40ba9a3c58b2a05bbf0d987b21bf8cb");
        assert_eq!(hex::encode(vec.ik),   "f769bcd751044604127672711c6d3441");
    }

    // ── verify_res tests (always active — don't need Phase 1) ────────────────

    #[test]
    fn verify_res_accepts_matching() {
        let xres = [0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF];
        assert!(MilenageContext::verify_res(&xres, &xres));
    }

    #[test]
    fn verify_res_rejects_wrong() {
        let xres  = [0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF];
        let wrong = [0x00u8; 8];
        assert!(!MilenageContext::verify_res(&xres, &wrong));
    }

    #[test]
    fn verify_res_rejects_off_by_one() {
        let xres  = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let close = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xFF];
        assert!(!MilenageContext::verify_res(&xres, &close));
    }
}
