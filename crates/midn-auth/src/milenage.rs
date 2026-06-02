// crates/midn-auth/src/milenage.rs
//! Milenage authentication algorithm — 3GPP TS 35.205 / 35.206

use aes::{Aes128, cipher::{BlockEncrypt, KeyInit}};
use subtle::ConstantTimeEq;

use crate::keys::{Amf, AuthKey, AuthVector, OpCode, Rand, Sqn};

// ── AES-128 ───────────────────────────────────────────────────────────────────

#[inline]
fn aes128(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new_from_slice(key).expect("16-byte key");
    let mut block = *input;
    cipher.encrypt_block(aes::Block::from_mut_slice(&mut block));
    block
}

// ── Milenage core ─────────────────────────────────────────────────────────────
//
// 3GPP TS 35.206 Annex 1 C reference formula:
//   RijndaelInput[(i + r/8) % 16] = TEMP[i] ^ OPc[i]
//
// Rotation offsets (r/8 bytes):
//   f1 / f4 : r=64 bits → offset=8  (symmetric for 16-byte block)
//   f2 / f5 : r=0  bits → offset=0  (no rotation)
//   f3      : r=32 bits → offset=4
//   f5*     : r=96 bits → offset=12
//
// Constants c1..c5 XOR only byte 15 of the working array:
//   c1=0x00, c2=0x01, c3=0x02, c4=0x04, c5=0x08

fn milenage_core(
    ki:  &[u8; 16],
    opc: &[u8; 16],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
) -> (
    [u8; 8],   // mac_a  (f1)
    [u8; 8],   // xres   (f2)
    [u8; 16],  // ck     (f3)
    [u8; 16],  // ik     (f4)
    [u8; 6],   // ak     (f5)
) {
    let mut input = [0u8; 16];
    let mut in1   = [0u8; 16];

    // TEMP = E[RAND XOR OPc]_K
    for i in 0..16 { input[i] = rand[i] ^ opc[i]; }
    let temp = aes128(ki, &input);

    // IN1 = SQN || AMF || SQN || AMF
    for i in 0..6 { in1[i] = sqn[i]; in1[i + 8] = sqn[i]; }
    for i in 0..2 { in1[i + 6] = amf[i]; in1[i + 14] = amf[i]; }

    // f1: MAC-A = OUT1[0..7]
    // OUT1 = E[rot(TEMP^OPc, r1=64bits) XOR c1=0 XOR IN1]_K XOR OPc
    // C ref: input[(i + 8) % 16] = TEMP[i] ^ OPc[i]  (offset = r1/8 = 8)
    for i in 0..16 { input[(i + 8) % 16] = temp[i] ^ opc[i]; }
    for i in 0..16 { input[i] ^= in1[i]; }
    let mut out1 = aes128(ki, &input);
    for i in 0..16 { out1[i] ^= opc[i]; }
    let mut mac_a = [0u8; 8];
    mac_a.copy_from_slice(&out1[0..8]);

    // f2/f5: XRES + AK
    // OUT2 = E[(TEMP^OPc) XOR c2=0x01]_K XOR OPc  (r2=0, no rotation)
    for i in 0..16 { input[i] = temp[i] ^ opc[i]; }
    input[15] ^= 0x01;
    let mut out2 = aes128(ki, &input);
    for i in 0..16 { out2[i] ^= opc[i]; }
    let mut xres = [0u8; 8];
    xres.copy_from_slice(&out2[8..16]);
    let mut ak = [0u8; 6];
    ak.copy_from_slice(&out2[0..6]);

    // f3: CK
    // OUT3 = E[rot(TEMP^OPc, r3=32bits) XOR c3=0x02]_K XOR OPc
    // C ref: input[(i + 4) % 16] = TEMP[i] ^ OPc[i]  (offset = r3/8 = 4)
    for i in 0..16 { input[(i + 4) % 16] = temp[i] ^ opc[i]; }
    input[15] ^= 0x02;
    let mut ck = aes128(ki, &input);
    for i in 0..16 { ck[i] ^= opc[i]; }

    // f4: IK
    // OUT4 = E[rot(TEMP^OPc, r4=64bits) XOR c4=0x04]_K XOR OPc
    // C ref: input[(i + 8) % 16] = TEMP[i] ^ OPc[i]  (offset = r4/8 = 8)
    for i in 0..16 { input[(i + 8) % 16] = temp[i] ^ opc[i]; }
    input[15] ^= 0x04;
    let mut ik = aes128(ki, &input);
    for i in 0..16 { ik[i] ^= opc[i]; }

    (mac_a, xres, ck, ik, ak)
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct MilenageContext {
    ki:  AuthKey,
    opc: OpCode,
}

impl MilenageContext {
    pub fn new(ki: AuthKey, opc: OpCode) -> Self { Self { ki, opc } }

    pub fn compute_opc(ki: &AuthKey, op: &[u8; 16]) -> OpCode {
        let mut enc = aes128(&ki.0, op);
        for i in 0..16 { enc[i] ^= op[i]; }
        OpCode(enc)
    }

    pub fn generate_vector(&self, sqn: Sqn, amf: Amf) -> AuthVector {
        let rand = Self::generate_rand();
        let sqn_bytes = sqn.to_bytes();
        let (mac_a, xres, ck, ik, ak) =
            milenage_core(&self.ki.0, &self.opc.0, &rand.0, &sqn_bytes, &amf.0);
        let mut autn = [0u8; 16];
        for i in 0..6 { autn[i] = sqn_bytes[i] ^ ak[i]; }
        autn[6..8].copy_from_slice(&amf.0);
        autn[8..16].copy_from_slice(&mac_a);
        AuthVector { rand, autn, xres, ck, ik }
    }

    #[inline]
    pub fn verify_res(xres: &[u8; 8], res: &[u8; 8]) -> bool {
        xres.ct_eq(res).into()
    }

    fn generate_rand() -> Rand { Rand(rand::random()) }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{AuthKey, OpCode};

    fn h(s: &str) -> Vec<u8> { hex::decode(s).expect("valid hex") }
    fn a16(v: &[u8]) -> [u8; 16] { v.try_into().expect("16 bytes") }
    fn a6(v: &[u8])  -> [u8; 6]  { v.try_into().expect("6 bytes")  }

    // ── Primitives ────────────────────────────────────────────────────────────

    #[test]
    fn aes128_nist_vector() {
        let key = a16(&h("2b7e151628aed2a6abf7158809cf4f3c"));
        let pt  = a16(&h("3243f6a8885a308d313198a2e0370734"));
        let ct  = a16(&h("3925841d02dc09fbdc118597196a0b32"));
        assert_eq!(aes128(&key, &pt), ct);
    }

    #[test]
    fn compute_opc_test_set_1() {
        let k  = AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
        let op = a16(&h("cdc202d5123e20f62b6d676ac72cb318"));
        let opc = MilenageContext::compute_opc(&k, &op);
        assert_eq!(hex::encode(opc.0), "cd63cb71954a9f4e48a5994e37a02baf");
    }

    // ── Diagnostic: step-by-step f3 rotation verification ────────────────────
    //
    // Verifies the f3 rotation offset=4 (r3=32 bits, C ref formula: (i+4)%16).
    // The scatter `input[(i+4)%16] = val[i]` places val[12..15] at positions
    // [0..3] and val[0..11] at positions [4..15] — a right-rotation by 4 bytes.
    #[test]
    fn diagnose_f3_rotation_offset() {
        let ki   = a16(&h("465b5ce8b199b49faa5f0a2ee238a6bc"));
        let opc  = a16(&h("cd63cb71954a9f4e48a5994e37a02baf"));
        let rand = a16(&h("23553cbe9637a89d218ae64dae47bf35"));
        let sqn  = a6(&h("ff9bb4d0b607"));
        let amf: [u8; 2] = h("b9b9").try_into().unwrap();

        // TEMP
        let mut buf = [0u8; 16];
        for i in 0..16 { buf[i] = rand[i] ^ opc[i]; }
        let temp = aes128(&ki, &buf);

        // TEMP^OPC
        let mut topo = [0u8; 16];
        for i in 0..16 { topo[i] = temp[i] ^ opc[i]; }

        // f3 rotation: offset=4 → input[(i+4)%16] = topo[i]
        // Result: [topo[12], topo[13], topo[14], topo[15], topo[0], ..., topo[11]]
        let mut rot = [0u8; 16];
        for i in 0..16 { rot[(i + 4) % 16] = topo[i]; }

        // Verify rot[0..3] = topo[12..15]
        assert_eq!(&rot[0..4], &topo[12..16], "f3 rot: first 4 bytes should be topo[12..15]");
        // Verify rot[4..16] = topo[0..12]
        assert_eq!(&rot[4..16], &topo[0..12], "f3 rot: bytes 4..15 should be topo[0..11]");

        // Then XOR c3=0x02 at byte 15
        rot[15] ^= 0x02;

        // AES then XOR OPC → CK = first 16 bytes of OUT3
        let mut out3 = aes128(&ki, &rot);
        for i in 0..16 { out3[i] ^= opc[i]; }

        // Expected CK from 3GPP TS 35.207 test set 1
        assert_eq!(hex::encode(out3), "b40ba9a3c58b2a05bbf0d987b21bf8cb", "f3 CK");
    }

    // ── f-function isolation (all 5 functions, test set 1) ───────────────────

    #[test]
    fn diagnose_f_function_isolation() {
        let ki   = a16(&h("465b5ce8b199b49faa5f0a2ee238a6bc"));
        let opc  = a16(&h("cd63cb71954a9f4e48a5994e37a02baf"));
        let rand = a16(&h("23553cbe9637a89d218ae64dae47bf35"));
        let sqn  = a6(&h("ff9bb4d0b607"));
        let amf: [u8; 2] = h("b9b9").try_into().unwrap();
        let (mac_a, xres, ck, ik, ak) = milenage_core(&ki, &opc, &rand, &sqn, &amf);
        assert_eq!(hex::encode(ak),    "aa689c648370",                      "f5 AK");
        assert_eq!(hex::encode(xres),  "a54211d5e3ba50bf",                  "f2 XRES");
        assert_eq!(hex::encode(ck),    "b40ba9a3c58b2a05bbf0d987b21bf8cb", "f3 CK");
        assert_eq!(hex::encode(ik),    "f769bcd751044604127672711c6d3441", "f4 IK");
        assert_eq!(hex::encode(mac_a), "4a9ffac354dfafb3",                  "f1 MAC-A");
    }

    // ── Test vector runner ────────────────────────────────────────────────────

    fn run(k: &str, opc: &str, rand: &str, sqn: &str, amf: &str,
           exp_mac_a: &str, exp_xres: &str, exp_ck: &str, exp_ik: &str, exp_ak: &str,
           label: &str) {
        let ki   = a16(&h(k));
        let opc  = a16(&h(opc));
        let rand = a16(&h(rand));
        let sqn  = a6(&h(sqn));
        let amf: [u8; 2] = h(amf).try_into().expect("2-byte AMF");
        let (mac_a, xres, ck, ik, ak) = milenage_core(&ki, &opc, &rand, &sqn, &amf);
        assert_eq!(hex::encode(ak),    exp_ak,    "{label}: AK");
        assert_eq!(hex::encode(xres),  exp_xres,  "{label}: XRES");
        assert_eq!(hex::encode(ck),    exp_ck,    "{label}: CK");
        assert_eq!(hex::encode(ik),    exp_ik,    "{label}: IK");
        assert_eq!(hex::encode(mac_a), exp_mac_a, "{label}: MAC-A");
    }

    #[test]
    fn test_set_1() {
        run("465b5ce8b199b49faa5f0a2ee238a6bc",
            "cd63cb71954a9f4e48a5994e37a02baf",
            "23553cbe9637a89d218ae64dae47bf35",
            "ff9bb4d0b607", "b9b9",
            "4a9ffac354dfafb3",
            "a54211d5e3ba50bf",
            "b40ba9a3c58b2a05bbf0d987b21bf8cb",
            "f769bcd751044604127672711c6d3441",
            "aa689c648370",
            "Test Set 1");
    }

    #[test]
    fn test_set_2() {
        // All values from 3GPP TS 35.207 Test Set 2.
        // K  = 0396eb317b6d1c36f19c1c84cd6ffd16
        // OP = ff9508d43e0d97fc1682d1b71a574f9f
        // OPc= 53c15671c60a4b731c55b4a441c0bde2
        run("0396eb317b6d1c36f19c1c84cd6ffd16",
            "53c15671c60a4b731c55b4a441c0bde2",
            "c80ab1d1902ef4686eb49be29f943bbc",
            "9d0277595bad", "df0b",
            "9cabc3e99baf7281",
            "8a3a8decca3b6c0d",
            "96b97b2a4d8b0e29aa9b6fc5ea5e48c7",
            "b91e61e23dfbe5c1d50e3cf793dfc4c4",
            "b35debc06189",
            "Test Set 2");
    }

    #[test]
    fn test_set_3() {
        // All values from 3GPP TS 35.207 Test Set 3.
        // K  = fec86ba6eb707ed08905757b1bb44b8f
        // OP = dbc59adcb6f9a0ef735477b7fadf8374
        // OPc= 1006020f0a478bf6b699f15c062e42b3
        run("fec86ba6eb707ed08905757b1bb44b8f",
            "1006020f0a478bf6b699f15c062e42b3",
            "9f7c8d021accf4db213ccff0c7f71a6a",
            "9d0277595bad", "df0b",
            "8011c48c0c214ed2",
            "16c8233f05a0ac28",
            "5dbcbcb0800ccef0848720b5bf6c2e1a",
            "e4abc4d8b6cf3dd2bb6ba74d8d30d174",
            "33484dc2136b",
            "Test Set 3");
    }

    #[test]
    #[ignore = "fill in from 3GPP TS 35.207 Test Set 4"]
    fn test_set_4() { todo!() }

    #[test]
    #[ignore = "fill in from 3GPP TS 35.207 Test Set 5"]
    fn test_set_5() { todo!() }

    #[test]
    #[ignore = "fill in from 3GPP TS 35.207 Test Set 6"]
    fn test_set_6() { todo!() }

    #[test]
    fn test_set_1_autn_construction() {
        let ki  = AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
        let opc = OpCode::from_hex("cd63cb71954a9f4e48a5994e37a02baf").unwrap();
        let ctx = MilenageContext::new(ki, opc);
        let sqn = Sqn::from_bytes(&[0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07]);
        let amf = Amf([0xB9, 0xB9]);
        let vec = ctx.generate_vector(sqn, amf);
        assert_eq!(hex::encode(vec.autn), "55f328b43577b9b94a9ffac354dfafb3");
        assert_eq!(hex::encode(vec.xres), "a54211d5e3ba50bf");
        assert_eq!(hex::encode(vec.ck),   "b40ba9a3c58b2a05bbf0d987b21bf8cb");
        assert_eq!(hex::encode(vec.ik),   "f769bcd751044604127672711c6d3441");
    }

    #[test]
    fn verify_res_accepts_matching() {
        let x = [0xA5u8,0x42,0x11,0xD5,0xE3,0xBA,0x50,0xBF];
        assert!(MilenageContext::verify_res(&x, &x));
    }

    #[test]
    fn verify_res_rejects_wrong() {
        let x = [0xA5u8,0x42,0x11,0xD5,0xE3,0xBA,0x50,0xBF];
        assert!(!MilenageContext::verify_res(&x, &[0u8;8]));
    }

    #[test]
    fn verify_res_rejects_off_by_one() {
        let x = [0x01u8,0x02,0x03,0x04,0x05,0x06,0x07,0x08];
        let y = [0x01u8,0x02,0x03,0x04,0x05,0x06,0x07,0xFF];
        assert!(!MilenageContext::verify_res(&x, &y));
    }
    }
