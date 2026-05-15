# Phase 1 — Foundation & Identity

## Goal

Implement the Milenage AKA procedure such that:
- Given (Ki, OPc, RAND, SQN, AMF) produce (AUTN, XRES, CK, IK)
- All 3GPP TS 35.207 official test vectors pass
- Auth vector generation < 10 µs (constant-time)

## Milenage Algorithm

Milenage is built on 5 functions (f1..f5*) over AES-128:

| Function | Output | Purpose |
|---|---|---|
| f1 | MAC-A (8 bytes) | Network auth token |
| f2 | RES (8 bytes) | UE response |
| f3 | CK (16 bytes) | Cipher key |
| f4 | IK (16 bytes) | Integrity key |
| f5 | AK (6 bytes) | Anonymity key |
| f1* | MAC-S | Re-sync MAC |
| f5* | AK* | Re-sync AK |

## Test Strategy

1. Implement AES-128 core (use `aes` crate with `zeroize` feature)
2. Implement f1..f5* against spec
3. Validate against 3GPP TS 35.207 test set 1..6
4. Add constant-time property tests using subtle
5. Fuzz with cargo-fuzz targeting the auth vector generator
