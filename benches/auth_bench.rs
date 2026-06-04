// crates/midn-auth/benches/auth_bench.rs
//! Midn-auth benchmark suite — Criterion.rs
//!
//! Run: cargo bench -p midn-auth
//! Output: target/criterion/
//!
//! ## Phase gates
//!
//! | Benchmark                  | Gate     | Rationale                                              |
//! |----------------------------|----------|--------------------------------------------------------|
//! | milenage_generate_vector   | < 10 µs  | Full production path: getrandom + 5× AES-128 + AUTN   |
//! | milenage_core_fixed_rand   | < 10 µs  | Pure crypto only (no syscall) — isolates AES cost      |
//! | verify_res_constant_time   | < 25 ns  | subtle::ConstantTimeEq — constant-time is the goal     |
//! | generate_rand_os_csprng    | < 100 ns | getrandom(2) syscall baseline                          |
//!
//! ## Baselines
//!
//! Build #5  (2026-05-26, rustc 1.95.0):
//!   milenage_generate_vector : 603.07 ps  ← STUB, not real
//!   milenage_core_fixed_rand : —          ← new bench, pending Build #6
//!   verify_res_constant_time : 10.370 ns  ✅
//!   generate_rand_os_csprng  : 36.356 ns  ✅
//!
//! Build #6+ : first real Milenage numbers (Phase 1 closed Build #52)
//!   Expected milenage_generate_vector : ~1.0–1.1 µs  (getrandom ~36 ns + crypto)
//!   Expected milenage_core_fixed_rand : ~0.9–1.0 µs  (5× AES-128 + AUTN + ZeroizeOnDrop)
//!
//! ## Split rationale
//!
//! Two bench functions cover the same code path at different entry points:
//!   generate_vector         → getrandom(2) + milenage_core + AUTN + zeroize
//!   generate_vector_with_rand → milenage_core + AUTN + zeroize  (no syscall)
//!
//! The ~36 ns difference between them is the OS random generation cost.
//! If the gap ever exceeds 200 ns, investigate CSPRNG batching.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use midn_auth::keys::{Amf, AuthKey, OpCode, Rand, Sqn};
use midn_auth::milenage::MilenageContext;

fn bench_milenage_generate_vector(c: &mut Criterion) {
    // 3GPP TS 35.207 Test Set 1 inputs.
    let ki  = AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc")
        .expect("valid test key");
    let opc = OpCode::from_hex("cd63cb71954a9f4e48a5994e37a02baf")
        .expect("valid test opc");
    let sqn = Sqn::from_bytes(&[0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07]);
    let amf = Amf::STANDARD;

    // Gate: < 10 µs [RELEASE]
    //
    // Full production path — what the HSS calls for every attach request:
    //   1. getrandom(2) for fresh RAND (~36 ns, Build #5)
    //   2. Compute TEMP = E[RAND ⊕ OPc]_K
    //   3. Compute OUT1..OUT4 (f1, f2, f3, f4) — each one AES-128
    //   4. Build AUTN = (SQN ⊕ AK) ‖ AMF ‖ MAC-A
    //   5. Drop AuthVector → ZeroizeOnDrop wipes CK, IK, XRES
    c.bench_function("milenage_generate_vector", |b| {
        let ctx = MilenageContext::new(ki.clone(), opc.clone());
        b.iter(|| {
            black_box(ctx.generate_vector(black_box(sqn), black_box(amf)))
        })
    });
}

fn bench_milenage_core_fixed_rand(c: &mut Criterion) {
    let ki  = AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
    let opc = OpCode::from_hex("cd63cb71954a9f4e48a5994e37a02baf").unwrap();
    let sqn = Sqn::from_bytes(&[0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07]);
    let amf = Amf::STANDARD;
    // Fixed RAND from Test Set 1 — eliminates getrandom(2) syscall overhead
    // so this measures pure AES-128 computation + AUTN + ZeroizeOnDrop.
    let rand = Rand([
        0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
        0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
    ]);

    // Gate: < 10 µs [RELEASE]
    // Expected: ~0.9–1.0 µs on x86_64 with AES-NI.
    // This minus generate_rand_os_csprng ≈ milenage_generate_vector.
    c.bench_function("milenage_core_fixed_rand", |b| {
        let ctx = MilenageContext::new(ki.clone(), opc.clone());
        b.iter(|| {
            black_box(ctx.generate_vector_with_rand(
                black_box(sqn),
                black_box(amf),
                black_box(rand),
            ))
        })
    });
}

fn bench_verify_res(c: &mut Criterion) {
    let xres = black_box([0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF]);
    let res  = black_box([0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF]);

    // Gate: < 25 ns [RELEASE]
    //
    // Build #5 baseline: 10.370 ns.
    //
    // IMPORTANT: do NOT tighten this gate below 15 ns.
    // subtle::ConstantTimeEq is deliberately resistant to compiler
    // optimisations. A result of < 5 ns would mean the compiler eliminated
    // the constant-time property — that is a security regression, not a win.
    c.bench_function("verify_res_constant_time", |b| {
        b.iter(|| {
            MilenageContext::verify_res(black_box(&xres), black_box(&res))
        })
    });
}

fn bench_rand_generation(c: &mut Criterion) {
    // Gate: < 100 ns [RELEASE]
    // Build #5 baseline: 36.356 ns.
    // This is the getrandom(2) syscall cost that adds to milenage_generate_vector.
    c.bench_function("generate_rand_os_csprng", |b| {
        b.iter(|| {
            let r: [u8; 16] = rand::random();
            black_box(r)
        })
    });
}

criterion_group!(
    benches,
    bench_milenage_generate_vector,
    bench_milenage_core_fixed_rand,
    bench_verify_res,
    bench_rand_generation,
);
criterion_main!(benches);
