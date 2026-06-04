// crates/midn-auth/benches/auth_bench.rs
//! Midn-auth benchmark suite — Criterion.rs
//!
//! Run: cargo bench -p midn-auth
//! Output: target/criterion/
//!
//! ## Phase gates
//!
//! | Benchmark                | Gate     | Rationale                                              |
//! |--------------------------|----------|--------------------------------------------------------|
//! | milenage_generate_vector | < 10 µs  | Full production path: getrandom + 5× AES-128 + AUTN   |
//! | milenage_core_fixed_rand | < 10 µs  | Pure crypto only (no syscall) — isolates AES cost      |
//! | verify_res_constant_time | < 25 ns  | subtle::ConstantTimeEq — intentionally ~10-15 ns       |
//! | generate_rand_os_csprng  | < 100 ns | getrandom(2) syscall baseline                          |
//!
//! ## Baselines
//!
//! Build #6 (2026-06-04, rustc 1.96.0):
//!   milenage_generate_vector : 939.03 ps  ← still stub, crate file wasn't updated
//!   verify_res_constant_time : 12.799 ns  ✅
//!   generate_rand_os_csprng  : 42.434 ns  ✅
//!
//! Build #7+ : first real numbers after this file is updated at the correct path

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
    // Full production path — what the HSS calls for every attach:
    //   1. getrandom(2) for fresh RAND    (~42 ns, Build #6)
    //   2. TEMP = E[RAND ⊕ OPc]_K        (AES-128)
    //   3. OUT1..OUT4 = f1, f2, f3, f4    (4× AES-128)
    //   4. AUTN = (SQN ⊕ AK) ‖ AMF ‖ MAC-A
    //   5. Drop AuthVector → ZeroizeOnDrop wipes CK, IK, XRES
    //
    // Expected on x86_64 + AES-NI: ~1.0–1.1 µs
    // Expected on non-AES-NI:       ~5–8 µs
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
    // Fixed RAND from Test Set 1 — eliminates getrandom syscall overhead.
    // The difference between this and milenage_generate_vector ≈ getrandom cost.
    let rand = Rand([
        0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
        0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
    ]);

    // Gate: < 10 µs [RELEASE]
    // Measures: 5× AES-128 + AUTN construction + AuthVector ZeroizeOnDrop.
    // Expected on x86_64 + AES-NI: ~0.9–1.0 µs
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
    // Build #6 baseline: 12.799 ns.
    //
    // Do NOT tighten below 15 ns — the constant-time cost is intentional.
    // A result < 5 ns means the compiler eliminated the safety guarantee.
    c.bench_function("verify_res_constant_time", |b| {
        b.iter(|| {
            MilenageContext::verify_res(black_box(&xres), black_box(&res))
        })
    });
}

fn bench_rand_generation(c: &mut Criterion) {
    // Gate: < 100 ns [RELEASE]
    // Build #6 baseline: 42.434 ns.
    // This is the getrandom(2) cost embedded inside milenage_generate_vector.
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
