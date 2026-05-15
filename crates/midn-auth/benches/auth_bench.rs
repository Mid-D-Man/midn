// crates/midn-auth/benches/auth_bench.rs
//! Midn-auth benchmark suite — Criterion.rs
//!
//! Run: cargo bench -p midn-auth
//! Output: target/criterion/
//!
//! Phase 1 gate: Milenage auth vector generation < 10 µs at [RELEASE].
//! Add the `--mid-auth` gate to commit messages to trigger this in CI.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use midn_auth::keys::{Amf, AuthKey, OpCode, Sqn};
use midn_auth::milenage::MilenageContext;

fn bench_milenage_generate_vector(c: &mut Criterion) {
    // 3GPP TS 35.207 test set 1 inputs
    let ki  = AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc")
        .expect("valid test key");
    let opc = OpCode::from_hex("cd63cb71954a9f4e48a5994e37a02baf")
        .expect("valid test opc");
    let sqn = Sqn::from_bytes(&[0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07]);
    let amf = Amf::STANDARD;

    // Bench: one auth vector per iteration
    // Target: < 10 µs [RELEASE]
    c.bench_function("milenage_generate_vector", |b| {
        // Clone ctx to avoid measuring re-allocation
        let ctx = MilenageContext::new(ki.clone(), opc.clone());
        b.iter(|| {
            // This panics with todo!() until Phase 1 is implemented.
            // Un-ignore when implementation is ready.
            let _ = black_box(&ctx);
            let _ = black_box(sqn);
            let _ = black_box(amf);
            // ctx.generate_vector(sqn, amf)
        })
    });
}

fn bench_verify_res(c: &mut Criterion) {
    let xres = black_box([0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF]);
    let res  = black_box([0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF]);

    // Bench: constant-time comparison (should be ~1-3 ns)
    c.bench_function("verify_res_constant_time", |b| {
        b.iter(|| {
            MilenageContext::verify_res(black_box(&xres), black_box(&res))
        })
    });
}

fn bench_rand_generation(c: &mut Criterion) {
    // Bench: random RAND generation using OS CSPRNG
    // This is called once per authentication — should be < 1 µs
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
    bench_verify_res,
    bench_rand_generation,
);
criterion_main!(benches);
