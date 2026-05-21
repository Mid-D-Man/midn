// crates/midn-auth/benches/auth_bench.rs
//! Midn-auth benchmark suite — Criterion.rs
//!
//! Run: cargo bench -p midn-auth
//! Output: target/criterion/
//!
//! ## Phase gates
//!
//! | Benchmark              | Gate    | Rationale                                      |
//! |------------------------|---------|------------------------------------------------|
//! | milenage_generate_vector | < 10 µs | stub until Phase 1; gate is meaningful then    |
//! | verify_res_constant_time | < 25 ns | subtle::ConstantTimeEq is intentionally ~12-15 ns |
//! | generate_rand_os_csprng  | < 100 ns| getrandom syscall; 40-80 ns is normal          |
//!
//! ## Build #11 baseline (Build #11, rustc 1.95.0, ubuntu-latest)
//!
//! | Benchmark                | Mean      | Gate     |
//! |--------------------------|-----------|----------|
//! | milenage_generate_vector | 945.98 ps | stub     |
//! | verify_res_constant_time | 12.800 ns | ✅ < 25 ns |
//! | generate_rand_os_csprng  | 42.047 ns | ✅ < 100 ns |

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use midn_auth::keys::{Amf, AuthKey, OpCode, Sqn};
use midn_auth::milenage::MilenageContext;

fn bench_milenage_generate_vector(c: &mut Criterion) {
    // 3GPP TS 35.207 test set 1 inputs.
    let ki  = AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc")
        .expect("valid test key");
    let opc = OpCode::from_hex("cd63cb71954a9f4e48a5994e37a02baf")
        .expect("valid test opc");
    let sqn = Sqn::from_bytes(&[0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07]);
    let amf = Amf::STANDARD;

    // Gate: < 10 µs [RELEASE] — meaningful only after Phase 1 implements f1..f5.
    // Current measurement (~1 ns) is a stub artifact: generate_vector is todo!(),
    // so the bench body only measures black_box overhead.
    c.bench_function("milenage_generate_vector", |b| {
        let ctx = MilenageContext::new(ki.clone(), opc.clone());
        b.iter(|| {
            // Uncomment when generate_vector is implemented:
            // ctx.generate_vector(sqn, amf)
            let _ = black_box(&ctx);
            let _ = black_box(sqn);
            let _ = black_box(amf);
        })
    });
}

fn bench_verify_res(c: &mut Criterion) {
    let xres = [0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF];
    let res  = [0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF];

    // Gate: < 25 ns [RELEASE]
    //
    // subtle::ConstantTimeEq is deliberately resistant to compiler
    // optimisations that would make it faster. The instruction sequence
    // is fixed regardless of input values to prevent timing oracles.
    //
    // Build #11 baseline: 12.800 ns — well within the 25 ns gate.
    // Do NOT tighten this gate below 15 ns: the whole point is that
    // constant-time has a cost and that cost must never be optimised away.
    c.bench_function("verify_res_constant_time", |b| {
        b.iter(|| {
            MilenageContext::verify_res(black_box(&xres), black_box(&res))
        })
    });
}

fn bench_rand_generation(c: &mut Criterion) {
    // Gate: < 100 ns [RELEASE]
    //
    // getrandom(2) syscall via the OS CSPRNG. 40-80 ns is typical on Linux.
    // Build #11 baseline: 42.047 ns.
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
