//! Authentication benchmark — Criterion.rs
//!
//! Run: cargo bench -p midn-auth
//! Results in: target/criterion/
//!
//! Validates Phase 1 target: Milenage auth vector < 10 µs

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_milenage_placeholder(c: &mut Criterion) {
    // TODO Phase 1: replace with real MilenageContext::generate_vector bench
    c.bench_function("milenage_placeholder", |b| {
        b.iter(|| black_box(0u8.wrapping_add(1)))
    });
}

criterion_group!(benches, bench_milenage_placeholder);
criterion_main!(benches);
