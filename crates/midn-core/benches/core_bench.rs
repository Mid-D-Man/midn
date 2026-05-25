// crates/midn-core/benches/core_bench.rs
//! midn-core benchmark suite — Criterion.rs
//!
//! Run: cargo bench -p midn-core
//!
//! ## Gates
//!
//! | Benchmark                    | Gate     | Rationale                                  |
//! |------------------------------|----------|--------------------------------------------|
//! | ecs_spawn                    | < 1 µs   | entity allocator, no heap in hot path      |
//! | ecs_spawn_with_all_components| < 5 µs   | 5× HashMap insert (one per component type)|
//! | ecs_despawn_with_zeroize     | < 5 µs   | SecurityContext ZeroizeOnDrop included     |
//! | ecs_lookup_auth_state        | < 100 ns | single HashMap get                         |
//! | registry_lookup              | < 100 ns | single HashMap get, O(1)                   |
//! | hss_provision                | < 1 µs   | HashMap insert + key clone                 |
//!
//! ## Notes
//!
//! `hss_get_auth_vector` is NOT benched here because `generate_vector` is `todo!()`
//! until Phase 1 validates test sets 1-6. Gate is < 20 µs after Phase 1 completes:
//!   HSS lookup (< 100 ns) + Milenage 5× AES (< 10 µs) + AUTN build (< 1 µs)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use midn_core::ecs::world::CoreWorld;
use midn_core::ecs::components::{
    AuthState, ImsiComponent, SecurityContext, SessionState, TunnelComponent,
};
use midn_core::ecs::registry::ImsiRegistry;
use midn_core::hss::Hss;

// ── ECS world benchmarks ──────────────────────────────────────────────────────

fn bench_ecs_spawn(c: &mut Criterion) {
    let mut world = CoreWorld::with_capacity(128);

    // Gate: < 1 µs
    // Measures: free-list pop or counter increment — no allocation on hot path.
    c.bench_function("ecs_spawn", |b| {
        b.iter(|| {
            let id = world.spawn();
            black_box(id)
        })
    });
}

fn bench_ecs_spawn_with_all_components(c: &mut Criterion) {
    let mut world = CoreWorld::with_capacity(1024);

    // Gate: < 5 µs
    // Measures: spawn + 5 HashMap inserts (one per component type).
    // In Phase 2, every attach creates exactly this set of components.
    c.bench_function("ecs_spawn_with_all_components", |b| {
        b.iter(|| {
            let id = world.spawn();

            world.imsi.insert(id, ImsiComponent(black_box(234_15_1234567890_u64)));
            world.auth.insert(id, AuthState::Unauthenticated);
            world.security.insert(id, SecurityContext::new_empty());
            world.session.insert(id, SessionState::new(
                black_box([10, 0, 0, 1]),
                b"internet",
                5,
            ));
            world.tunnel.insert(id, TunnelComponent::new(
                black_box(0x0001_0000),
                black_box(0x0002_0000),
                black_box([192, 168, 1, 100]),
            ));

            black_box(id)
        })
    });
}

fn bench_ecs_despawn_with_zeroize(c: &mut Criterion) {
    // Gate: < 5 µs
    // Measures: 5× HashMap remove + SecurityContext ZeroizeOnDrop.
    // The zeroize cost is the security contract — do NOT try to optimize it away.
    let mut group = c.benchmark_group("ecs_despawn");

    // Pre-fill a pool so we're always despawning something that exists.
    // Each iteration despawns one entity and respawns it at the end.
    group.bench_function("with_security_context_zeroize", |b| {
        let mut world = CoreWorld::with_capacity(1024);
        let id = world.spawn();
        world.imsi.insert(id, ImsiComponent(234_15_0000000001_u64));
        world.auth.insert(id, AuthState::Authenticated);
        let mut ctx = SecurityContext::new_empty();
        ctx.ck = [0xAA; 16]; // simulate populated key material
        ctx.ik = [0xBB; 16];
        world.security.insert(id, ctx);
        world.session.insert(id, SessionState::new([10, 0, 1, 1], b"internet", 5));
        world.tunnel.insert(id, TunnelComponent::new(1, 2, [192, 168, 0, 1]));

        b.iter(|| {
            // Despawn triggers ZeroizeOnDrop on SecurityContext
            world.despawn(black_box(id));
            // Respawn with full components for next iteration
            let new_id = world.spawn();
            world.imsi.insert(new_id, ImsiComponent(234_15_0000000001_u64));
            world.auth.insert(new_id, AuthState::Authenticated);
            let mut ctx = SecurityContext::new_empty();
            ctx.ck = [0xAA; 16];
            world.security.insert(new_id, ctx);
            world.session.insert(new_id, SessionState::new([10, 0, 1, 1], b"internet", 5));
            world.tunnel.insert(new_id, TunnelComponent::new(1, 2, [192, 168, 0, 1]));
            black_box(new_id)
        })
    });

    group.finish();
}

fn bench_ecs_lookup(c: &mut Criterion) {
    let mut world = CoreWorld::with_capacity(1024);

    // Pre-populate 1000 entities
    let ids: Vec<_> = (0..1000u64).map(|i| {
        let id = world.spawn();
        world.imsi.insert(id, ImsiComponent(i));
        world.auth.insert(id, AuthState::Authenticated);
        id
    }).collect();

    let mid = ids[500]; // lookup a middle entity

    // Gate: < 100 ns — single HashMap get, O(1) amortized
    c.bench_function("ecs_lookup_auth_state", |b| {
        b.iter(|| world.auth_state(black_box(mid)))
    });

    c.bench_function("ecs_is_authenticated", |b| {
        b.iter(|| world.is_authenticated(black_box(mid)))
    });
}

fn bench_ecs_bulk_scan(c: &mut Criterion) {
    let mut world = CoreWorld::with_capacity(100_000);

    // Simulate 10k subscribers
    for i in 0..10_000u64 {
        let id = world.spawn();
        world.imsi.insert(id, ImsiComponent(i));
        world.auth.insert(id, if i % 3 == 0 {
            AuthState::Authenticated
        } else {
            AuthState::Unauthenticated
        });
    }

    // Measures the cost of a bulk authenticated count scan
    // (used by monitoring/metrics path — not hot path)
    c.bench_function("ecs_authenticated_count_10k", |b| {
        b.iter(|| world.authenticated_count())
    });
}

// ── IMSI registry benchmarks ──────────────────────────────────────────────────

fn bench_registry(c: &mut Criterion) {
    let mut registry = ImsiRegistry::new();
    let mut world    = CoreWorld::with_capacity(1024);

    // Pre-populate 500 entries
    for i in 0..500u64 {
        let id = world.spawn();
        registry.register(i * 10, id);
    }

    // Gate: < 100 ns — HashMap get
    c.bench_function("registry_lookup_hit", |b| {
        b.iter(|| registry.lookup(black_box(2500))) // known to be in registry
    });

    c.bench_function("registry_lookup_miss", |b| {
        b.iter(|| registry.lookup(black_box(999_999_999))) // known to be absent
    });

    c.bench_function("registry_register", |b| {
        let mut idx = 100_000u64;
        let id = world.spawn();
        b.iter(|| {
            idx += 1;
            registry.register(black_box(idx), black_box(id))
        })
    });
}

// ── HSS benchmarks ────────────────────────────────────────────────────────────

fn bench_hss_provision(c: &mut Criterion) {
    // Gate: < 1 µs — HashMap insert + two key clones
    c.bench_function("hss_provision_subscriber", |b| {
        let ki  = midn_auth::keys::AuthKey::from_hex("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
        let opc = midn_auth::keys::OpCode::from_hex("cd63cb71954a9f4e48a5994e37a02baf").unwrap();
        let mut hss  = Hss::new();
        let mut imsi = 234_15_0000000001_u64;

        b.iter(|| {
            imsi += 1;
            hss.provision(black_box(imsi), ki.clone(), opc.clone())
        })
    });
}

fn bench_hss_lookup_miss(c: &mut Criterion) {
    let mut hss = Hss::new();
    hss.provision_hex(
        234_15_1234567890_u64,
        "465b5ce8b199b49faa5f0a2ee238a6bc",
        "cd63cb71954a9f4e48a5994e37a02baf",
    ).unwrap();

    // Measures just the HashMap miss — no Milenage involved
    c.bench_function("hss_lookup_miss", |b| {
        b.iter(|| hss.has_subscriber(black_box(999_99_9999999999_u64)))
    });

    c.bench_function("hss_lookup_hit", |b| {
        b.iter(|| hss.has_subscriber(black_box(234_15_1234567890_u64)))
    });
}

// hss_get_auth_vector is NOT benched here — generate_vector is todo!() until
// Phase 1 validates all test sets. After Phase 1:
//   Expected: < 20 µs total (HSS lookup < 100 ns + Milenage 5× AES < 10 µs + AUTN < 1 µs)
//   Gate will be added to midn-bench.yml at Phase 1 completion.

// ── Size/alignment verification ───────────────────────────────────────────────

fn bench_component_sizes(_c: &mut Criterion) {
    // Not a timing benchmark — verifies layout mandates at bench-time.
    // If these fail the bench won't run, catching regressions before CI tests.
    assert_eq!(core::mem::align_of::<SecurityContext>(), 64,
        "SecurityContext alignment regressed — check components.rs");
    assert_eq!(core::mem::align_of::<SessionState>(), 64,
        "SessionState alignment regressed");
    assert_eq!(core::mem::size_of::<TunnelComponent>(), 16,
        "TunnelComponent size regressed");
}

// ── Criterion groups ──────────────────────────────────────────────────────────

criterion_group!(
    ecs_world_benches,
    bench_ecs_spawn,
    bench_ecs_spawn_with_all_components,
    bench_ecs_despawn_with_zeroize,
    bench_ecs_lookup,
    bench_ecs_bulk_scan,
);

criterion_group!(
    registry_benches,
    bench_registry,
);

criterion_group!(
    hss_benches,
    bench_hss_provision,
    bench_hss_lookup_miss,
);

criterion_main!(ecs_world_benches, registry_benches, hss_benches);
