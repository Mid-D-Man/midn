// crates/midn-core/benches/core_bench.rs
//! midn-core benchmark suite — Criterion.rs
//!
//! Run: cargo bench -p midn-core
//!
//! ## Gates
//!
//! | Benchmark                    | Gate     | Rationale                                  |
//! |------------------------------|----------|--------------------------------------------|
//! | ecs_spawn                    | < 1 µs   | Build #3 baseline: 819 ps (counter incr)   |
//! | ecs_spawn_with_all_components| < 5 µs   | 5× HashMap insert, fresh world each sample |
//! | ecs_despawn_with_zeroize     | < 5 µs   | Build #3 baseline: 164 ns                  |
//! | ecs_lookup_auth_state        | < 100 ns | Build #3 baseline: 11 ns                   |
//! | registry_lookup              | < 100 ns | Build #3 baseline: 14 ns                   |
//! | hss_provision                | < 1 µs   | Build #3 baseline: 77 ns                   |
//!
//! ## Notes on iter_batched
//!
//! `ecs_spawn_with_all_components` uses `iter_batched` so each sample gets a
//! fresh CoreWorld. Without this, the world accumulates across thousands of
//! Criterion iterations, HashMap rehashes dominate, and you measure table
//! growth rather than the actual spawn cost.
//!
//! `hss_get_auth_vector` is NOT benched here — `generate_vector` is `todo!()`
//! until Phase 1 validates test sets 1-6. Expected gate after Phase 1: < 20 µs.

use criterion::{
    black_box, criterion_group, criterion_main,
    BatchSize, BenchmarkId, Criterion,
};

use midn_core::ecs::world::CoreWorld;
use midn_core::ecs::components::{
    AuthState, ImsiComponent, SecurityContext, SessionState, TunnelComponent,
};
use midn_core::ecs::registry::ImsiRegistry;
use midn_core::hss::Hss;

// ── ECS world benchmarks ──────────────────────────────────────────────────────

fn bench_ecs_spawn(c: &mut Criterion) {
    let mut world = CoreWorld::with_capacity(128);

    // Gate: < 1 µs  |  Build #3 baseline: 819 ps
    // Measures: entity ID counter increment — intentionally trivial.
    c.bench_function("ecs_spawn", |b| {
        b.iter(|| {
            let id = world.spawn();
            black_box(id)
        })
    });
}

fn bench_ecs_spawn_with_all_components(c: &mut Criterion) {
    // Gate: < 5 µs
    //
    // Uses iter_batched(SmallInput): each sample gets a fresh CoreWorld(16).
    // Without this, the world grows unboundedly across Criterion's warmup +
    // measurement iterations, rehash events dominate, and you measure cache
    // thrashing rather than the actual insert cost. (Build #3 showed 31.526 µs
    // — that was all resize overhead, not real spawn cost.)
    //
    // SmallInput: setup runs per-sample inside the measurement loop.
    // The world is sized at 16 to keep it small but not force a rehash on
    // the first insert.
    c.bench_function("ecs_spawn_with_all_components", |b| {
        b.iter_batched(
            || CoreWorld::with_capacity(16),
            |mut world| {
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
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_ecs_despawn_with_zeroize(c: &mut Criterion) {
    // Gate: < 5 µs  |  Build #3 baseline: 164 ns (5× faster than gate)
    //
    // Measures: 5× HashMap remove + SecurityContext ZeroizeOnDrop.
    // The zeroize cost is the security contract — do NOT optimize it away.
    let mut group = c.benchmark_group("ecs_despawn");

    group.bench_function("with_security_context_zeroize", |b| {
        // Setup: a persistent world that we despawn-from and respawn-into
        // each iteration so HashMap size stays constant (~1 entry).
        let mut world = CoreWorld::with_capacity(4);

        let seed = world.spawn();
        world.imsi.insert(seed, ImsiComponent(234_15_0000000001_u64));
        world.auth.insert(seed, AuthState::Authenticated);
        let mut ctx = SecurityContext::new_empty();
        ctx.ck = [0xAA; 16];
        ctx.ik = [0xBB; 16];
        world.security.insert(seed, ctx);
        world.session.insert(seed, SessionState::new([10, 0, 1, 1], b"internet", 5));
        world.tunnel.insert(seed, TunnelComponent::new(1, 2, [192, 168, 0, 1]));

        b.iter(|| {
            world.despawn(black_box(seed));

            // Respawn with fresh components so the next iter has something to despawn.
            // The world never grows past 1 entity — no resize pressure.
            let id = world.spawn();
            world.imsi.insert(id, ImsiComponent(234_15_0000000001_u64));
            world.auth.insert(id, AuthState::Authenticated);
            let mut ctx = SecurityContext::new_empty();
            ctx.ck = [0xAA; 16];
            world.security.insert(id, ctx);
            world.session.insert(id, SessionState::new([10, 0, 1, 1], b"internet", 5));
            world.tunnel.insert(id, TunnelComponent::new(1, 2, [192, 168, 0, 1]));
            black_box(id)
        })
    });

    group.finish();
}

fn bench_ecs_lookup(c: &mut Criterion) {
    let mut world = CoreWorld::with_capacity(1024);

    // Pre-populate 1000 entities so lookup is into a realistic table.
    let ids: Vec<_> = (0..1000u64).map(|i| {
        let id = world.spawn();
        world.imsi.insert(id, ImsiComponent(i));
        world.auth.insert(id, AuthState::Authenticated);
        id
    }).collect();

    let mid = ids[500];

    // Gate: < 100 ns  |  Build #3 baseline: 11 ns
    c.bench_function("ecs_lookup_auth_state", |b| {
        b.iter(|| world.auth_state(black_box(mid)))
    });

    c.bench_function("ecs_is_authenticated", |b| {
        b.iter(|| world.is_authenticated(black_box(mid)))
    });
}

fn bench_ecs_bulk_scan(c: &mut Criterion) {
    let mut world = CoreWorld::with_capacity(16_384);

    for i in 0..10_000u64 {
        let id = world.spawn();
        world.imsi.insert(id, ImsiComponent(i));
        world.auth.insert(id, if i % 3 == 0 {
            AuthState::Authenticated
        } else {
            AuthState::Unauthenticated
        });
    }

    // Informational — no gate. Used to track metrics-path cost over time.
    c.bench_function("ecs_authenticated_count_10k", |b| {
        b.iter(|| world.authenticated_count())
    });
}

// ── IMSI registry benchmarks ──────────────────────────────────────────────────

fn bench_registry(c: &mut Criterion) {
    let mut registry = ImsiRegistry::new();
    let mut world    = CoreWorld::with_capacity(1024);

    for i in 0..500u64 {
        let id = world.spawn();
        registry.register(i * 10, id);
    }

    // Gate: < 100 ns  |  Build #3 baseline: 14 ns hit / 13 ns miss
    c.bench_function("registry_lookup_hit", |b| {
        b.iter(|| registry.lookup(black_box(2500)))
    });

    c.bench_function("registry_lookup_miss", |b| {
        b.iter(|| registry.lookup(black_box(999_999_999)))
    });

    // Gate: < 500 ns  |  Build #3 baseline: 125 ns
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
    // Gate: < 1 µs  |  Build #3 baseline: 77 ns
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

    // Gate: < 50 ns  |  Build #3 baseline: 11 ns hit / 11 ns miss
    c.bench_function("hss_lookup_miss", |b| {
        b.iter(|| hss.has_subscriber(black_box(999_99_9999999999_u64)))
    });

    c.bench_function("hss_lookup_hit", |b| {
        b.iter(|| hss.has_subscriber(black_box(234_15_1234567890_u64)))
    });
}

// hss_get_auth_vector intentionally absent.
// generate_vector is todo!() until Phase 1 closes.
// After Phase 1: expected < 20 µs (HSS lookup < 100 ns + Milenage 5× AES < 10 µs)

// ── Size / alignment verification ────────────────────────────────────────────

fn bench_component_sizes(_c: &mut Criterion) {
    assert_eq!(core::mem::align_of::<SecurityContext>(), 64,
        "SecurityContext alignment regressed");
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
