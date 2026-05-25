// crates/midn-userplane/benches/userplane_bench.rs
//! midn-userplane benchmark suite — Criterion.rs
//!
//! Run: cargo bench -p midn-userplane
//!
//! ## Gates
//!
//! | Benchmark                    | Gate     | Rationale                                    |
//! |------------------------------|----------|----------------------------------------------|
//! | routing_table_lookup_ul      | < 50 ns  | O(1) HashMap, hot UPF path on every packet   |
//! | routing_table_lookup_dl      | < 50 ns  | O(1) HashMap, hot UPF path on every packet   |
//! | routing_table_install        | < 500 ns | called once per attach, not hot               |
//! | tunnel_create                | < 1 µs   | TEID alloc + 2× HashMap insert               |
//!
//! ## Context
//!
//! The routing table lookup IS the UPF hot path in userspace mode.
//! Every GTP-U packet parsed (see midn-proto GTP-U benches: ~1.8 ns) then
//! needs a routing decision: this lookup must be fast enough not to dominate.
//! 50 ns gate gives ~27× headroom over the parse time.
//!
//! Phase 3: these lookups move into the eBPF BPF_MAP_TYPE_HASH in the kernel.
//! The XDP path will be < 200 ns end-to-end (parse + lookup + rewrite).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use midn_userplane::upf::routing::{RouteEntry, RoutingTable};
use midn_userplane::upf::tunnel::TunnelManager;

// ── Routing table benchmarks ──────────────────────────────────────────────────

fn make_entry(ue_ip: [u8; 4], dl_teid: u32) -> RouteEntry {
    RouteEntry::new(ue_ip, dl_teid, [192, 168, 1, 100], 9)
}

fn bench_routing_table_install(c: &mut Criterion) {
    let mut table = RoutingTable::new();

    // Gate: < 500 ns — two HashMap inserts (UL map + DL map)
    c.bench_function("routing_table_install", |b| {
        let mut ul_teid = 0x1000_0000u32;
        b.iter(|| {
            ul_teid += 1;
            let ip = ul_teid.to_be_bytes();
            table.install(
                black_box(ul_teid),
                black_box(make_entry(ip, ul_teid + 0x8000_0000)),
            );
        })
    });
}

fn bench_routing_table_lookup(c: &mut Criterion) {
    let mut table = RoutingTable::new();

    // Pre-populate 10k routes
    for i in 0..10_000u32 {
        let ue_ip = [10, (i >> 8) as u8, (i & 0xFF) as u8, 1];
        table.install(i, make_entry(ue_ip, i + 0x8000_0000));
    }

    let mid_ul_teid  = 5000u32;
    let mid_ue_ip    = [10, (5000u32 >> 8) as u8, (5000u32 & 0xFF) as u8, 1];

    // Gate: < 50 ns — single HashMap get, this runs per GTP-U packet
    c.bench_function("routing_table_lookup_ul", |b| {
        b.iter(|| table.lookup_ul(black_box(mid_ul_teid)))
    });

    // Gate: < 50 ns — single HashMap get, DL path
    c.bench_function("routing_table_lookup_dl", |b| {
        b.iter(|| table.lookup_dl(black_box(&mid_ue_ip)))
    });

    // Miss path — must be equally fast
    c.bench_function("routing_table_lookup_ul_miss", |b| {
        b.iter(|| table.lookup_ul(black_box(0xDEAD_BEEF)))
    });
}

fn bench_routing_table_remove(c: &mut Criterion) {
    // Gate: < 500 ns — two HashMap removes
    c.bench_function("routing_table_remove", |b| {
        let mut table = RoutingTable::new();
        let mut ul    = 0x2000_0000u32;

        b.iter(|| {
            ul += 1;
            let ip = ul.to_be_bytes();
            table.install(ul, make_entry(ip, ul + 0x8000_0000));
            table.remove(black_box(ul))
        })
    });
}

fn bench_routing_table_bulk_lookup(c: &mut Criterion) {
    let mut table = RoutingTable::new();
    for i in 0..1000u32 {
        let ip = [10, 0, (i >> 8) as u8, (i & 0xFF) as u8];
        table.install(i, make_entry(ip, i + 0x8000_0000));
    }

    let teids: Vec<u32> = (0..1000u32).collect();

    let mut group = c.benchmark_group("routing_bulk_lookup");
    for n in [10u64, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &count| {
            b.iter(|| {
                for &teid in teids.iter().take(count as usize) {
                    let _ = black_box(table.lookup_ul(teid));
                }
            })
        });
    }
    group.finish();
}

// ── Tunnel manager benchmarks ─────────────────────────────────────────────────

fn bench_tunnel_create(c: &mut Criterion) {
    let mut mgr = TunnelManager::new();

    // Gate: < 1 µs — TEID alloc (wrapping_add) + routing_table.install (2× HashMap)
    c.bench_function("tunnel_create", |b| {
        let mut octet = 1u32;
        b.iter(|| {
            octet = octet.wrapping_add(1);
            let ue_ip = [10, 0, (octet >> 8) as u8, (octet & 0xFF) as u8];
            let ul_teid = black_box(mgr.create_tunnel(
                ue_ip,
                black_box(0x8000_0000 + octet),
                black_box([192, 168, 1, 1]),
                black_box(9),
            ));
            ul_teid
        })
    });
}

fn bench_tunnel_destroy(c: &mut Criterion) {
    // Gate: < 500 ns — 2× HashMap remove + TEID list push
    c.bench_function("tunnel_destroy", |b| {
        let mut mgr = TunnelManager::new();
        let ul_teid = mgr.create_tunnel([10, 0, 0, 1], 0x8000_0001, [192, 168, 0, 1], 9);

        b.iter(|| {
            // Recreate before destroying so we always have something to destroy
            let id = mgr.create_tunnel(
                black_box([10, 0, 0, 1]),
                black_box(0x8000_0001),
                black_box([192, 168, 0, 1]),
                black_box(9),
            );
            mgr.destroy_tunnel(black_box(id));
        })
    });
}

// ── Criterion groups ──────────────────────────────────────────────────────────

criterion_group!(
    routing_benches,
    bench_routing_table_install,
    bench_routing_table_lookup,
    bench_routing_table_remove,
    bench_routing_table_bulk_lookup,
);

criterion_group!(
    tunnel_benches,
    bench_tunnel_create,
    bench_tunnel_destroy,
);

criterion_main!(routing_benches, tunnel_benches);
