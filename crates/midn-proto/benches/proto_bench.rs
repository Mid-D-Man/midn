// crates/midn-proto/benches/proto_bench.rs
//! midn-proto benchmark suite — Criterion.rs
//!
//! Run: cargo bench -p midn-proto
//! Output: target/criterion/
//!
//! Phase 2 gate: GTP-U parse < 500 ns/packet at [RELEASE].

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use midn_proto::gtp::header::GtpuHeader;
use midn_proto::gtp::parser::GtpuParser;

// ── Pre-built packet buffers ──────────────────────────────────────────────────

/// Minimal G-PDU: 8-byte header + 20-byte IPv4 header = 28 bytes total.
fn gpdu_minimal() -> Vec<u8> {
    let mut buf = vec![
        0x30, 0xFF,              // flags (v1, PT=GTP), G-PDU
        0x00, 0x14,              // length = 20 (payload only)
        0x00, 0x00, 0x00, 0x01, // TEID = 1
    ];
    // IPv4 header (version=4, IHL=5, total=40)
    buf.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x02,
    ]);
    buf
}

/// G-PDU with sequence number flag set (4 extra optional bytes).
fn gpdu_with_seq() -> Vec<u8> {
    let mut buf = vec![
        0x32, 0xFF,              // flags with S bit
        0x00, 0x18,              // length = 24
        0x00, 0x00, 0x00, 0x02, // TEID = 2
        0x00, 0x01,              // seq = 1
        0x00, 0x00,              // N-PDU + next ext = 0
    ];
    buf.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x02,
    ]);
    buf
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

fn bench_header_parse(c: &mut Criterion) {
    let buf = gpdu_minimal();
    c.bench_function("gtpu_header_parse", |b| {
        b.iter(|| GtpuHeader::parse(black_box(&buf)))
    });
}

fn bench_parser_parse_minimal(c: &mut Criterion) {
    let buf = gpdu_minimal();
    // Phase 2 gate: < 500 ns
    c.bench_function("gtpu_parser_gpdu_minimal", |b| {
        b.iter(|| GtpuParser::parse(black_box(&buf)))
    });
}

fn bench_parser_parse_with_seq(c: &mut Criterion) {
    let buf = gpdu_with_seq();
    c.bench_function("gtpu_parser_gpdu_with_seq", |b| {
        b.iter(|| GtpuParser::parse(black_box(&buf)))
    });
}

fn bench_header_round_trip(c: &mut Criterion) {
    c.bench_function("gtpu_header_serialize_round_trip", |b| {
        b.iter(|| {
            let hdr   = GtpuHeader::new_gpdu(black_box(0xDEAD_BEEF), black_box(1460));
            let bytes = hdr.to_bytes();
            let (parsed, _) = GtpuHeader::parse(black_box(&bytes)).unwrap();
            black_box(parsed.teid)
        })
    });
}

fn bench_bulk_parse_throughput(c: &mut Criterion) {
    // Simulate parsing a batch of 1000 packets — models a packet burst.
    let packets: Vec<Vec<u8>> = (0..1000)
        .map(|i| {
            let mut buf = vec![
                0x30, 0xFF, 0x00, 0x14,
                ((i >> 24) as u8), ((i >> 16) as u8), ((i >> 8) as u8), (i as u8),
            ];
            buf.extend_from_slice(&[0x45u8; 20]);
            buf
        })
        .collect();

    let mut group = c.benchmark_group("bulk_parse");
    for batch_size in [10u64, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    let n = size as usize;
                    for pkt in packets.iter().take(n) {
                        let _ = black_box(GtpuParser::parse(pkt));
                    }
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_header_parse,
    bench_parser_parse_minimal,
    bench_parser_parse_with_seq,
    bench_header_round_trip,
    bench_bulk_parse_throughput,
);
criterion_main!(benches);
