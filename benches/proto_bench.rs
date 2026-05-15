//! Protocol benchmark — Criterion.rs
//!
//! Run: cargo bench -p midn-proto
//! Validates Phase 2 target: GTP-U parse < 500 ns/packet

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use midn_proto::gtp::parser::GtpuParser;

fn bench_gtpu_parse(c: &mut Criterion) {
    // Minimal G-PDU packet: 8-byte header + 20-byte IPv4 header
    let buf = [
        0x30u8, 0xFF, 0x00, 0x18,
        0x00, 0x00, 0x00, 0x01,
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x02,
    ];
    c.bench_function("gtpu_parse_gpdu", |b| {
        b.iter(|| {
            let pkt = GtpuParser::parse(black_box(&buf));
            black_box(pkt)
        })
    });
}

criterion_group!(benches, bench_gtpu_parse);
criterion_main!(benches);
