// crates/midn-proto/benches/proto_bench.rs
//! midn-proto benchmark suite — Criterion.rs
//!
//! Run: cargo bench -p midn-proto
//!
//! ## Gates
//!
//! | Benchmark                    | Gate     | Rationale                          |
//! |------------------------------|----------|------------------------------------|
//! | GTP-U parse (minimal)        | < 500 ns | Build #12 baseline: 1.77 ns        |
//! | NAS encode AuthRequest       | < 500 ns | pure byte packing, no alloc        |
//! | NAS decode AuthRequest       | < 500 ns | slice parsing, no alloc            |
//! | NAS IMSI BCD encode/decode   | < 100 ns | arithmetic only                    |

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

// ── GTP-U ─────────────────────────────────────────────────────────────────────
use midn_proto::gtp::header::GtpuHeader;
use midn_proto::gtp::parser::GtpuParser;

// ── NAS codec ─────────────────────────────────────────────────────────────────
use midn_proto::nas::codec::{
    decode_nas,
    encode_attach_request, encode_attach_accept,
    encode_auth_request,   encode_auth_response,
    encode_sec_mode_cmd,   encode_sec_mode_complete,
    encode_attach_complete,
};
use midn_proto::nas::ie::{encode_imsi, decode_imsi, NasEeaAlgorithm, NasEiaAlgorithm};

// ── Pre-built packet buffers ──────────────────────────────────────────────────

fn gpdu_minimal() -> Vec<u8> {
    let mut buf = vec![0x30, 0xFF, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01];
    buf.extend_from_slice(&[0x45u8; 20]);
    buf
}

fn gpdu_with_seq() -> Vec<u8> {
    let mut buf = vec![0x32, 0xFF, 0x00, 0x18, 0x00, 0x00, 0x00, 0x02,
                       0x00, 0x01, 0x00, 0x00];
    buf.extend_from_slice(&[0x45u8; 20]);
    buf
}

// ── GTP-U benchmarks ─────────────────────────────────────────────────────────

fn bench_gtpu_header_parse(c: &mut Criterion) {
    let buf = gpdu_minimal();
    c.bench_function("gtpu_header_parse", |b| {
        b.iter(|| GtpuHeader::parse(black_box(&buf)))
    });
}

fn bench_gtpu_parser_minimal(c: &mut Criterion) {
    let buf = gpdu_minimal();
    c.bench_function("gtpu_parser_gpdu_minimal", |b| {
        b.iter(|| GtpuParser::parse(black_box(&buf)))
    });
}

fn bench_gtpu_parser_with_seq(c: &mut Criterion) {
    let buf = gpdu_with_seq();
    c.bench_function("gtpu_parser_gpdu_with_seq", |b| {
        b.iter(|| GtpuParser::parse(black_box(&buf)))
    });
}

fn bench_gtpu_header_round_trip(c: &mut Criterion) {
    c.bench_function("gtpu_header_serialize_round_trip", |b| {
        b.iter(|| {
            let hdr   = GtpuHeader::new_gpdu(black_box(0xDEAD_BEEF), black_box(1460));
            let bytes = hdr.to_bytes();
            let (parsed, _) = GtpuHeader::parse(black_box(&bytes)).unwrap();
            black_box(parsed.teid)
        })
    });
}

fn bench_gtpu_bulk(c: &mut Criterion) {
    let packets: Vec<Vec<u8>> = (0..1000u32)
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
    for size in [10u64, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &n| {
            b.iter(|| {
                for pkt in packets.iter().take(n as usize) {
                    let _ = black_box(GtpuParser::parse(pkt));
                }
            })
        });
    }
    group.finish();
}

// ── NAS codec benchmarks ──────────────────────────────────────────────────────

fn bench_nas_encode_auth_request(c: &mut Criterion) {
    let rand = [0x23u8; 16];
    let autn = [0xAAu8; 16];
    // Gate: < 500 ns — pure byte packing, single allocation
    c.bench_function("nas_encode_auth_request", |b| {
        b.iter(|| encode_auth_request(black_box(7), black_box(&rand), black_box(&autn)))
    });
}

fn bench_nas_decode_auth_request(c: &mut Criterion) {
    let rand    = [0x23u8; 16];
    let autn    = [0xAAu8; 16];
    let encoded = encode_auth_request(7, &rand, &autn);
    // Gate: < 500 ns — slice indexing + two 16-byte copies
    c.bench_function("nas_decode_auth_request", |b| {
        b.iter(|| decode_nas(black_box(&encoded)))
    });
}

fn bench_nas_encode_auth_response(c: &mut Criterion) {
    let res = [0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF];
    // Gate: < 500 ns
    c.bench_function("nas_encode_auth_response", |b| {
        b.iter(|| encode_auth_response(black_box(&res)))
    });
}

fn bench_nas_decode_auth_response(c: &mut Criterion) {
    let res     = [0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF];
    let encoded = encode_auth_response(&res);
    c.bench_function("nas_decode_auth_response", |b| {
        b.iter(|| decode_nas(black_box(&encoded)))
    });
}

fn bench_nas_encode_attach_request(c: &mut Criterion) {
    let imsi: u64 = 234_15_1234567890_u64;
    // Includes IMSI BCD encode — gate: < 1 µs
    c.bench_function("nas_encode_attach_request", |b| {
        b.iter(|| encode_attach_request(black_box(imsi), black_box(1), black_box(7)))
    });
}

fn bench_nas_decode_attach_request(c: &mut Criterion) {
    let encoded = encode_attach_request(234_15_1234567890_u64, 1, 7);
    // Includes IMSI BCD decode — gate: < 1 µs
    c.bench_function("nas_decode_attach_request", |b| {
        b.iter(|| decode_nas(black_box(&encoded)))
    });
}

fn bench_nas_encode_sec_mode_cmd(c: &mut Criterion) {
    let cap = [0x20u8, 0x40];
    c.bench_function("nas_encode_sec_mode_cmd", |b| {
        b.iter(|| encode_sec_mode_cmd(
            black_box(NasEeaAlgorithm::Eea2),
            black_box(NasEiaAlgorithm::Eia2),
            black_box(7),
            black_box(&cap),
        ))
    });
}

fn bench_nas_encode_attach_accept(c: &mut Criterion) {
    let ip = [10u8, 0, 0, 1];
    c.bench_function("nas_encode_attach_accept", |b| {
        b.iter(|| encode_attach_accept(
            black_box(1),
            black_box(0x54),
            black_box(&[]),
            black_box(Some(ip)),
            black_box(Some("internet")),
        ))
    });
}

fn bench_nas_decode_attach_accept(c: &mut Criterion) {
    let encoded = encode_attach_accept(1, 0x54, &[], Some([10, 0, 0, 1]), Some("internet"));
    c.bench_function("nas_decode_attach_accept", |b| {
        b.iter(|| decode_nas(black_box(&encoded)))
    });
}

fn bench_nas_auth_round_trip(c: &mut Criterion) {
    let rand = [0x23u8; 16];
    let autn = [0xAAu8; 16];
    // Full encode + decode — gate: < 1 µs
    c.bench_function("nas_auth_round_trip", |b| {
        b.iter(|| {
            let encoded = encode_auth_request(black_box(7), black_box(&rand), black_box(&autn));
            let decoded = decode_nas(black_box(&encoded));
            black_box(decoded)
        })
    });
}

fn bench_nas_sec_mode_complete(c: &mut Criterion) {
    // Single message, no IEs — should be near zero
    c.bench_function("nas_encode_sec_mode_complete", |b| {
        b.iter(|| encode_sec_mode_complete())
    });
}

// ── NAS IE primitives ─────────────────────────────────────────────────────────

fn bench_imsi_bcd(c: &mut Criterion) {
    let imsi: u64 = 234_15_1234567890_u64;

    // Gate: < 100 ns — arithmetic + byte packing
    c.bench_function("nas_imsi_bcd_encode", |b| {
        b.iter(|| encode_imsi(black_box(imsi)))
    });

    let encoded = encode_imsi(imsi);
    // Gate: < 100 ns — slice arithmetic + modular arithmetic
    c.bench_function("nas_imsi_bcd_decode", |b| {
        b.iter(|| decode_imsi(black_box(&encoded)))
    });
}

// ── Criterion groups ──────────────────────────────────────────────────────────

criterion_group!(
    gtpu_benches,
    bench_gtpu_header_parse,
    bench_gtpu_parser_minimal,
    bench_gtpu_parser_with_seq,
    bench_gtpu_header_round_trip,
    bench_gtpu_bulk,
);

criterion_group!(
    nas_benches,
    bench_nas_encode_auth_request,
    bench_nas_decode_auth_request,
    bench_nas_encode_auth_response,
    bench_nas_decode_auth_response,
    bench_nas_encode_attach_request,
    bench_nas_decode_attach_request,
    bench_nas_encode_sec_mode_cmd,
    bench_nas_encode_attach_accept,
    bench_nas_decode_attach_accept,
    bench_nas_auth_round_trip,
    bench_nas_sec_mode_complete,
    bench_imsi_bcd,
);

criterion_main!(gtpu_benches, nas_benches);
