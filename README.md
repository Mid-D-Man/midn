# Midn Core

> Experimental LTE/5G Core Network — Rust

An experimental, from-scratch implementation of a 3GPP mobile core network.
Not production-ready. Not feature-complete. Built to understand what a
data-oriented, zero-copy cellular core actually looks like when you stop
accepting the assumptions of legacy stacks.

## What it is

A private LTE/5G core network with:

- **Milenage/TUAK** — 3GPP AKA authentication against real SIM cards
- **NAS / S1AP / NGAP** — control plane protocol parsers and state machines
- **MME / AMF** — subscriber session lifecycle backed by an ECS registry
- **GTP-U** — zero-copy user plane tunnel parser
- **eBPF / XDP** — kernel-level packet steering (Phase 3)

## What it is not

- Production-ready (Phase 1 in progress)
- A full 3GPP compliance suite
- A drop-in replacement for OpenAirInterface or free5GC
- Stable API (everything changes until v1.0)

## Crates

| Crate | Role | Phase |
|---|---|---|
| `midn-auth` | Milenage / TUAK SIM authentication | **1 — active** |
| `midn-proto` | NAS, S1AP, NGAP, GTP-U | 2 |
| `midn-core` | MME/AMF state machine + ECS subscriber registry | 2 |
| `midn-userplane` | UPF routing + eBPF loader (Linux) | 3 |
| `midn-userplane-ebpf` | Kernel XDP program — no\_std | 3 |

## Quick Start

```bash
# Phase 1: authentication only
cargo build -p midn-auth
cargo test  -p midn-auth

# Phase 2: protocol stack
cargo build -p midn-proto
cargo test  -p midn-proto
cargo build -p midn-core
cargo test  -p midn-core

# Benchmarks (release numbers only — debug is meaningless for perf)
cargo bench -p midn-auth
cargo bench -p midn-proto
```

## mid-math dependency

Signal geometry and handover calculations use `mid-math`. Pick one option
in the root `Cargo.toml` and uncomment it:

```toml
# Git (CI-friendly)
# mid-math = { git = "https://github.com/Mid-D-Man/mid-engine", branch = "main" }

# Local path (mid-engine checked out alongside midn-core)
# mid-math = { path = "../mid-engine/crates/mid-math" }
```

## Performance Targets

| Subsystem | Target | Measured by |
|---|---|---|
| Milenage auth vector | < 10 µs | `cargo bench -p midn-auth` |
| GTP-U header parse | < 500 ns | `cargo bench -p midn-proto` |
| ECS subscriber spawn | < 1 µs | unit tests |
| Concurrent sessions | 100k+ | stress tests |
| XDP packet decision | < 200 ns (Phase 3) | kernel perf counters |

## CI

Tests and benchmarks run on GitHub Actions.

| Trigger | What runs |
|---|---|
| Commit with `--midn-auth` | midn-auth tests |
| Commit with `--midn-proto` | midn-proto tests |
| Commit with `--midn-core` | midn-core tests |
| Commit with `--midn-all` | all crates |
| Actions tab (manual) | always runs all |

Benchmark workflow is manual-only (Actions → "midn-core: Benchmarks").

## eBPF (Phase 3, Linux ≥ 5.8 only)

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

cargo +nightly build -p midn-userplane-ebpf \
  --release --target bpfel-unknown-none -Z build-std=core
```

## License

MIT
