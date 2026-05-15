# Dev Setup

## Prerequisites

```bash
# Rust stable >= 1.85 (Edition 2024)
rustup update stable

# For eBPF (Phase 3 only, Linux)
cargo install bpf-linker
```

## Build

```bash
# Build one crate at a time
cargo build -p midn-auth
cargo build -p midn-proto
cargo build -p midn-core
cargo build -p midn-userplane

# Tests
cargo test -p midn-auth
cargo test -p midn-proto
cargo test -p midn-core
cargo test -p midn-userplane

# Benchmarks (release only)
cargo bench -p midn-auth
```

## eBPF (Phase 3, Linux only)

```bash
# Requires nightly + bpf-linker
cargo +nightly build -p midn-userplane-ebpf \
  --release --target bpfel-unknown-none \
  -Z build-std=core
```
