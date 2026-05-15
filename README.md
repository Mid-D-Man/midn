# Midn Core

> High-performance ECS-driven Private LTE/5G Core Network

Unity is a black box. Telecom stacks are legacy black holes.
Midn Core is for the Mad Scientists who want a modular,
game-engine-speed toolkit for cellular networking they can actually control.

## Why

Legacy telecom stacks (OpenAirInterface, free5GC) are built on C/C++ with
hand-crafted state machines. Midn Core uses the same ECS architecture that
runs 100k entity transforms in 131 µs — applied to subscriber session state.

## Crates

| Crate | Role | Phase |
|---|---|---|
| `midn-auth` | Milenage/TUAK SIM authentication | 1 |
| `midn-proto` | NAS, S1AP, NGAP, GTP-U parsers | 2 |
| `midn-core` | MME/AMF state machine + ECS orchestrator | 2 |
| `midn-userplane` | High-speed UPF + eBPF/XDP routing | 3 |
| `midn-userplane-ebpf` | Kernel-space XDP program (no_std) | 3 |

## Performance Targets

| System | Budget | Status |
|---|---|---|
| Auth vector (Milenage) | < 10 µs | Phase 1 |
| GTP-U parse (zero-copy) | < 500 ns/packet | Phase 2 |
| UPF routing (eBPF/XDP) | line rate | Phase 3 |
| ECS subscriber capacity | 100k+ sessions | Phase 2 |

## Technical Mandates

- **No exceptions** — Rust memory safety + no unwrap in hot paths
- **Zero-copy** — postcard for serialization, XDP for packet I/O
- **ECS-first** — subscriber state is components, not objects
- **FFI-ready** — every crate exposes a C API for integration
- **Constant-time crypto** — `subtle` crate for all auth comparisons

## Getting Started

```bash
# Build one crate at a time — saves your CPU
cargo build -p midn-auth
cargo build -p midn-proto

# Tests
cargo test -p midn-auth
cargo test -p midn-proto

# Benchmarks (release only — debug numbers are meaningless)
cargo bench -p midn-auth
```

## mid-math Dependency

This project depends on `mid-math` from Mid Engine for signal geometry
and handover calculations. See workspace `Cargo.toml` for setup options.

## Platform Notes

- `midn-userplane` and `midn-userplane-ebpf` require **Linux ≥ 5.8**
- eBPF compilation requires `bpf-linker`: `cargo install bpf-linker`
- All other crates build on Linux, macOS, and Windows

## License

MIT
