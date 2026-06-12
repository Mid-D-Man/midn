// crates/midn-userplane/src/ebpf/mod.rs
//! eBPF subsystem — XDP program loader and BPF map management.
//!
//! `loader::load_xdp` and `loader::BpfHandle` are defined on all platforms.
//! On non-Linux, `load_xdp` immediately returns an error and `BpfHandle` is
//! a zero-sized unit struct that cannot be constructed. Map methods (`insert_teid`,
//! `remove_teid`) are only compiled on Linux.
//!
//! ## Phase 3.1 activation
//!
//! 1. `cargo install bpf-linker`
//! 2. Uncomment `aya-build` in `Cargo.toml` `[build-dependencies]`
//! 3. Uncomment `aya_build::build_ebpf_programs` in `build.rs`
//! 4. Uncomment `BPF_OBJECT` + the body of `load_xdp` in `loader.rs`
//! 5. Wire `load_xdp(iface)` into the UPF startup path and pass the returned
//!    `BpfHandle` to `SessionManager::set_bpf_handle`

pub mod loader;
