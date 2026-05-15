// crates/midn-userplane/src/ebpf/mod.rs
//! eBPF subsystem — Linux only.
//!
//! Loads and manages the XDP program from midn-userplane-ebpf.
//! The compiled BPF object is embedded at build time via include_bytes!.
//!
//! This module is only compiled when `target_os = "linux"`.

pub mod loader;
