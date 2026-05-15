//! eBPF loader — Linux only.
//!
//! Loads and attaches the XDP program from midn-userplane-ebpf.
//! The compiled BPF object is embedded via include_bytes! at build time.

pub mod loader;
