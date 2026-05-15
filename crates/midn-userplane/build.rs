// crates/midn-userplane/build.rs
//! Build script — compiles the eBPF crate and embeds the BPF object.
//!
//! Uncomment the aya-build block when Phase 3 begins.
//! Requires: cargo install bpf-linker

fn main() {
    // Tell Cargo to re-run this build script if the eBPF source changes.
    println!("cargo:rerun-if-changed=../midn-userplane-ebpf/src/");
    println!("cargo:rerun-if-changed=build.rs");

    // TODO Phase 3: compile the eBPF program and embed it.
    //
    // use aya_build::cargo_metadata;
    // aya_build::build_ebpf_programs(&[
    //     "midn-userplane-ebpf",
    // ]).unwrap();
}
