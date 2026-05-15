//! build.rs — compile midn-userplane-ebpf and embed the BPF object.
//!
//! Uncomment when Phase 3 eBPF work begins.
//! Requires: cargo install bpf-linker

fn main() {
    // TODO Phase 3: use aya_build::build() to compile the eBPF program
    // and embed the resulting .bpf.o into this crate via include_bytes!.
    println!("cargo:rerun-if-changed=../midn-userplane-ebpf/src/");
}
