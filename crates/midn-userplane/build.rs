// crates/midn-userplane/build.rs
//! Build script.
//!
//! Default build: emits rerun-if-changed directives only — no eBPF toolchain needed.
//!
//! --features ebpf: also locates midn-userplane-ebpf via cargo_metadata and
//! invokes aya_build::build_ebpf_programs, which shells out to:
//!   cargo +nightly build -p midn-userplane-ebpf
//!     --release --target bpfel-unknown-none -Z build-std=core
//!
//! Output: $OUT_DIR/midn_userplane_ebpf.bpf.o
//! (aya-build names the object after the package, hyphens → underscores)
//!
//! Prerequisites for --features ebpf:
//!   rustup toolchain install nightly --component rust-src
//!   cargo install bpf-linker

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../midn-userplane-ebpf/src/");
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(feature = "ebpf")]
    compile_ebpf()?;

    Ok(())
}

#[cfg(feature = "ebpf")]
fn compile_ebpf() -> Result<(), Box<dyn std::error::Error>> {
    use aya_build::cargo_metadata;

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()?;

    let ebpf_package = packages
        .into_iter()
        .find(|p| p.name == "midn-userplane-ebpf")
        .ok_or("midn-userplane-ebpf package not found in workspace metadata")?;

    aya_build::build_ebpf_programs(&[ebpf_package])?;
    Ok(())
}
