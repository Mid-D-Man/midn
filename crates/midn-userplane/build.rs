// crates/midn-userplane/build.rs
//! Build script.
//!
//! Default build: emits rerun-if-changed directives only — no eBPF toolchain needed.
//!
//! --features ebpf: shells out to
//!   cargo +nightly build -p midn-userplane-ebpf
//!     --release --target bpfel-unknown-none -Z build-std=core
//! and copies the resulting ELF to $OUT_DIR/midn_userplane_ebpf.bpf.o
//! so that loader.rs can embed it via include_bytes!.
//!
//! Uses a private --target-dir inside OUT_DIR to avoid cargo re-entrancy
//! deadlocks (cargo holds workspace locks while running build scripts).
//!
//! Prerequisites for --features ebpf:
//!   rustup toolchain install nightly --component rust-src
//!   cargo install bpf-linker

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../midn-userplane-ebpf/src/");
    println!("cargo:rerun-if-changed=build.rs");

    // CARGO_FEATURE_EBPF is set by cargo when --features ebpf is active.
    if std::env::var("CARGO_FEATURE_EBPF").is_ok() {
        compile_ebpf()?;
    }

    Ok(())
}

fn compile_ebpf() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;
    use std::process::Command;

    let out_dir      = PathBuf::from(std::env::var("OUT_DIR")?);
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);

    // CARGO_MANIFEST_DIR = .../midn/crates/midn-userplane
    // parent             = .../midn/crates
    // parent.parent      = .../midn   ← workspace root
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or("cannot resolve workspace root from CARGO_MANIFEST_DIR")?;

    // Separate target dir inside OUT_DIR — avoids holding the workspace
    // target lock that cargo itself already holds during the build.
    let bpf_target_dir = out_dir.join("bpf-target");

    // Use the same cargo binary that invoked us.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    println!("cargo:warning=Compiling midn-userplane-ebpf (nightly, bpfel-unknown-none)…");

    let status = Command::new(&cargo)
        .args([
            "+nightly",
            "build",
            "--package",    "midn-userplane-ebpf",
            "--release",
            "--target",     "bpfel-unknown-none",
            "-Z",           "build-std=core",
            "--target-dir",
        ])
        .arg(&bpf_target_dir)
        .current_dir(workspace_root)
        // Prevent host RUSTFLAGS (e.g. -C instrument-coverage) from leaking
        // into the BPF target — the BPF verifier rejects coverage instrumentation.
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .status()?;

    if !status.success() {
        return Err(
            "midn-userplane-ebpf compilation failed.\n\
             Ensure the following are installed:\n\
             \  rustup toolchain install nightly --component rust-src\n\
             \  cargo install bpf-linker"
            .into(),
        );
    }

    // The cargo output binary for a [[bin]] crate is named after the package.
    let src = bpf_target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join("midn-userplane-ebpf");

    if !src.exists() {
        return Err(format!(
            "BPF binary not found at {src:?} after successful build — \
             check that [[bin]] name in midn-userplane-ebpf/Cargo.toml \
             matches 'midn-userplane-ebpf'"
        )
        .into());
    }

    let dst = out_dir.join("midn_userplane_ebpf.bpf.o");
    std::fs::copy(&src, &dst).map_err(|e| {
        format!("copy {src:?} → {dst:?}: {e}")
    })?;

    println!("cargo:warning=BPF object ready: {dst:?}");
    Ok(())
}
