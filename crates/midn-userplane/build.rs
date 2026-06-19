// crates/midn-userplane/build.rs
//! Build script.
//!
//! Default build: emits rerun-if-changed directives only — no eBPF toolchain needed.
//!
//! --features ebpf: invokes nightly's cargo/rustc binaries DIRECTLY BY ABSOLUTE PATH
//! (resolved from $RUSTUP_HOME/toolchains/nightly-<host>/bin/) to build
//! midn-userplane-ebpf with `-Z build-std=core`, then copies the resulting ELF to
//! $OUT_DIR/midn_userplane_ebpf.bpf.o so loader.rs can embed it via include_bytes!.
//!
//! Uses a private --target-dir inside OUT_DIR to avoid cargo re-entrancy
//! deadlocks (cargo holds workspace locks while running build scripts).
//!
//! ## Root cause #1 (historical) — `CARGO` env var
//!
//! Inside a build script, the CARGO env var is set to the absolute path of
//! the stable cargo binary — NOT the rustup shim. So `cargo +nightly` passes
//! "+nightly" as a literal argument to the stable binary, which ignores it and
//! proceeds with stable (whose rust-src component is not installed).
//!
//! ## Root cause #2 — `RUSTUP_TOOLCHAIN` env leak (the actual CI failure)
//!
//! `rustup run nightly cargo build ...` DOES find and execute nightly's real
//! cargo binary. But that cargo process still needs to invoke `rustc`, and it
//! resolves `rustc` via `PATH`. If `PATH` contains rustup's shim directory
//! (`~/.cargo/bin`), the shim `rustc` it finds checks the `RUSTUP_TOOLCHAIN`
//! env var FIRST — and if some earlier CI step (e.g. `dtolnay/rust-toolchain`)
//! exported `RUSTUP_TOOLCHAIN=stable-...` into `$GITHUB_ENV`, that value is
//! inherited by this build script's child process and wins, regardless of
//! `rustup run`'s explicit "nightly" argument.
//!
//! Net effect: nightly **cargo** + stable **rustc**. Cargo accepts `-Z
//! build-std` (its own channel check passes — it IS nightly cargo), then asks
//! the (stable) rustc for its sysroot and looks for `library/Cargo.lock`
//! there — which doesn't exist for stable. Hence an error path under
//! `stable-x86_64-unknown-linux-gnu` with a hint that says "add to nightly".
//!
//! Fix: never resolve anything through PATH or rustup shims for this build.
//! Resolve nightly's `cargo` and `rustc` to absolute paths under
//! `$RUSTUP_HOME/toolchains/nightly-<host>/bin/` and invoke `cargo` directly,
//! with `RUSTC` pinned to nightly's rustc explicitly. No shim is ever consulted.
//!
//! Prerequisites for --features ebpf:
//!   rustup toolchain install nightly --component rust-src
//!   cargo install bpf-linker

use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=../midn-userplane-ebpf/src/");
    println!("cargo:rerun-if-changed=build.rs");

    // CARGO_FEATURE_EBPF is set by cargo when --features ebpf is active.
    if std::env::var("CARGO_FEATURE_EBPF").is_ok() {
        compile_ebpf()?;
    }

    Ok(())
}

/// Resolve `$RUSTUP_HOME` — defaults to `~/.rustup` if unset (the normal case).
fn rustup_home() -> Result<PathBuf, Box<dyn Error>> {
    if let Ok(p) = std::env::var("RUSTUP_HOME") {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var("HOME")
        .map_err(|_| "neither RUSTUP_HOME nor HOME is set — cannot locate rustup toolchains")?;
    Ok(PathBuf::from(home).join(".rustup"))
}

/// Host triple of the machine running this build (e.g. `x86_64-unknown-linux-gnu`).
///
/// Parsed from `rustc -vV` — this is platform info, not channel-specific, so
/// it's safe to read from whichever `rustc` happens to be on PATH (normally
/// the active/stable one) purely to learn the triple string.
fn host_triple() -> Result<String, Box<dyn Error>> {
    let out = Command::new("rustc").arg("-vV").output()
        .map_err(|e| format!("failed to run `rustc -vV`: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(str::to_string)
        .ok_or_else(|| "could not parse `host:` line from `rustc -vV`".into())
}

fn compile_ebpf() -> Result<(), Box<dyn Error>> {
    let out_dir      = PathBuf::from(std::env::var("OUT_DIR")?);
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);

    // CARGO_MANIFEST_DIR = .../midn/crates/midn-userplane
    // parent             = .../midn/crates
    // parent.parent      = .../midn  ← workspace root
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or("cannot resolve workspace root from CARGO_MANIFEST_DIR")?;

    // Separate target dir inside OUT_DIR — avoids holding the workspace
    // target lock that cargo itself already holds during the build.
    let bpf_target_dir = out_dir.join("bpf-target");

    // ── Resolve nightly toolchain binaries by ABSOLUTE PATH ───────────────────
    // No PATH lookup, no rustup shim, no `RUSTUP_TOOLCHAIN` env var involved
    // anywhere in this resolution — eliminates the split-brain toolchain bug.
    let triple       = host_triple()?;
    let toolchain    = format!("nightly-{triple}");
    let toolchain_dir = rustup_home()?.join("toolchains").join(&toolchain);
    let nightly_cargo = toolchain_dir.join("bin").join("cargo");
    let nightly_rustc = toolchain_dir.join("bin").join("rustc");

    if !nightly_cargo.exists() || !nightly_rustc.exists() {
        return Err(format!(
            "nightly toolchain not found at {toolchain_dir:?}.\n\
             Ensure the following are installed:\n  \
             rustup toolchain install nightly --component rust-src\n  \
             cargo install bpf-linker"
        )
        .into());
    }

    println!("cargo:warning=Compiling midn-userplane-ebpf via {nightly_cargo:?} (bpfel-unknown-none)…");

    let status = Command::new(&nightly_cargo)
        .args([
            "build",
            "--package",    "midn-userplane-ebpf",
            "--release",
            "--target",     "bpfel-unknown-none",
            "-Z",           "build-std=core",
            "--target-dir",
        ])
        .arg(&bpf_target_dir)
        .current_dir(workspace_root)
        // Pin rustc explicitly — cargo will use this instead of resolving
        // `rustc` via PATH, so the rustup shim (and its RUSTUP_TOOLCHAIN
        // env-var check) is never consulted.
        .env("RUSTC", &nightly_rustc)
        // Belt-and-suspenders: if anything else downstream does its own
        // rustup-shim resolution, force it to nightly too.
        .env("RUSTUP_TOOLCHAIN", &toolchain)
        // Prevent host RUSTFLAGS (e.g. -C instrument-coverage) from leaking
        // into the BPF target — the BPF verifier rejects coverage instrumentation.
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        // Unset CARGO so this subprocess doesn't pick up the parent stable
        // cargo's absolute path via that env var.
        .env_remove("CARGO")
        .status()?;

    if !status.success() {
        return Err(
            "midn-userplane-ebpf compilation failed.\n\
             Ensure the following are installed:\n  \
             rustup toolchain install nightly --component rust-src\n  \
             cargo install bpf-linker"
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
