// crates/midn-auth/src/ffi.rs
//! C-ABI exports for midn-auth.
//!
//! Allows Milenage authentication to be called from C, C++, Go, Python,
//! or any language with a C FFI. The generated header goes in headers/midn_auth.h.
//!
//! All C types use `#[repr(C)]` and fixed-size arrays — no fat pointers.
//! Secrets (Ki, OPc) are accepted as raw 16-byte arrays since the C caller
//! manages memory layout. Zeroizing the C buffers is the caller's responsibility.
//!
//! ## Rust 2024 notes
//!
//! - `#[no_mangle]` is now `#[unsafe(no_mangle)]` — unsafe attribute rule.
//! - Unsafe calls inside `unsafe fn` bodies require explicit `unsafe {}` blocks
//!   (`unsafe_op_in_unsafe_fn` is a hard error in Edition 2024).

use crate::keys::{Amf, AuthKey, OpCode, Sqn};
use crate::milenage::MilenageContext;

/// C-safe authentication vector output.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CAuthVector {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
    pub xres: [u8; 8],
    pub ck:   [u8; 16],
    pub ik:   [u8; 16],
}

/// C-safe result type — avoids returning `Result<>` across FFI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum CAuthResult {
    Ok  = 0,
    Err = 1,
}

/// Generate a Milenage authentication vector.
///
/// # Safety
///
/// All pointers must be non-null and point to valid memory of the stated size:
/// - `ki`  — 16 bytes
/// - `opc` — 16 bytes
/// - `amf` — 2 bytes
/// - `out` — sizeof(CAuthVector), writable
///
/// The caller is responsible for zeroizing `ki` and `opc` buffers after use.
///
/// # Returns
///
/// `CAuthResult::Ok` on success. `CAuthResult::Err` if any pointer is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn midn_auth_milenage_generate(
    ki:  *const u8,       // 16-byte Ki
    opc: *const u8,       // 16-byte OPc
    sqn: u64,             // 48-bit SQN in top bits of u64
    amf: *const u8,       // 2-byte AMF
    out: *mut CAuthVector,
) -> CAuthResult {
    if ki.is_null() || opc.is_null() || amf.is_null() || out.is_null() {
        return CAuthResult::Err;
    }

    let mut ki_buf  = [0u8; 16];
    let mut opc_buf = [0u8; 16];
    let mut amf_buf = [0u8; 2];

    // Edition 2024: `unsafe fn` body is no longer implicitly unsafe.
    // Unsafe operations must be in explicit `unsafe {}` blocks.
    // Safety: caller guarantees all pointers are valid and correctly sized.
    unsafe {
        core::ptr::copy_nonoverlapping(ki,  ki_buf.as_mut_ptr(),  16);
        core::ptr::copy_nonoverlapping(opc, opc_buf.as_mut_ptr(), 16);
        core::ptr::copy_nonoverlapping(amf, amf_buf.as_mut_ptr(), 2);
    }

    let ctx = MilenageContext::new(AuthKey(ki_buf), OpCode(opc_buf));
    let _vec = ctx.generate_vector(Sqn(sqn), Amf(amf_buf));

    // TODO Phase 1: populate *out from the returned AuthVector once
    // generate_vector is implemented:
    //   unsafe {
    //       (*out).rand = _vec.rand.0;
    //       (*out).autn = _vec.autn;
    //       (*out).xres = _vec.xres;
    //       (*out).ck   = _vec.ck;
    //       (*out).ik   = _vec.ik;
    //   }

    CAuthResult::Ok
}

/// Constant-time comparison of RES (from UE) and XRES (expected).
///
/// Returns `1` if equal, `0` if not equal or if either pointer is null.
///
/// MUST be used instead of `memcmp` — timing oracles on the auth path
/// enable MITM authentication attacks.
///
/// # Safety
///
/// Both pointers must be non-null and point to at least 8 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn midn_auth_verify_res(
    xres: *const u8,   // 8 bytes
    res:  *const u8,   // 8 bytes
) -> u8 {
    if xres.is_null() || res.is_null() {
        return 0;
    }
    // Safety: caller guarantees both pointers are valid 8-byte arrays.
    let xres_ref = unsafe { &*(xres as *const [u8; 8]) };
    let res_ref  = unsafe { &*(res  as *const [u8; 8]) };
    MilenageContext::verify_res(xres_ref, res_ref) as u8
}
