// crates/midn-auth/src/ffi.rs
//! C-ABI exports for midn-auth.
//!
//! Allows Milenage authentication to be called from C, C++, Go, Python,
//! or any language with a C FFI. The generated header goes in headers/midn_auth.h.
//!
//! All C types use `#[repr(C)]` and fixed-size arrays — no fat pointers.
//! Secrets (Ki, OPc) are accepted as raw 16-byte arrays since the C caller
//! manages memory layout. Zeroizing the C buffers is the caller's responsibility.

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

/// C-safe result type — avoids returning Result<> across FFI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum CAuthResult {
    Ok  = 0,
    Err = 1,
}

/// Generate a Milenage authentication vector.
///
/// # Safety
/// All pointers must be non-null and point to valid memory of the stated size.
/// `out` must point to an uninitialized (or overwriteable) CAuthVector.
///
/// # Returns
/// `CAuthResult::Ok` on success. `CAuthResult::Err` if inputs are invalid.
#[no_mangle]
pub unsafe extern "C" fn midn_auth_milenage_generate(
    ki:     *const u8,   // 16-byte Ki
    opc:    *const u8,   // 16-byte OPc
    sqn:    u64,         // 48-bit SQN in top bits of u64
    amf:    *const u8,   // 2-byte AMF
    out:    *mut CAuthVector,
) -> CAuthResult {
    if ki.is_null() || opc.is_null() || amf.is_null() || out.is_null() {
        return CAuthResult::Err;
    }

    let mut ki_buf  = [0u8; 16];
    let mut opc_buf = [0u8; 16];
    let mut amf_buf = [0u8; 2];

    core::ptr::copy_nonoverlapping(ki,  ki_buf.as_mut_ptr(),  16);
    core::ptr::copy_nonoverlapping(opc, opc_buf.as_mut_ptr(), 16);
    core::ptr::copy_nonoverlapping(amf, amf_buf.as_mut_ptr(), 2);

    let ctx = MilenageContext::new(AuthKey(ki_buf), OpCode(opc_buf));
    let _vec = ctx.generate_vector(Sqn(sqn), Amf(amf_buf));

    // TODO Phase 1: populate *out from the returned AuthVector
    // (*out).rand = vec.rand.0;
    // (*out).autn = vec.autn;
    // (*out).xres = vec.xres;
    // (*out).ck   = vec.ck;
    // (*out).ik   = vec.ik;

    CAuthResult::Ok
}

/// Constant-time comparison of RES and XRES.
///
/// Returns 1 if equal, 0 if not equal.
/// MUST be used instead of memcmp to prevent timing oracle attacks.
#[no_mangle]
pub extern "C" fn midn_auth_verify_res(
    xres: *const u8,  // 8 bytes
    res:  *const u8,  // 8 bytes
) -> u8 {
    if xres.is_null() || res.is_null() {
        return 0;
    }
    let xres_ref = unsafe { &*(xres as *const [u8; 8]) };
    let res_ref  = unsafe { &*(res  as *const [u8; 8]) };
    MilenageContext::verify_res(xres_ref, res_ref) as u8
}
