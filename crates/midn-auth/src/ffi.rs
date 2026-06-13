// crates/midn-auth/src/ffi.rs
//! C-compatible FFI surface for midn-auth.
//!
//! All functions are `unsafe extern "C"` — callers are responsible for passing
//! valid, correctly-sized, non-overlapping buffers.
//!
//! ## Null-pointer contract
//!
//! Every pointer argument is checked for null before dereferencing. On null,
//! the function returns -1 without writing any output.
//!
//! ## Buffer sizes
//!
//! | Parameter     | Bytes |
//! |---------------|-------|
//! | ki / opc      | 16    |
//! | rand          | 16    |
//! | sqn           | 6     |
//! | amf           | 2     |
//! | mac_a / mac_s | 8     |
//! | res           | 8     |
//! | ck / ik       | 16    |
//! | ak / ak_star  | 6     |
//! | op            | 16    |
//! | opc_out       | 16    |
//! | expected_res  | 8     |
//! | received_res  | 8     |

use crate::keys::{AuthKey, OpCode};
use crate::milenage::MilenageContext;

// ── midn_milenage_generate_vector ─────────────────────────────────────────────

/// Generate a Milenage authentication vector from C.
///
/// Inputs:  ki (16), opc (16), rand (16), sqn (6), amf (2)
/// Outputs: mac_a (8), mac_s (8), res (8), ck (16), ik (16), ak (6), ak_star (6)
///
/// Returns 0 on success, -1 if any pointer is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn midn_milenage_generate_vector(
    ki_ptr:      *const u8,
    opc_ptr:     *const u8,
    rand_ptr:    *const u8,
    sqn_ptr:     *const u8,
    amf_ptr:     *const u8,
    mac_a_out:   *mut u8,
    mac_s_out:   *mut u8,
    res_out:     *mut u8,
    ck_out:      *mut u8,
    ik_out:      *mut u8,
    ak_out:      *mut u8,
    ak_star_out: *mut u8,
) -> i32 {
    if ki_ptr.is_null()    || opc_ptr.is_null()     || rand_ptr.is_null()
    || sqn_ptr.is_null()   || amf_ptr.is_null()
    || mac_a_out.is_null() || mac_s_out.is_null()   || res_out.is_null()
    || ck_out.is_null()    || ik_out.is_null()
    || ak_out.is_null()    || ak_star_out.is_null()
    {
        return -1;
    }

    let mut ki_buf   = [0u8; 16];
    let mut opc_buf  = [0u8; 16];
    let mut rand_buf = [0u8; 16];
    let mut sqn      = [0u8; 6];
    let mut amf_buf  = [0u8; 2];

    std::ptr::copy_nonoverlapping(ki_ptr,   ki_buf.as_mut_ptr(),   16);
    std::ptr::copy_nonoverlapping(opc_ptr,  opc_buf.as_mut_ptr(),  16);
    std::ptr::copy_nonoverlapping(rand_ptr, rand_buf.as_mut_ptr(), 16);
    std::ptr::copy_nonoverlapping(sqn_ptr,  sqn.as_mut_ptr(),       6);
    std::ptr::copy_nonoverlapping(amf_ptr,  amf_buf.as_mut_ptr(),   2);

    let ctx = MilenageContext::new(AuthKey(ki_buf), OpCode(opc_buf));
    let vec = ctx.generate_vector(&rand_buf, &sqn, &amf_buf);

    std::ptr::copy_nonoverlapping(vec.mac_a.as_ptr(),   mac_a_out,    8);
    std::ptr::copy_nonoverlapping(vec.mac_s.as_ptr(),   mac_s_out,    8);
    std::ptr::copy_nonoverlapping(vec.res.as_ptr(),     res_out,      8);
    std::ptr::copy_nonoverlapping(vec.ck.as_ptr(),      ck_out,      16);
    std::ptr::copy_nonoverlapping(vec.ik.as_ptr(),      ik_out,      16);
    std::ptr::copy_nonoverlapping(vec.ak.as_ptr(),      ak_out,       6);
    std::ptr::copy_nonoverlapping(vec.ak_star.as_ptr(), ak_star_out,  6);

    0
}

// ── midn_milenage_compute_opc ─────────────────────────────────────────────────

/// Derive OPc = OP ⊕ E_K(OP) from an operator OP value.
///
/// Call once at provisioning; store OPc in the HSS, discard OP.
///
/// Inputs:  ki (16), op (16)
/// Outputs: opc_out (16)
///
/// Returns 0 on success, -1 if any pointer is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn midn_milenage_compute_opc(
    ki_ptr:  *const u8,
    op_ptr:  *const u8,
    opc_out: *mut u8,
) -> i32 {
    if ki_ptr.is_null() || op_ptr.is_null() || opc_out.is_null() {
        return -1;
    }

    let mut ki_buf = [0u8; 16];
    let mut op_buf = [0u8; 16];
    std::ptr::copy_nonoverlapping(ki_ptr, ki_buf.as_mut_ptr(), 16);
    std::ptr::copy_nonoverlapping(op_ptr, op_buf.as_mut_ptr(), 16);

    let ctx = MilenageContext::with_op(AuthKey(ki_buf), &op_buf);
    std::ptr::copy_nonoverlapping(ctx.opc().0.as_ptr(), opc_out, 16);

    0
}

// ── midn_milenage_verify_res ──────────────────────────────────────────────────

/// Constant-time comparison of a received RES against the network's XRES.
///
/// Inputs: expected_res (8 — XRES from network), received_res (8 — RES from UE)
///
/// Returns: 1 if match, 0 if mismatch, -1 if any pointer is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn midn_milenage_verify_res(
    expected_ptr: *const u8,
    received_ptr: *const u8,
) -> i32 {
    if expected_ptr.is_null() || received_ptr.is_null() {
        return -1;
    }

    let mut expected = [0u8; 8];
    let mut received = [0u8; 8];
    std::ptr::copy_nonoverlapping(expected_ptr, expected.as_mut_ptr(), 8);
    std::ptr::copy_nonoverlapping(received_ptr, received.as_mut_ptr(), 8);

    if MilenageContext::verify_res(&expected, &received) { 1 } else { 0 }
}
