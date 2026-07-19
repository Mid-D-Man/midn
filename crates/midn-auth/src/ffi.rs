// crates/midn-auth/src/ffi.rs
//! C-compatible FFI surface for midn-auth.

use crate::keys::{Amf, AuthKey, OpCode, Rand, Sqn};
use crate::milenage::MilenageContext;

/// Generate a Milenage authentication vector from C.
///
/// Inputs:  ki (16), opc (16), rand (16), sqn (6), amf (2)
/// Outputs: mac_a (8), mac_s (8), res (8), ck (16), ik (16), ak (6), ak_star (6)
///
/// Returns 0 on success, -1 if any pointer is null.
///
/// # Safety
///
/// The caller must ensure that, for every non-null pointer among
/// `ki_ptr`/`opc_ptr`/`rand_ptr`/`sqn_ptr`/`amf_ptr`/`mac_a_out`/
/// `mac_s_out`/`res_out`/`ck_out`/`ik_out`/`ak_out`/`ak_star_out`:
/// - it is valid for reads (input pointers) or writes (output pointers) of
///   its documented length in bytes (16/16/16/6/2 in, 8/8/8/16/16/6/6 out),
/// - it is properly aligned (trivially true for `u8`),
/// - none of the input buffers overlap any of the output buffers, and
/// - it remains valid for the duration of the call (no concurrent
///   mutation from another thread).
///
/// Passing a null pointer for any parameter is safe and yields `-1`.
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
    let mut sqn_buf  = [0u8; 6];
    let mut amf_buf  = [0u8; 2];

    // SAFETY: caller guarantees pointers are valid for the given lengths,
    // non-null check above. Edition 2024 requires explicit unsafe blocks
    // inside unsafe fn bodies.
    unsafe {
        std::ptr::copy_nonoverlapping(ki_ptr,   ki_buf.as_mut_ptr(),   16);
        std::ptr::copy_nonoverlapping(opc_ptr,  opc_buf.as_mut_ptr(),  16);
        std::ptr::copy_nonoverlapping(rand_ptr, rand_buf.as_mut_ptr(), 16);
        std::ptr::copy_nonoverlapping(sqn_ptr,  sqn_buf.as_mut_ptr(),   6);
        std::ptr::copy_nonoverlapping(amf_ptr,  amf_buf.as_mut_ptr(),   2);
    }

    let ctx = MilenageContext::new(AuthKey(ki_buf), OpCode(opc_buf));
    let vec = ctx.generate_vector_with_rand(
        Sqn::from_bytes(&sqn_buf),
        Amf(amf_buf),
        Rand(rand_buf),
    );

    // SAFETY: output pointers are valid and non-null (checked above).
    unsafe {
        std::ptr::copy_nonoverlapping(vec.mac_a.as_ptr(),   mac_a_out,    8);
        std::ptr::copy_nonoverlapping(vec.mac_s.as_ptr(),   mac_s_out,    8);
        std::ptr::copy_nonoverlapping(vec.res.as_ptr(),     res_out,      8);
        std::ptr::copy_nonoverlapping(vec.ck.as_ptr(),      ck_out,      16);
        std::ptr::copy_nonoverlapping(vec.ik.as_ptr(),      ik_out,      16);
        std::ptr::copy_nonoverlapping(vec.ak.as_ptr(),      ak_out,       6);
        std::ptr::copy_nonoverlapping(vec.ak_star.as_ptr(), ak_star_out,  6);
    }

    0
}

/// Derive OPc = OP ⊕ E_K(OP).
///
/// # Safety
///
/// The caller must ensure that, for every non-null pointer among
/// `ki_ptr`/`op_ptr`/`opc_out`: it is valid for reads (`ki_ptr`, `op_ptr`)
/// or writes (`opc_out`) of 16 bytes, is properly aligned (trivially true
/// for `u8`), does not overlap either of the other two buffers, and
/// remains valid for the duration of the call.
///
/// Passing a null pointer for any parameter is safe and yields `-1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn midn_milenage_compute_opc(
    ki_ptr:  *const u8,
    op_ptr:  *const u8,
    opc_out: *mut u8,
) -> i32 {
    if ki_ptr.is_null() || op_ptr.is_null() || opc_out.is_null() { return -1; }

    let mut ki_buf = [0u8; 16];
    let mut op_buf = [0u8; 16];

    // SAFETY: non-null checked above, caller guarantees 16-byte validity.
    unsafe {
        std::ptr::copy_nonoverlapping(ki_ptr, ki_buf.as_mut_ptr(), 16);
        std::ptr::copy_nonoverlapping(op_ptr, op_buf.as_mut_ptr(), 16);
    }

    let ctx = MilenageContext::with_op(AuthKey(ki_buf), &op_buf);

    // SAFETY: opc_out is non-null and valid for 16 bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(ctx.opc().0.as_ptr(), opc_out, 16);
    }
    0
}

/// Constant-time RES comparison. Returns 1 match, 0 mismatch, -1 null ptr.
///
/// # Safety
///
/// The caller must ensure that, for every non-null pointer among
/// `expected_ptr`/`received_ptr`: it is valid for reads of 8 bytes, is
/// properly aligned (trivially true for `u8`), and remains valid for the
/// duration of the call.
///
/// Passing a null pointer for either parameter is safe and yields `-1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn midn_milenage_verify_res(
    expected_ptr: *const u8,
    received_ptr: *const u8,
) -> i32 {
    if expected_ptr.is_null() || received_ptr.is_null() { return -1; }

    let mut expected = [0u8; 8];
    let mut received = [0u8; 8];

    // SAFETY: non-null checked above, caller guarantees 8-byte validity.
    unsafe {
        std::ptr::copy_nonoverlapping(expected_ptr, expected.as_mut_ptr(), 8);
        std::ptr::copy_nonoverlapping(received_ptr, received.as_mut_ptr(), 8);
    }

    if MilenageContext::verify_res(&expected, &received) { 1 } else { 0 }
                                      }
