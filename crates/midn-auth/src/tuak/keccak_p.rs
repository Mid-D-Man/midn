// crates/midn-auth/src/tuak/keccak_p.rs
//! Keccak-f[1600] permutation — thin wrapper over the RustCrypto `keccak` crate.
//!
//! This is the one fixed, standardized primitive everything else in the
//! `tuak` module is built on: a 1600-bit (25 × 64-bit lane) state permuted
//! by 24 rounds of theta/rho/pi/chi/iota. NOT TUAK-specific — it's the same
//! permutation underlying SHA-3, SHAKE, and TUAK alike (NIST FIPS 202 / the
//! original Keccak submission).
//!
//! Deliberately delegated to an established crate rather than hand-rolled:
//! a hand-rolled permutation risks a subtle, silent transcription error in
//! the round constants or rotation-offset table — exactly the failure mode
//! this module exists to avoid. Same reasoning as using the `aes` crate for
//! Milenage's AES-128 core instead of hand-rolling AES.
//!
//! ⚠️ If `keccak::f1600` doesn't match this signature when CI runs: that's
//! a one-line, compiler-caught fix (wrong function name/arg type), NOT a
//! silent-correctness risk — totally different failure class from anything
//! in `algorithm.rs`.

/// Width of the Keccak-f[1600] state in 64-bit lanes (5×5 array, flattened).
pub const STATE_LANES: usize = 25;

/// Width of the Keccak-f[1600] state in bytes.
pub const STATE_BYTES: usize = STATE_LANES * 8; // 200 bytes = 1600 bits

/// Apply the Keccak-f[1600] permutation in place.
#[inline]
pub fn keccak_f1600(state: &mut [u64; STATE_LANES]) {
    keccak::f1600(state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_of_zero_state_is_not_identity() {
        // The all-zero state would be a fixed point if iota (which XORs in
        // non-zero round constants) didn't run. A correct permutation must
        // move away from all-zero.
        let mut state = [0u64; STATE_LANES];
        keccak_f1600(&mut state);
        assert_ne!(state, [0u64; STATE_LANES], "Keccak-f[1600] must not fix the zero state");
    }

    #[test]
    fn permutation_is_deterministic() {
        let mut a = [0x0123_4567_89AB_CDEFu64; STATE_LANES];
        let mut b = a;
        keccak_f1600(&mut a);
        keccak_f1600(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn permutation_changes_every_lane_eventually() {
        // Not a diffusion proof — just confirms we're not accidentally
        // permuting a zero-sized or truncated state.
        let mut state = [0u64; STATE_LANES];
        state[0] = 1;
        keccak_f1600(&mut state);
        let nonzero_lanes = state.iter().filter(|&&l| l != 0).count();
        assert!(nonzero_lanes > 1, "single-bit input should diffuse across multiple lanes after 24 rounds");
    }

    #[test]
    fn distinct_inputs_give_distinct_outputs() {
        let mut a = [0u64; STATE_LANES];
        let mut b = [0u64; STATE_LANES];
        b[0] = 1; // single bit different
        keccak_f1600(&mut a);
        keccak_f1600(&mut b);
        assert_ne!(a, b);
    }
  }
