// crates/midn-auth/src/tuak/sponge.rs
//! Generic Keccak sponge construction on top of `keccak_p::keccak_f1600`.
//!
//! Same absorb/permute/squeeze plumbing underlying SHA-3 and SHAKE —
//! standard, stable, NIST FIPS 202 / original Keccak submission material,
//! not TUAK-specific. `rate_bytes` (and therefore the implied capacity =
//! 200 - rate_bytes) is a caller-supplied parameter rather than a
//! hardcoded TUAK default, because I don't have TS 35.231 in front of me
//! confirming TUAK's specific rate/capacity split — see `algorithm.rs`.
//!
//! ## Padding: pad10*1 (multi-rate padding)
//!
//! Byte-oriented implementation (standard for byte-aligned rates, which
//! covers every real Keccak/SHA-3 parameter set):
//!   - exactly 1 padding byte needed → `0x81`
//!     (LSB-first '1' bit + MSB '1' bit combined in one byte)
//!   - otherwise → `0x01`, then zero bytes, then `0x80`
//!
//! ## Lane byte order
//!
//! Each of the 25 64-bit lanes is little-endian, per FIPS 202 / the Keccak
//! reference: lane bytes absorb/squeeze via `u64::from_le_bytes` /
//! `u64::to_le_bytes`.

use super::keccak_p::{keccak_f1600, STATE_BYTES, STATE_LANES};

/// A Keccak sponge instance: fixed 1600-bit state, configurable rate.
pub struct KeccakSponge {
    state: [u64; STATE_LANES],
    rate_bytes: usize,
    /// Byte offset within the rate portion not yet consumed by a squeeze
    /// call. Lets `squeeze` be called multiple times and continue where
    /// the last call left off, re-permuting only when the current rate
    /// block is exhausted.
    squeeze_pos: usize,
    /// True once any byte has been squeezed — absorbing after squeezing
    /// would silently produce nonsense (the sponge has moved into its
    /// output phase), so we guard against it explicitly.
    squeezing: bool,
}

impl KeccakSponge {
    /// `rate_bytes` must be in `1..=200` (1..=STATE_BYTES). Capacity is
    /// implicitly `STATE_BYTES - rate_bytes`.
    pub fn new(rate_bytes: usize) -> Self {
        assert!(
            rate_bytes >= 1 && rate_bytes <= STATE_BYTES,
            "rate_bytes must be in 1..={STATE_BYTES}, got {rate_bytes}"
        );
        Self {
            state: [0u64; STATE_LANES],
            rate_bytes,
            squeeze_pos: 0,
            squeezing: false,
        }
    }

    /// Absorb the *entire* input in one call, applying pad10*1 and
    /// permuting after every full rate block (including the final, padded
    /// one). Call exactly once per message — this wrapper does not support
    /// incremental multi-call absorption (TUAK's inputs are short, fixed-
    /// shape records; no need for streaming here).
    pub fn absorb(&mut self, input: &[u8]) {
        assert!(!self.squeezing, "cannot absorb after squeeze has begun");

        let padded = pad10_star_1(input, self.rate_bytes);
        debug_assert_eq!(padded.len() % self.rate_bytes, 0);

        for block in padded.chunks(self.rate_bytes) {
            self.xor_block_into_state(block);
            keccak_f1600(&mut self.state);
        }
    }

    /// Squeeze `len` bytes of output. May be called multiple times in
    /// sequence to extend the output (continues from where the previous
    /// call left off, permuting again once the current rate block is
    /// exhausted) — standard Keccak/SHAKE squeeze semantics.
    pub fn squeeze(&mut self, len: usize) -> Vec<u8> {
        self.squeezing = true;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            if self.squeeze_pos == self.rate_bytes {
                keccak_f1600(&mut self.state);
                self.squeeze_pos = 0;
            }
            let state_bytes = self.state_as_bytes();
            let available = self.rate_bytes - self.squeeze_pos;
            let take = available.min(len - out.len());
            out.extend_from_slice(&state_bytes[self.squeeze_pos..self.squeeze_pos + take]);
            self.squeeze_pos += take;
        }
        out
    }

    /// One-shot convenience: absorb `input`, then squeeze `output_len` bytes.
    pub fn absorb_and_squeeze(rate_bytes: usize, input: &[u8], output_len: usize) -> Vec<u8> {
        let mut sponge = Self::new(rate_bytes);
        sponge.absorb(input);
        sponge.squeeze(output_len)
    }

    fn xor_block_into_state(&mut self, block: &[u8]) {
        debug_assert!(block.len() <= self.rate_bytes);
        for (i, chunk) in block.chunks(8).enumerate() {
            let mut lane_bytes = [0u8; 8];
            lane_bytes[..chunk.len()].copy_from_slice(chunk);
            self.state[i] ^= u64::from_le_bytes(lane_bytes);
        }
    }

    fn state_as_bytes(&self) -> [u8; STATE_BYTES] {
        let mut out = [0u8; STATE_BYTES];
        for (i, lane) in self.state.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
        }
        out
    }
}

/// Multi-rate padding (pad10*1), byte-oriented — see module docs.
fn pad10_star_1(input: &[u8], rate_bytes: usize) -> Vec<u8> {
    let mut out = input.to_vec();
    let rem = out.len() % rate_bytes;
    let pad_len = rate_bytes - rem; // always in 1..=rate_bytes

    if pad_len == 1 {
        out.push(0x81);
    } else {
        out.push(0x01);
        out.extend(std::iter::repeat(0u8).take(pad_len - 2));
        out.push(0x80);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA3-256-shaped rate (136 bytes) purely as a convenient, well-known
    // configuration for these structural tests — this file tests the
    // SPONGE, not any particular SHA-3/TUAK parameter set.
    const RATE: usize = 136;

    #[test]
    fn pad_exactly_one_byte_short_uses_0x81() {
        let input = vec![0u8; RATE - 1];
        let padded = pad10_star_1(&input, RATE);
        assert_eq!(padded.len(), RATE);
        assert_eq!(padded[RATE - 1], 0x81);
    }

    #[test]
    fn pad_empty_input_fills_whole_block() {
        let padded = pad10_star_1(&[], RATE);
        assert_eq!(padded.len(), RATE);
        assert_eq!(padded[0], 0x01);
        assert_eq!(padded[RATE - 1], 0x80);
        assert!(padded[1..RATE - 1].iter().all(|&b| b == 0));
    }

    #[test]
    fn pad_exact_multiple_of_rate_adds_full_extra_block() {
        let input = vec![0xAAu8; RATE];
        let padded = pad10_star_1(&input, RATE);
        assert_eq!(padded.len(), 2 * RATE, "exact-multiple input still needs a full padding block");
    }

    #[test]
    fn squeeze_output_has_requested_length() {
        let out = KeccakSponge::absorb_and_squeeze(RATE, b"test input", 64);
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn squeeze_longer_than_rate_continues_correctly() {
        // Output longer than one rate block forces a re-permute mid-squeeze.
        let out = KeccakSponge::absorb_and_squeeze(RATE, b"test input", RATE + 50);
        assert_eq!(out.len(), RATE + 50);
    }

    #[test]
    fn sponge_is_deterministic() {
        let a = KeccakSponge::absorb_and_squeeze(RATE, b"deterministic check", 32);
        let b = KeccakSponge::absorb_and_squeeze(RATE, b"deterministic check", 32);
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_inputs_give_distinct_output() {
        let a = KeccakSponge::absorb_and_squeeze(RATE, b"input A", 32);
        let b = KeccakSponge::absorb_and_squeeze(RATE, b"input B", 32);
        assert_ne!(a, b);
    }

    #[test]
    fn single_bit_input_change_changes_output() {
        let a = KeccakSponge::absorb_and_squeeze(RATE, &[0u8; 10], 32);
        let mut input_b = [0u8; 10];
        input_b[5] = 1;
        let b = KeccakSponge::absorb_and_squeeze(RATE, &input_b, 32);
        assert_ne!(a, b);
    }

    #[test]
    fn incremental_squeeze_matches_one_shot() {
        let mut s1 = KeccakSponge::new(RATE);
        s1.absorb(b"incremental check");
        let mut combined = s1.squeeze(20);
        combined.extend(s1.squeeze(20));

        let one_shot = KeccakSponge::absorb_and_squeeze(RATE, b"incremental check", 40);
        assert_eq!(combined, one_shot, "two squeeze(20) calls must equal one squeeze(40)");
    }

    #[test]
    #[should_panic(expected = "cannot absorb after squeeze")]
    fn absorb_after_squeeze_panics() {
        let mut s = KeccakSponge::new(RATE);
        s.absorb(b"first");
        let _ = s.squeeze(8);
        s.absorb(b"second"); // must panic — sponge already in squeeze phase
    }

    #[test]
    #[should_panic]
    fn zero_rate_panics() {
        let _ = KeccakSponge::new(0);
    }
}
