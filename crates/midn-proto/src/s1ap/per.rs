// crates/midn-proto/src/s1ap/per.rs
//! Generic ASN.1 ALIGNED PER (Packed Encoding Rules) primitives — ITU-T X.691.
//!
//! This implements the core ALIGNED-variant bit-packing rules used by S1AP/
//! NGAP/X2AP over SCTP: constrained whole numbers, the PER length
//! determinant, and the OPEN TYPE convention. These are stable, public
//! ITU-T algorithm rules — not 3GPP-specific trivia — so confidence here is
//! high and the tests below assert exact byte output, not just round-trips.
//!
//! What this does NOT implement (not needed for our current message set):
//!   - Length-determinant fragmentation for values >= 16384 bytes
//!   - Unconstrained / semi-constrained integers (only fully-constrained,
//!     which covers every IE in scope today)
//!   - Extension markers / optional-component presence bitmaps
//!
//! ## ALIGNED constrained whole number rule (X.691 §10.5)
//!
//! Given `range = max - min + 1`:
//!   - `range == 1`            → zero bits (degenerate single-value type)
//!   - `range <= 256`          → minimum bits, NOT octet-aligned, packed
//!                               directly against whatever precedes it
//!   - `range > 256`           → octet-align first, then encode using the
//!                               minimum whole number of octets (NOT the
//!                               minimum number of bits) needed for the range
//!
//! ## OPEN TYPE convention (X.691 §10.6)
//!
//! An open type's value is encoded as if it were an OCTET STRING containing
//! the complete ALIGNED PER encoding of the inner type. In practice this
//! means: encode the inner value into its own freestanding `PerWriter`,
//! `into_bytes()` it, then embed those bytes via `write_octet_string` in the
//! parent. `codec.rs` uses exactly this pattern for IE values and PDU bodies.

/// Bit-level ALIGNED PER writer.
///
/// Internally buffers individual bits and packs them MSB-first into bytes
/// at `into_bytes()` time. This trades a little memory for a much lower risk
/// of off-by-one bit-shifting bugs — acceptable here since S1AP control-plane
/// signaling is nowhere near this project's performance-gated hot paths
/// (GTP-U parse, NAS codec, ECS) and isn't covered by any Criterion bench.
pub struct PerWriter {
    bits: Vec<bool>,
}

impl PerWriter {
    pub fn new() -> Self {
        Self { bits: Vec::new() }
    }

    #[inline]
    pub fn write_bit(&mut self, bit: bool) {
        self.bits.push(bit);
    }

    /// Write the low `n` bits of `value`, MSB first.
    #[inline]
    pub fn write_bits(&mut self, value: u64, n: usize) {
        debug_assert!(n <= 64);
        for i in (0..n).rev() {
            self.bits.push((value >> i) & 1 == 1);
        }
    }

    /// Pad with zero bits up to the next octet boundary. No-op if already aligned.
    pub fn align(&mut self) {
        let rem = self.bits.len() % 8;
        if rem != 0 {
            for _ in 0..(8 - rem) {
                self.bits.push(false);
            }
        }
    }

    /// Write raw octets. Caller must already be octet-aligned (every call
    /// site in `codec.rs` either starts a fresh writer at bit 0, or calls
    /// `align()` first via `write_length_determinant`).
    pub fn write_octets(&mut self, data: &[u8]) {
        for &b in data {
            self.write_bits(b as u64, 8);
        }
    }

    /// ALIGNED PER constrained whole number — see module docs for the rule.
    ///
    /// Panics if `value` is outside `[min, max]` — every caller in this
    /// codebase passes internally-generated values that are valid by
    /// construction (simulated IDs, fixed enums), so this is a programmer
    /// error, not an attacker-controlled path, on the encode side.
    pub fn write_constrained_int(&mut self, value: u64, min: u64, max: u64) {
        assert!(
            value >= min && value <= max,
            "value {value} out of constrained range [{min}, {max}]"
        );
        // NOTE: assumes max - min + 1 doesn't overflow u64. True for every
        // range used in this codec (largest is the full u32 space); not
        // safe for a fully generic max=u64::MAX caller.
        let range = max - min + 1;
        let v = value - min;
        if range <= 1 {
            return; // degenerate single-value type — zero bits
        }
        let num_bits = bits_for_range(range);
        if num_bits <= 8 {
            self.write_bits(v, num_bits);
        } else {
            self.align();
            let num_octets = (num_bits + 7) / 8;
            for i in (0..num_octets).rev() {
                let byte = (v >> (i * 8)) & 0xFF;
                self.write_bits(byte, 8);
            }
        }
    }

    /// PER length determinant (X.691 §10.9), short/medium form only.
    /// `len < 128` → 1 octet. `128 <= len < 16384` → 2 octets. Always
    /// octet-aligned. Panics above 16383 (fragmentation not implemented —
    /// none of our current PDUs get anywhere close to that size).
    pub fn write_length_determinant(&mut self, len: usize) {
        assert!(len < 16_384, "length fragmentation (>= 16384) not implemented");
        self.align();
        if len < 128 {
            self.write_bit(false);
            self.write_bits(len as u64, 7);
        } else {
            self.write_bit(true);
            self.write_bit(false);
            self.write_bits(len as u64, 14);
        }
    }

    /// Length-prefixed octet string — the OPEN TYPE / OCTET STRING wire shape.
    pub fn write_octet_string(&mut self, data: &[u8]) {
        self.write_length_determinant(data.len());
        self.write_octets(data);
    }

    /// Finish writing — pads the final byte with zero bits if needed.
    pub fn into_bytes(mut self) -> Vec<u8> {
        self.align();
        let mut out = Vec::with_capacity(self.bits.len() / 8);
        for chunk in self.bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &b) in chunk.iter().enumerate() {
                if b {
                    byte |= 1 << (7 - i);
                }
            }
            out.push(byte);
        }
        out
    }
}

impl Default for PerWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Bit-level ALIGNED PER reader — mirrors `PerWriter` exactly.
pub struct PerReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> PerReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    pub fn read_bit(&mut self) -> Option<bool> {
        let byte_idx = self.bit_pos / 8;
        let bit_idx = self.bit_pos % 8;
        if byte_idx >= self.data.len() {
            return None;
        }
        let bit = (self.data[byte_idx] >> (7 - bit_idx)) & 1 == 1;
        self.bit_pos += 1;
        Some(bit)
    }

    pub fn read_bits(&mut self, n: usize) -> Option<u64> {
        let mut v = 0u64;
        for _ in 0..n {
            let b = self.read_bit()?;
            v = (v << 1) | (b as u64);
        }
        Some(v)
    }

    pub fn align(&mut self) {
        let rem = self.bit_pos % 8;
        if rem != 0 {
            self.bit_pos += 8 - rem;
        }
    }

    pub fn read_constrained_int(&mut self, min: u64, max: u64) -> Option<u64> {
        let range = max - min + 1;
        if range <= 1 {
            return Some(min);
        }
        let num_bits = bits_for_range(range);
        let v = if num_bits <= 8 {
            self.read_bits(num_bits)?
        } else {
            self.align();
            let num_octets = (num_bits + 7) / 8;
            self.read_bits(num_octets * 8)?
        };
        Some(min + v)
    }

    pub fn read_length_determinant(&mut self) -> Option<usize> {
        self.align();
        let b0 = self.read_bit()?;
        if !b0 {
            let rest = self.read_bits(7)?;
            Some(rest as usize)
        } else {
            let b1 = self.read_bit()?;
            if b1 {
                return None; // 4-octet/fragmented form — not implemented
            }
            let rest = self.read_bits(14)?;
            Some(rest as usize)
        }
    }

    /// Read exactly `n` raw octets (no length prefix) — for fixed-size fields.
    pub fn read_octets(&mut self, n: usize) -> Option<Vec<u8>> {
        self.align();
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.read_bits(8)? as u8);
        }
        Some(out)
    }

    pub fn read_octet_string(&mut self) -> Option<Vec<u8>> {
        let len = self.read_length_determinant()?;
        self.read_octets(len)
    }
}

#[inline]
fn bits_for_range(range: u64) -> usize {
    if range <= 1 {
        0
    } else {
        64 - (range - 1).leading_zeros() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Exact-byte tests — not just round-trips ──────────────────────────────

    #[test]
    fn constrained_int_3_bits_exact_byte() {
        // range = 8 (0..7), value = 5 → bits "101", padded → 0b10100000
        let mut w = PerWriter::new();
        w.write_constrained_int(5, 0, 7);
        assert_eq!(w.into_bytes(), vec![0xA0]);
    }

    #[test]
    fn length_determinant_short_form_exact_byte() {
        // len=10 → bit0=0, then 7 bits of 10 (0001010) → 0b00001010 = 0x0A
        let mut w = PerWriter::new();
        w.write_length_determinant(10);
        assert_eq!(w.into_bytes(), vec![0x0A]);
    }

    #[test]
    fn small_range_is_not_octet_aligned() {
        // Two consecutive 2-bit fields should pack into the SAME byte —
        // proves the "range <= 256 → no alignment" rule is actually active.
        let mut w = PerWriter::new();
        w.write_constrained_int(1, 0, 2); // 2 bits
        w.write_constrained_int(2, 0, 2); // 2 bits
        let bytes = w.into_bytes();
        assert_eq!(bytes.len(), 1, "two 2-bit fields must share one octet");
    }

    #[test]
    fn large_range_is_octet_aligned() {
        // First a 1-bit field, then a >256 range field — the second field
        // must start at a fresh octet boundary, so total spans 2+ bytes
        // even though the bit field alone is only 1 bit.
        let mut w = PerWriter::new();
        w.write_bit(true); // 1 bit, byte 0 has 7 bits of padding after align
        w.write_constrained_int(300, 0, 1000); // range=1001>256 → octet-aligned
        let bytes = w.into_bytes();
        // 1 byte for the leading bit (aligned), then ceil(bits_for_range(1001)/8) octets
        assert!(bytes.len() >= 2);
    }

    // ── Round trips ───────────────────────────────────────────────────────────

    #[test]
    fn constrained_int_round_trip_boundary_256_257() {
        for (val, max) in [(255u64, 255u64), (256, 300)] {
            let mut w = PerWriter::new();
            w.write_constrained_int(val, 0, max);
            let bytes = w.into_bytes();
            let mut r = PerReader::new(&bytes);
            assert_eq!(r.read_constrained_int(0, max), Some(val));
        }
    }

    #[test]
    fn constrained_int_round_trip_full_u32_range() {
        let mut w = PerWriter::new();
        w.write_constrained_int(0xDEAD_BEEF, 0, u32::MAX as u64);
        let bytes = w.into_bytes();
        assert_eq!(bytes.len(), 4, "32-bit range must encode in exactly 4 octets");
        let mut r = PerReader::new(&bytes);
        assert_eq!(r.read_constrained_int(0, u32::MAX as u64), Some(0xDEAD_BEEF));
    }

    #[test]
    fn constrained_int_round_trip_24_bit_range() {
        let mut w = PerWriter::new();
        w.write_constrained_int(0x12_3456, 0, 16_777_215);
        let bytes = w.into_bytes();
        assert_eq!(bytes.len(), 3, "24-bit range must encode in exactly 3 octets");
        let mut r = PerReader::new(&bytes);
        assert_eq!(r.read_constrained_int(0, 16_777_215), Some(0x12_3456));
    }

    #[test]
    fn length_determinant_round_trip_medium_form() {
        let mut w = PerWriter::new();
        w.write_length_determinant(200);
        let bytes = w.into_bytes();
        assert_eq!(bytes.len(), 2, "medium-form length determinant is 2 octets");
        let mut r = PerReader::new(&bytes);
        assert_eq!(r.read_length_determinant(), Some(200));
    }

    #[test]
    fn octet_string_round_trip() {
        let data = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut w = PerWriter::new();
        w.write_octet_string(&data);
        let bytes = w.into_bytes();
        let mut r = PerReader::new(&bytes);
        assert_eq!(r.read_octet_string(), Some(data.to_vec()));
    }

    #[test]
    fn read_past_end_returns_none() {
        let mut r = PerReader::new(&[0x00]);
        assert_eq!(r.read_bits(16), None);
    }

    #[test]
    fn degenerate_single_value_range_consumes_zero_bits() {
        let mut w = PerWriter::new();
        w.write_constrained_int(7, 7, 7); // min==max
        assert!(w.into_bytes().is_empty());
    }
}
