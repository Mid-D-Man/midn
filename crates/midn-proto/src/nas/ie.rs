// crates/midn-proto/src/nas/ie.rs
//! NAS Information Element encoding helpers.
//!
//! Implements the IE encoding primitives used across NAS messages:
//!   - BCD IMSI encoding/decoding (3GPP TS 24.008 Section 10.5.1.4)
//!   - LV  (Length-Value) — mandatory IEs, no type byte
//!   - TLV (Type-Length-Value) — optional IEs with IEI prefix
//!   - Nibble-packed fields (EPS Attach Type, NAS KSI)

// ── IMSI BCD encoding ─────────────────────────────────────────────────────────

const IDENTITY_IMSI: u8 = 0x01;

/// Encode a 15-digit IMSI (u64) to a Mobile Identity byte string.
///
/// Format (3GPP TS 24.008 Section 10.5.1.4):
/// ```text
/// Byte 1: [digit_1 (4b)] [odd/even (1b)] [type (3b)]
/// Byte 2: [digit_3 (4b)] [digit_2 (4b)]
/// ...
/// Byte N: [0xF or digit_N] [digit_N-1]
/// ```
///
/// ## Implementation note
///
/// Uses pure integer arithmetic to extract BCD digits — no `format!`,
/// no intermediate `String`, no extra heap allocation.
/// A 15-digit IMSI always produces exactly 8 output bytes.
/// Gate: < 100 ns [RELEASE]. Build #4 baseline after fix: ~35–45 ns.
pub fn encode_imsi(imsi: u64) -> Vec<u8> {
    // Extract 15 decimal digits onto the stack — no format!, no String.
    let mut digits = [0u8; 15];
    let mut n = imsi;
    for i in (0..15).rev() {
        digits[i] = (n % 10) as u8;
        n /= 10;
    }

    // 15 digits = odd count → odd flag = 1 (always true for standard IMSI).
    // Byte 0: [d[0] (4b)] | [odd=1 (1b)] | [IMSI_TYPE (3b)]
    let mut out = Vec::with_capacity(8);
    out.push((digits[0] << 4) | (1u8 << 3) | IDENTITY_IMSI);

    // Pack remaining 14 digits as 7 bytes, low nibble first per 3GPP BCD format.
    let mut i = 1usize;
    while i < 15 {
        let lo = digits[i];
        let hi = if i + 1 < 15 { digits[i + 1] } else { 0xF };
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

/// Decode a Mobile Identity byte string back to IMSI u64.
///
/// Returns `None` if the identity type is not IMSI or the bytes are invalid.
pub fn decode_imsi(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() { return None; }
    let id_type = bytes[0] & 0x07;
    if id_type != IDENTITY_IMSI { return None; }

    let odd = (bytes[0] >> 3) & 0x01;
    let mut digits: Vec<u8> = Vec::with_capacity(15);

    // First digit is in the high nibble of byte 0
    digits.push((bytes[0] >> 4) & 0x0F);

    for byte in &bytes[1..] {
        let lo = byte & 0x0F;
        let hi = (byte >> 4) & 0x0F;
        digits.push(lo);
        if hi != 0x0F { digits.push(hi); }
    }

    // Trim trailing padding if even-length padding was added
    if odd == 0 && digits.last() == Some(&0xF) {
        digits.pop();
    }

    if digits.len() > 15 { return None; }

    let mut imsi: u64 = 0;
    for d in digits {
        if d > 9 { return None; } // invalid BCD digit
        imsi = imsi * 10 + d as u64;
    }
    Some(imsi)
}

// ── LV encoding ───────────────────────────────────────────────────────────────

/// Write an LV field into a buffer: 1-byte length + value bytes.
pub fn write_lv(buf: &mut Vec<u8>, value: &[u8]) {
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

/// Read an LV field from a slice. Returns (value_slice, remaining_slice).
/// Returns None if the buffer is too short.
pub fn read_lv(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.is_empty() { return None; }
    let len = buf[0] as usize;
    if buf.len() < 1 + len { return None; }
    Some((&buf[1..1+len], &buf[1+len..]))
}

// ── TLV encoding ──────────────────────────────────────────────────────────────

/// Write a TLV field: 1-byte IEI + 1-byte length + value bytes.
pub fn write_tlv(buf: &mut Vec<u8>, iei: u8, value: &[u8]) {
    buf.push(iei);
    write_lv(buf, value);
}

/// Try to read the next TLV field. Returns (iei, value_slice, remaining).
pub fn read_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if buf.len() < 2 { return None; }
    let iei = buf[0];
    let (value, rest) = read_lv(&buf[1..])?;
    Some((iei, value, rest))
}

/// Skip optional TLV fields until reaching the end of buffer or a known IEI.
/// Returns the slice starting at `target_iei` or `None` if not found.
pub fn find_tlv<'a>(mut buf: &'a [u8], target_iei: u8) -> Option<&'a [u8]> {
    while buf.len() >= 2 {
        if buf[0] == target_iei {
            return Some(buf);
        }
        // Skip this TLV
        let len = buf[1] as usize;
        if buf.len() < 2 + len { return None; }
        buf = &buf[2 + len..];
    }
    None
}

// ── NAS security algorithms (EEA/EIA) ────────────────────────────────────────

/// NAS ciphering algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NasEeaAlgorithm {
    Eea0 = 0,  // Null (no ciphering)
    Eea1 = 1,  // SNOW 3G
    Eea2 = 2,  // AES-CTR  ← recommended
    Eea3 = 3,  // ZUC
}

/// NAS integrity algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NasEiaAlgorithm {
    Eia0 = 0,  // Null (forbidden for normal NAS — emergency only)
    Eia1 = 1,  // SNOW 3G CMAC
    Eia2 = 2,  // AES-CMAC  ← recommended
    Eia3 = 3,  // ZUC MAC
}

/// Encode the selected NAS security algorithm byte.
/// ```text
/// bits 7-4: EEA algorithm selector
/// bits 3-0: EIA algorithm selector
/// ```
pub fn encode_security_algorithms(eea: NasEeaAlgorithm, eia: NasEiaAlgorithm) -> u8 {
    ((eea as u8) << 4) | (eia as u8)
}

/// Decode the NAS security algorithm byte.
pub fn decode_security_algorithms(byte: u8) -> (NasEeaAlgorithm, NasEiaAlgorithm) {
    let eea = match (byte >> 4) & 0x0F {
        1 => NasEeaAlgorithm::Eea1,
        2 => NasEeaAlgorithm::Eea2,
        3 => NasEeaAlgorithm::Eea3,
        _ => NasEeaAlgorithm::Eea0,
    };
    let eia = match byte & 0x0F {
        1 => NasEiaAlgorithm::Eia1,
        2 => NasEiaAlgorithm::Eia2,
        3 => NasEiaAlgorithm::Eia3,
        _ => NasEiaAlgorithm::Eia0,
    };
    (eea, eia)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imsi_round_trip_standard() {
        let imsi = 234_15_1234567890_u64;
        let encoded = encode_imsi(imsi);
        let decoded  = decode_imsi(&encoded).expect("should decode");
        assert_eq!(decoded, imsi);
    }

    #[test]
    fn imsi_round_trip_with_leading_zeros() {
        let imsi = 001_01_0000000001_u64;
        let encoded = encode_imsi(imsi);
        let decoded  = decode_imsi(&encoded).expect("should decode");
        assert_eq!(decoded, imsi);
    }

    #[test]
    fn imsi_encode_produces_8_bytes() {
        // 15-digit IMSI always encodes to 8 bytes
        let encoded = encode_imsi(234_15_1234567890_u64);
        assert_eq!(encoded.len(), 8, "15-digit IMSI must encode to exactly 8 bytes");
    }

    #[test]
    fn imsi_encode_identity_type_is_imsi() {
        let encoded = encode_imsi(234_15_0000000001_u64);
        assert_eq!(encoded[0] & 0x07, IDENTITY_IMSI, "low 3 bits must be IMSI type = 0x01");
    }

    #[test]
    fn imsi_encode_odd_flag_set_for_15_digits() {
        let encoded = encode_imsi(234_15_0000000001_u64);
        assert_eq!((encoded[0] >> 3) & 0x01, 1, "odd flag must be 1 for 15-digit IMSI");
    }

    #[test]
    fn decode_imsi_rejects_wrong_type() {
        // type bits = 010 (TMSI) rather than 001 (IMSI)
        assert!(decode_imsi(&[0x02, 0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn lv_round_trip() {
        let mut buf = Vec::new();
        write_lv(&mut buf, &[0xAA, 0xBB, 0xCC]);
        let (value, rest) = read_lv(&buf).unwrap();
        assert_eq!(value, &[0xAA, 0xBB, 0xCC]);
        assert!(rest.is_empty());
    }

    #[test]
    fn tlv_round_trip() {
        let mut buf = Vec::new();
        write_tlv(&mut buf, 0x28, &[1, 2, 3, 4]);
        let (iei, value, rest) = read_tlv(&buf).unwrap();
        assert_eq!(iei, 0x28);
        assert_eq!(value, &[1, 2, 3, 4]);
        assert!(rest.is_empty());
    }

    #[test]
    fn security_algorithms_round_trip() {
        let byte = encode_security_algorithms(NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let (eea, eia) = decode_security_algorithms(byte);
        assert_eq!(eea, NasEeaAlgorithm::Eea2);
        assert_eq!(eia, NasEiaAlgorithm::Eia2);
    }
    }
