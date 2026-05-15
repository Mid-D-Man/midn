// crates/midn-proto/src/gtp/parser.rs
//! High-level zero-copy GTP-U parser.
//!
//! `GtpuParser::parse` processes a raw UDP payload and extracts the
//! inner IP packet with no allocation. Extension headers are skipped
//! cleanly per 3GPP TS 29.281 Section 5.2.1.

use crate::gtp::header::GtpuHeader;

/// Result of parsing a UDP payload as a GTP-U packet.
///
/// Both fields are views into the original buffer — zero-copy.
#[derive(Debug)]
pub struct GtpuPacket<'a> {
    /// Parsed mandatory header.
    pub header:  GtpuHeader,
    /// The inner IP packet (or other payload type).
    pub payload: &'a [u8],
}

impl<'a> GtpuPacket<'a> {
    /// Convenience: is this packet carrying user data?
    #[inline(always)]
    pub fn is_data(&self) -> bool { self.header.is_gpdu() }

    /// The TEID of this packet.
    #[inline(always)]
    pub fn teid(&self) -> u32 { self.header.teid }
}

/// Stateless GTP-U parser.
pub struct GtpuParser;

impl GtpuParser {
    /// Parse a raw UDP payload as a GTP-U packet. Zero-copy, no allocation.
    ///
    /// Handles optional sequence number / N-PDU / extension header fields
    /// per 3GPP TS 29.281 Section 5.1.
    ///
    /// Returns `None` if:
    /// - Buffer is shorter than 8 bytes (mandatory header)
    /// - Optional fields present but buffer too short for them
    #[inline]
    pub fn parse(udp_payload: &[u8]) -> Option<GtpuPacket<'_>> {
        let (hdr, rest) = GtpuHeader::parse(udp_payload)?;

        // If any of E, S, PN flags are set, 4 extra bytes are present:
        // [sequence_number(2)] [n_pdu(1)] [next_ext_hdr_type(1)]
        let payload = if hdr.has_optional_fields() {
            if rest.len() < 4 {
                return None;
            }
            let next_ext = rest[3];
            // If extension headers follow, skip them.
            // Extension header layout: [length(1)][content(variable)][next_type(1)]
            // Length is in 4-byte units. We skip all extension headers.
            if next_ext != 0 {
                Self::skip_ext_headers(&rest[4..])?
            } else {
                &rest[4..]
            }
        } else {
            rest
        };

        Some(GtpuPacket { header: hdr, payload })
    }

    /// Skip all extension headers and return a slice starting at the inner payload.
    ///
    /// Extension header format:
    ///   byte 0:         length in 4-byte units (includes this byte and next_type byte)
    ///   bytes 1..N-1:   content
    ///   byte N:         next extension header type (0 = no more)
    fn skip_ext_headers(mut buf: &[u8]) -> Option<&[u8]> {
        loop {
            if buf.is_empty() {
                return None;
            }
            // Length field is in 4-byte units
            let len_units = buf[0] as usize;
            if len_units == 0 {
                return None; // malformed
            }
            let total_bytes = len_units * 4;
            if buf.len() < total_bytes {
                return None;
            }
            let next_type = buf[total_bytes - 1];
            buf = &buf[total_bytes..];
            if next_type == 0 {
                return Some(buf);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gpdu_no_optional_fields() {
        // Standard G-PDU: 8-byte header + 20-byte IPv4 minimum header
        let buf: Vec<u8> = {
            let mut v = vec![
                0x30, 0xFF, 0x00, 0x14,  // flags, G-PDU, length=20
                0x00, 0x00, 0x00, 0x01,  // TEID=1
            ];
            v.extend_from_slice(&[0x45u8; 20]); // fake IPv4 header
            v
        };
        let pkt = GtpuParser::parse(&buf).unwrap();
        assert_eq!(pkt.teid(), 1);
        assert!(pkt.is_data());
        assert_eq!(pkt.payload.len(), 20);
        assert_eq!(pkt.payload[0], 0x45); // IPv4 IHL=5, version=4
    }

    #[test]
    fn parse_gpdu_with_sequence_number_flag() {
        // G-PDU with S flag set: 8-byte header + 4-byte optional fields + payload
        let buf = [
            0x32, 0xFF,              // flags with S bit set (0x32 = 0b0011_0010)
            0x00, 0x08,              // length = 8
            0x00, 0x00, 0x00, 0x02, // TEID = 2
            0x00, 0x01,              // sequence_number = 1
            0x00,                    // N-PDU = 0
            0x00,                    // next ext hdr type = 0 (none)
            0x45, 0x00,              // payload (IPv4)
        ];
        let pkt = GtpuParser::parse(&buf).unwrap();
        assert_eq!(pkt.teid(), 2);
        assert!(pkt.is_data());
        assert_eq!(pkt.payload[0], 0x45);
    }

    #[test]
    fn parse_empty_returns_none() {
        assert!(GtpuParser::parse(&[]).is_none());
    }

    #[test]
    fn parse_too_short_for_header() {
        assert!(GtpuParser::parse(&[0x30, 0xFF, 0x00]).is_none());
    }

    #[test]
    fn parse_echo_request() {
        let buf = [
            0x20, 0x01,              // version=1, PT=1, msg=Echo Request
            0x00, 0x04,              // length = 4
            0x00, 0x00, 0x00, 0x00, // TEID = 0
            0x00, 0x00, 0x00, 0x00, // sequence + padding
        ];
        let pkt = GtpuParser::parse(&buf).unwrap();
        assert!(!pkt.is_data());
        assert_eq!(pkt.header.msg_type, GtpuHeader::MSG_ECHO_REQ);
    }
}
