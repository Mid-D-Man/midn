//! High-level GTP-U parser — zero-copy, allocation-free.
//!
//! Extracts the TEID and payload from a raw UDP payload.
//! Skips optional headers cleanly.

use crate::gtp::header::GtpuHeader;

/// Result of parsing a UDP payload as a GTP-U packet.
#[derive(Debug)]
pub struct GtpuPacket<'a> {
    /// Parsed mandatory header.
    pub header:  GtpuHeader,
    /// The inner IP packet (or other payload).
    pub payload: &'a [u8],
}

pub struct GtpuParser;

impl GtpuParser {
    /// Parse a raw UDP payload as a GTP-U packet.
    /// Returns None if malformed or too short.
    #[inline]
    pub fn parse(udp_payload: &[u8]) -> Option<GtpuPacket<'_>> {
        let (hdr, rest) = GtpuHeader::parse(udp_payload)?;
        // Skip optional sequence/N-PDU/extension headers if flags are set
        let payload_start = if hdr.flags & 0x07 != 0 {
            // Sequence number (2) + N-PDU (1) + next ext hdr type (1) = 4 more bytes
            if rest.len() < 4 { return None; }
            &rest[4..]
        } else {
            rest
        };
        Some(GtpuPacket { header: hdr, payload: payload_start })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_gpdu_no_ext() {
        let buf = [
            0x30, 0xFF, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x01,
            0x45, 0x00, 0x00, 0x14,
        ];
        let pkt = GtpuParser::parse(&buf).unwrap();
        assert_eq!(pkt.header.teid, 1);
        assert_eq!(pkt.payload[0], 0x45); // IPv4 header start
    }
}
