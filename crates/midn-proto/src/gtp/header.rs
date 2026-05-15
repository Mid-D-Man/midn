//! GTP-U header — 3GPP TS 29.281 Section 5
//!
//! Fixed 8-byte mandatory header, plus optional extension headers.
//! Zero-copy design: the header is a view into the incoming UDP payload.

/// GTP-U mandatory header (8 bytes).
/// Layout matches the wire format directly — no reordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct GtpuHeader {
    /// Flags: version (3b), PT (1b), reserved (1b), E (1b), S (1b), PN (1b)
    pub flags:   u8,
    /// Message type: 0xFF = G-PDU (data), 0x01 = Echo Request
    pub msg_type: u8,
    /// Total length of the GTP packet (big-endian)
    pub length:  u16,
    /// Tunnel Endpoint Identifier — identifies the GTP tunnel
    pub teid:    u32,
}

impl GtpuHeader {
    pub const SIZE: usize = 8;
    pub const MSG_GPDU: u8  = 0xFF;
    pub const MSG_ECHO_REQ: u8 = 0x01;
    pub const MSG_ECHO_RSP: u8 = 0x02;
    pub const VERSION_1: u8 = 0b0010_0000;
    pub const PT_GTP: u8    = 0b0001_0000;

    /// Parse a GTP-U header from a byte slice. Zero-copy: no allocation.
    ///
    /// Returns the header and the remaining payload slice.
    /// Returns None if the slice is shorter than 8 bytes.
    #[inline]
    pub fn parse(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < Self::SIZE {
            return None;
        }
        let hdr = Self {
            flags:    buf[0],
            msg_type: buf[1],
            length:   u16::from_be_bytes([buf[2], buf[3]]),
            teid:     u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        };
        Some((hdr, &buf[Self::SIZE..]))
    }

    /// Returns true if this is a G-PDU (user data) packet.
    #[inline(always)]
    pub fn is_gpdu(self) -> bool { self.msg_type == Self::MSG_GPDU }

    /// Returns true if extension headers are present (E flag).
    #[inline(always)]
    pub fn has_ext_hdr(self) -> bool { self.flags & 0x04 != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_gpdu_header() {
        // Construct a minimal G-PDU header for TEID 0xDEADBEEF
        let buf = [
            0x30, 0xFF,          // flags, msg_type
            0x00, 0x20,          // length = 32
            0xDE, 0xAD, 0xBE, 0xEF,  // TEID
            1, 2, 3, 4,          // payload
        ];
        let (hdr, payload) = GtpuHeader::parse(&buf).unwrap();
        assert_eq!(hdr.teid, 0xDEAD_BEEF);
        assert!(hdr.is_gpdu());
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn parse_too_short_returns_none() {
        assert!(GtpuHeader::parse(&[0x30, 0xFF, 0x00]).is_none());
    }
}
