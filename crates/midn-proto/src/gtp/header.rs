// crates/midn-proto/src/gtp/header.rs
//! GTP-U mandatory header — 3GPP TS 29.281 Section 5.1.

/// GTP-U mandatory header. 8 bytes, no padding.
///
/// Directly maps to the wire format — `parse` is a bitcast of the first
/// 8 bytes of the UDP payload. Zero-copy, no allocation.
///
/// ## Flag byte layout
///
/// ```text
/// Bit  7-5 : Version (must be 001 for GTPv1)
/// Bit  4   : Protocol Type (PT): 1 = GTP, 0 = GTP'
/// Bit  3   : Reserved (always 0)
/// Bit  2   : Extension Header flag (E): 1 = ext header present
/// Bit  1   : Sequence number flag (S): 1 = seq/N-PDU/next ext present
/// Bit  0   : N-PDU flag (PN)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct GtpuHeader {
    /// Flags: version | PT | reserved | E | S | PN
    pub flags:    u8,
    /// Message type: 0xFF = G-PDU (user data)
    pub msg_type: u8,
    /// Total GTP packet length excluding mandatory header (big-endian)
    pub length:   u16,
    /// Tunnel Endpoint Identifier — identifies the GTP-U tunnel
    pub teid:     u32,
}

impl GtpuHeader {
    /// Size of the mandatory header in bytes.
    pub const SIZE: usize = 8;

    // ── Message types ─────────────────────────────────────────────────────
    /// G-PDU: carries a user IP packet.
    pub const MSG_GPDU:     u8 = 0xFF;
    /// Echo Request (keep-alive).
    pub const MSG_ECHO_REQ: u8 = 0x01;
    /// Echo Response.
    pub const MSG_ECHO_RSP: u8 = 0x02;
    /// Error Indication.
    pub const MSG_ERR_IND:  u8 = 0x1A;

    // ── Flag constants ────────────────────────────────────────────────────
    /// GTPv1 version bits (bits 7-5 = 001).
    pub const VERSION_1: u8    = 0b0010_0000;
    /// Protocol Type = GTP (bit 4 = 1).
    pub const PT_GTP: u8       = 0b0001_0000;
    /// Extension Header flag (bit 2).
    pub const FLAG_E: u8       = 0b0000_0100;
    /// Sequence Number flag (bit 1).
    pub const FLAG_S: u8       = 0b0000_0010;
    /// N-PDU Number flag (bit 0).
    pub const FLAG_PN: u8      = 0b0000_0001;

    /// Standard flags for a plain G-PDU (version=1, PT=GTP, no optional fields).
    pub const FLAGS_STANDARD: u8 = Self::VERSION_1 | Self::PT_GTP;

    // ── Parsing ───────────────────────────────────────────────────────────

    /// Parse a GTP-U header from a byte slice. Zero-copy — no allocation.
    ///
    /// Returns `(header, remaining_payload)` on success.
    /// Returns `None` if `buf` is shorter than 8 bytes.
    #[inline]
    pub fn parse(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < Self::SIZE {
            return None;
        }
        let hdr = Self {
            flags:    buf[0],
            msg_type: buf[1],
            // GTP length is big-endian
            length:   u16::from_be_bytes([buf[2], buf[3]]),
            // TEID is big-endian
            teid:     u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        };
        Some((hdr, &buf[Self::SIZE..]))
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    /// Returns true if this is a G-PDU (user data packet).
    #[inline(always)]
    pub fn is_gpdu(self) -> bool { self.msg_type == Self::MSG_GPDU }

    /// Returns true if optional extension headers are present.
    #[inline(always)]
    pub fn has_ext_hdr(self) -> bool { self.flags & Self::FLAG_E != 0 }

    /// Returns true if sequence number / N-PDU fields are present.
    #[inline(always)]
    pub fn has_optional_fields(self) -> bool {
        self.flags & (Self::FLAG_E | Self::FLAG_S | Self::FLAG_PN) != 0
    }

    /// Extract the GTPv1 version (should always be 1).
    #[inline(always)]
    pub fn version(self) -> u8 { (self.flags >> 5) & 0x07 }

    // ── Serialization ─────────────────────────────────────────────────────

    /// Serialize header to 8 bytes (big-endian wire format).
    #[inline]
    pub fn to_bytes(self) -> [u8; 8] {
        let len  = self.length.to_be_bytes();
        let teid = self.teid.to_be_bytes();
        [
            self.flags, self.msg_type,
            len[0], len[1],
            teid[0], teid[1], teid[2], teid[3],
        ]
    }

    /// Build a standard G-PDU header for a given TEID and payload length.
    #[inline]
    pub fn new_gpdu(teid: u32, payload_len: u16) -> Self {
        Self {
            flags:    Self::FLAGS_STANDARD,
            msg_type: Self::MSG_GPDU,
            length:   payload_len,
            teid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gpdu_teid_deadbeef() {
        let buf = [
            0x30, 0xFF,              // flags=0x30 (version=1,PT=1), msg_type=G-PDU
            0x00, 0x20,              // length = 32
            0xDE, 0xAD, 0xBE, 0xEF, // TEID = 0xDEADBEEF
            0x45, 0x00,              // payload (IP header start)
        ];
        let (hdr, payload) = GtpuHeader::parse(&buf).unwrap();
        assert_eq!(hdr.teid, 0xDEAD_BEEF);
        assert_eq!(hdr.length, 32);
        assert!(hdr.is_gpdu());
        assert!(!hdr.has_ext_hdr());
        assert_eq!(hdr.version(), 1);
        assert_eq!(payload, &[0x45, 0x00]);
    }

    #[test]
    fn parse_too_short_returns_none() {
        assert!(GtpuHeader::parse(&[0x30, 0xFF, 0x00]).is_none());
        assert!(GtpuHeader::parse(&[]).is_none());
    }

    #[test]
    fn round_trip_serialization() {
        let original = GtpuHeader::new_gpdu(0x0000_0001, 60);
        let bytes    = original.to_bytes();
        let (parsed, _) = GtpuHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.teid,     original.teid);
        assert_eq!(parsed.length,   original.length);
        assert_eq!(parsed.msg_type, original.msg_type);
    }

    #[test]
    fn new_gpdu_flags_are_standard() {
        let hdr = GtpuHeader::new_gpdu(42, 100);
        assert_eq!(hdr.version(), 1);
        assert!(hdr.is_gpdu());
        assert!(!hdr.has_ext_hdr());
        assert!(!hdr.has_optional_fields());
    }

    #[test]
    fn echo_request_is_not_gpdu() {
        let buf = [
            0x20, 0x01,              // flags, msg_type=Echo Request
            0x00, 0x04,              // length
            0x00, 0x00, 0x00, 0x00, // TEID = 0
        ];
        let (hdr, _) = GtpuHeader::parse(&buf).unwrap();
        assert!(!hdr.is_gpdu());
        assert_eq!(hdr.msg_type, GtpuHeader::MSG_ECHO_REQ);
    }
}
