// crates/midn-proto/src/gtp/mod.rs
//! GTP-U — GPRS Tunneling Protocol User Plane (3GPP TS 29.281)
//!
//! GTP-U wraps every subscriber data packet in a UDP/IP tunnel between
//! the eNodeB/gNodeB and the UPF/P-GW. The TEID (Tunnel Endpoint Identifier)
//! identifies which subscriber session a packet belongs to.
//!
//! ## Wire format
//!
//! ```text
//! [Outer IP][Outer UDP][GTP-U Header (8 bytes)][Inner IP Packet]
//!           port 2152   ├─ flags (1)
//!                       ├─ msg_type (1)
//!                       ├─ length (2, big-endian)
//!                       └─ teid (4, big-endian)
//! ```
//!
//! ## Performance target
//!
//! Parse < 500 ns per packet (zero-copy, no allocation).
//! Validated by `cargo bench -p midn-proto`.

pub mod header;
pub mod parser;

pub use header::GtpuHeader;
pub use parser::{GtpuPacket, GtpuParser};
