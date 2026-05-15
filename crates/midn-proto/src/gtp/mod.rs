//! GTP-U — GPRS Tunneling Protocol (User Plane)
//!
//! GTP-U encapsulates user data in UDP tunnels between the eNodeB/gNodeB
//! and the UPF/P-GW. Every data packet a subscriber sends/receives
//! is wrapped in a GTP-U header.
//!
//! Protocol: UDP/IP, default port 2152.
//! Reference: 3GPP TS 29.281
//!
//! Performance target: < 500 ns per packet parse (zero-copy)

pub mod header;
pub mod parser;

pub use header::GtpuHeader;
pub use parser::GtpuParser;
