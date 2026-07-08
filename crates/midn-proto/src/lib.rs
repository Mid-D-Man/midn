// crates/midn-proto/src/lib.rs
//! midn-proto — LTE/5G protocol stack
//!
//! Implements the signaling and data plane protocols used in a cellular core:
//!
//! | Protocol | Layer     | Purpose |
//! |----------|-----------|---------|
//! | NAS      | Signaling | UE ↔ MME/AMF: attach, auth, session |
//! | S1AP     | Signaling | eNodeB ↔ MME (LTE) |
//! | NGAP     | Signaling | gNodeB ↔ AMF (5G NR) |
//! | GTP-U    | Data      | Tunnel encapsulation for user data |
//!
//! `per` is the shared ASN.1 ALIGNED PER (ITU-T X.691) bit-packing engine —
//! S1AP and NGAP both build their wire codecs on top of it, since both
//! protocols use the identical PER variant. See `per` module docs.
//!
//! ## Zero-copy design
//!
//! GTP-U parsing is zero-copy: `GtpuHeader::parse` and `GtpuParser::parse`
//! return views into the original buffer with no allocation.
//! NAS/S1AP use `bytes::Bytes` for shared ownership of PDU buffers.

pub mod error;
pub mod gtp;
pub mod nas;
pub mod ngap;
pub mod per;
pub mod s1ap;

pub use error::ProtoError;
pub use gtp::header::GtpuHeader;
pub use gtp::parser::{GtpuPacket, GtpuParser};
pub use nas::messages::NasMessage;
pub use s1ap::messages::S1apMessage;
