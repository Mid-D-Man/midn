// crates/midn-proto/src/error.rs
//! Unified error type for midn-proto.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("packet too short: need {expected} bytes, got {got}")]
    TooShort { expected: usize, got: usize },

    #[error("invalid GTP-U version: expected 1, got {0}")]
    InvalidGtpVersion(u8),

    #[error("unknown GTP-U message type: {0:#04x}")]
    UnknownGtpMsgType(u8),

    #[error("malformed NAS message: {reason}")]
    MalformedNas { reason: &'static str },

    #[error("malformed S1AP message: {reason}")]
    MalformedS1ap { reason: &'static str },

    #[error("malformed NGAP message: {reason}")]
    MalformedNgap { reason: &'static str },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ProtoError>;
