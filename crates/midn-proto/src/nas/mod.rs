// crates/midn-proto/src/nas/mod.rs
//! NAS — Non-Access Stratum (3GPP TS 24.301 / 24.501)

pub mod codec;
pub mod ie;
pub mod messages;
pub mod security;

pub use codec::{
    decode_nas,
    encode_attach_request,
    encode_attach_accept,          // ← was wrongly named encode_attach_response_accept
    encode_auth_request,
    encode_auth_response,
    encode_sec_mode_cmd,
    encode_sec_mode_complete,
    encode_attach_complete,
    encode_detach_request,
    encode_detach_accept,
    DecodedAttachAccept,
    DecodedAttachRequest,
    DecodedAuthenticationRequest,
    DecodedAuthenticationResponse,
    DecodedSecurityModeCommand,
    DecodedDetachRequest,
    NasPdu,
    MT_ATTACH_REQUEST,
    MT_AUTHENTICATION_REQUEST,
    MT_AUTHENTICATION_RESPONSE,
    MT_SECURITY_MODE_COMMAND,
    MT_SECURITY_MODE_COMPLETE,
    MT_ATTACH_ACCEPT,
    MT_ATTACH_COMPLETE,
    MT_DETACH_REQUEST,
    MT_DETACH_ACCEPT,
};
pub use ie::{NasEeaAlgorithm, NasEiaAlgorithm};
pub use messages::NasMessage;
