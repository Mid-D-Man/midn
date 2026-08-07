// crates/midn-proto/src/nas5gs/mod.rs
//! NAS-5GS — 5G Non-Access Stratum (3GPP TS 24.501)
//!
//! Structural sibling of `nas` (NAS-EPS, TS 24.301) — carried inside
//! NGAP's `nas_pdu` field the same way NAS-EPS rides inside S1AP's, and
//! reusing the same TLV/LV byte-oriented IE encoding (TS 24.007 §11) rather
//! than NGAP's own ASN.1 PER. See `messages` module doc for the specific
//! deltas from the NAS-EPS message set this mirrors, and `codec`'s module
//! doc for a real structural difference (full-octet Extended Protocol
//! Discriminator) that a naive "just mirror nas::codec" pass would have
//! gotten wrong.
//!
//! ## Status
//!
//! `messages`  — message shapes.
//! `codec`     — wire encode/decode. Plain PDUs, plus a security-protected
//!               envelope (`encode_protected`/`decode_protected`) now that
//!               `security` below is real.
//! `security`  — 5G NAS ciphering/integrity. Reuses `nas::security`'s
//!               EEA2/EIA2 primitives directly (5G's 128-5G-EA2/128-5G-IA2
//!               are the same algorithms, TS 33.501 §5.11 explicitly
//!               reuses the TS 33.401 cipher/integrity set). The KAMF →
//!               NAS-key KDF (TS 33.501 Annex A.8) is now IMPLEMENTED —
//!               confirmed against directly-quoted spec text, see that
//!               module's doc for the confidence note. KAMF itself still
//!               has to come from somewhere upstream — that chain
//!               (KAUSF → KSEAF → KAMF) lives in `midn_core::kdf`.

pub mod codec;
pub mod messages;
pub mod security;

pub use codec::{
    decode_nas5gs,
    decode_protected,
    decode_protected_downlink,
    encode_auth_reject,
    encode_auth_request,
    encode_auth_response,
    encode_deregistration_accept,
    encode_deregistration_request,
    encode_identity_request,
    encode_identity_response_guti,
    encode_identity_response_pei,
    encode_identity_response_suci,
    encode_protected,
    encode_protected_uplink,
    encode_registration_accept,
    encode_registration_complete,
    encode_registration_reject,
    encode_registration_request,
    encode_sec_mode_cmd,
    encode_sec_mode_complete,
    DecodedAuthenticationRequest,
    DecodedAuthenticationResponse,
    DecodedIdentityResponse,
    DecodedRegistrationAccept,
    DecodedRegistrationRequest,
    DecodedSecurityModeCommand,
    Nas5gsPdu,
    IDTYPE_5G_GUTI,
    IDTYPE_PEI,
    IDTYPE_SUCI,
    MT_AUTHENTICATION_REJECT,
    MT_AUTHENTICATION_REQUEST,
    MT_AUTHENTICATION_RESPONSE,
    MT_DEREGISTRATION_ACCEPT,
    MT_DEREGISTRATION_REQUEST,
    MT_IDENTITY_REQUEST,
    MT_IDENTITY_RESPONSE,
    MT_REGISTRATION_ACCEPT,
    MT_REGISTRATION_COMPLETE,
    MT_REGISTRATION_REJECT,
    MT_REGISTRATION_REQUEST,
    MT_SECURITY_MODE_COMMAND,
    MT_SECURITY_MODE_COMPLETE,
    NAS5GS_MM_EPD,
    NAS5GS_SHT_INTEGRITY,
    NAS5GS_SHT_INTEGRITY_CIPHERED,
    NAS5GS_SHT_INTEGRITY_CIPHERED_NEW_CTX,
    NAS5GS_SHT_INTEGRITY_NEW_CTX,
    NAS5GS_SHT_PLAIN,
};
pub use messages::{
    AuthenticationRequest, AuthenticationResponse, IdentityResponse, Nas5gsMessage,
    RegistrationAccept, RegistrationRequest, SecurityModeCommand, Suci,
};
pub use security::{derive_nas_keys, Nas5gsSecurityContext, ProtectedNas5gs};
