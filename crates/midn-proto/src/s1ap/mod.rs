// crates/midn-proto/src/s1ap/mod.rs
//! S1AP — S1 Application Protocol (3GPP TS 36.413)
//!
//! `messages` defines the in-process message structs the MME state machine
//! already operates on (in-process mock eNodeB, no real transport yet).
//!
//! `per` + `ie_ids` + `codec` add a real ASN.1 ALIGNED PER wire encoder/
//! decoder on top of those structs. See `codec` module docs for current
//! scope (InitialUEMessage/Uplink/DownlinkNASTransport only) and the
//! spec-fidelity disclaimer in `ie_ids` before relying on this for actual
//! eNodeB hardware. Not yet wired into `Mme::process_s1ap` — that still
//! takes in-process structs; plugging `encode_s1ap_pdu`/`decode_s1ap_pdu`
//! into a real SCTP transport boundary is a separate next step.

pub mod codec;
pub mod ie_ids;
pub mod messages;
pub mod per;

pub use codec::{decode_s1ap_pdu, encode_s1ap_pdu};
pub use messages::{
    DownlinkNasTransport,
    ErabSetupItem,
    ErabToSetup,
    Gummei,
    InitialContextSetupRequest,
    InitialContextSetupResponse,
    InitialUeMessage,
    S1SetupRequest,
    S1SetupResponse,
    S1apCause,
    S1apMessage,
    SupportedTa,
    UeContextReleaseComplete,
    UplinkNasTransport,
};
