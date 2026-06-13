// crates/midn-core/src/lib.rs
//! midn-core — MME/AMF state machine, ECS subscriber registry, in-memory HSS.
//!
//! ## Public surface
//!
//! | Item           | Path                         |
//! |----------------|------------------------------|
//! | Mme            | `midn_core::mme::Mme`        |
//! | UpfEvent       | `midn_core::UpfEvent`        |
//! | Hss            | `midn_core::hss::Hss`        |
//! | HssAuthInfo    | `midn_core::hss::HssAuthInfo`|
//!
//! S1AP types are re-exported as `crate::s1ap` within this crate (backed by
//! `midn_proto::s1ap`).  External users import directly from `midn_proto`.

pub mod hss;
pub mod mme;

/// Thin re-export so every module inside midn-core can write
/// `use crate::s1ap::S1apMessage` without pulling in the full proto path.
pub(crate) mod s1ap {
    pub use midn_proto::s1ap::*;
}

// UpfEvent re-exported at crate root per key_api spec
// (`re_exported_as: midn_core::UpfEvent`).
pub use mme::state_machine::UpfEvent;
