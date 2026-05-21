// crates/midn-core/src/lib.rs
//! midn-core — Control Plane Orchestrator
//!
//! Implements the MME (LTE) and AMF (5G NR) state machines backed by
//! an ECS subscriber registry.
//!
//! ## Architecture
//!
//! ```text
//! CoreWorld (ECS)
//!   └── Entities = UEs (one per attached subscriber)
//!       ├── ImsiComponent    — subscriber identity
//!       ├── AuthState        — where in the AKA procedure we are
//!       ├── SecurityContext  — session keys (zeroized on drop)
//!       ├── SessionState     — assigned IP, APN, bearer
//!       └── TunnelComponent  — GTP-U TEID mapping
//!
//! ImsiRegistry (reverse index: IMSI u64 → EntityId)
//!
//! Mme / Amf
//!   └── Processes incoming S1AP / NGAP messages
//!   └── Calls midn-auth for AKA procedure
//!   └── Updates ECS world state
//! ```

pub mod ecs;
pub mod hss;
pub mod mme;
pub mod amf;

pub use ecs::components::{
    AuthFailReason, AuthState, ImsiComponent, SecurityContext, SessionState, TunnelComponent,
};
pub use ecs::registry::ImsiRegistry;
pub use ecs::world::{CoreWorld, EntityId};
pub use hss::Hss;
pub use mme::Mme;
