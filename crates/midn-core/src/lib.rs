//! midn-core — Control Plane Orchestrator
//!
//! The MME/AMF state machine and ECS-based subscriber registry.
//!
//! Architecture:
//!   ECS World    — all subscriber state as components
//!   MME Systems  — process Attach, Detach, Handover
//!   AMF Systems  — process Registration, Session Management (5G)
//!
//! The ECS pattern means subscriber state is cache-friendly SoA,
//! enabling bulk operations at the performance level of mid-math.

pub mod ecs;
pub mod mme;
pub mod amf;

pub use ecs::world::CoreWorld;
pub use mme::Mme;
