//! midn-ecs — dense SoA entity/component storage for subscriber state.
//!
//! Pulled out of `midn-core` into its own crate so a future
//! `midn-core::amf` (5G, stub) can share the same storage `midn-core::mme`
//! drives, without depending on MME-specific code.
//!
//! `World` stores `NasSecurityContext` (from `midn_proto::nas`) directly —
//! it's a component, not metadata — so this crate depends on midn-proto.

pub mod components;
pub mod registry;
pub mod systems;
pub mod world;

pub use components::{AuthFailReason, AuthState, IdentityComponent, SecurityContext, TunnelComponent};
pub use registry::ImsiRegistry;
pub use world::{EntityId, World};
