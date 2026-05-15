// crates/midn-core/src/ecs/mod.rs
//! ECS — Entity Component System for subscriber state.
//!
//! ## Design rationale
//!
//! Each subscriber is an `EntityId` (a u32 index). Their state is split
//! into components stored in separate collections — this matches the
//! data-oriented ECS pattern from mid-engine applied to telecom.
//!
//! ## Phase 2 optimization note
//!
//! Current storage: `HashMap<EntityId, ComponentT>` — correct but not
//! cache-optimal. Phase 2 target: replace with dense `Vec<ComponentT>`
//! indexed by entity generation slots (similar to mid-ecs archetype layout).
//! The interface (spawn/despawn/get/insert) stays identical.

pub mod components;
pub mod registry;
pub mod systems;
pub mod world;
