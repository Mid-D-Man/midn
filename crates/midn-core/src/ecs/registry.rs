//! IMSI → EntityId reverse index.
//!
//! When a UE attaches, we need O(1) lookup: IMSI → world entity.
//! This registry is the secondary index over the ECS world.
// Auto-generated stub — Phase 2
