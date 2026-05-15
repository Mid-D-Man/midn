// crates/midn-core/src/ecs/systems.rs
//! ECS Systems — subscriber lifecycle batch processing.
//!
//! Each system is a pure function over a slice of the ECS world.
//! No heap allocation in the hot path.
//!
//! ## Phase 2 targets
//!
//! - `expire_stale_challenges`: scan all ChallengeIssued entities older
//!   than T300 timer and transition them to Failed(timeout).
//! - `collect_active_tunnels`: iterate all TunnelComponents and sync
//!   changes to the eBPF routing map.
//! - `periodic_tracking_area_update`: process TAU timers in bulk.
//!
//! ## SoA optimization note
//!
//! When world.auth is upgraded from HashMap to Vec (Phase 2), these
//! systems will benefit immediately — a linear scan of Vec<AuthState>
//! is fully cache-friendly and LLVM can auto-vectorize the comparison.

// Auto-generated stub — Phase 2 target
