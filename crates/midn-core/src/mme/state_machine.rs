//! MME top-level state machine.
//!
//! Processes incoming messages from eNodeB (S1AP) and
//! UE (via NAS), updating ECS subscriber state accordingly.

use crate::ecs::world::CoreWorld;

pub struct Mme {
    world: CoreWorld,
}

impl Mme {
    pub fn new() -> Self {
        Self { world: CoreWorld::new() }
    }

    // TODO: process_s1ap_message, process_nas_message — Phase 2
}

impl Default for Mme {
    fn default() -> Self { Self::new() }
}
