// crates/midn-core/src/amf/state_machine.rs
//! AMF top-level state machine — 5G NR.
//!
//! Phase 3 stub — mirrors MME structure, implements 5G NR procedures.

use crate::ecs::registry::ImsiRegistry;
use crate::ecs::world::CoreWorld;
use midn_proto::ngap::messages::NgapMessage;

/// Access and Mobility Function (5G NR).
pub struct Amf {
    pub world:    CoreWorld,
    pub registry: ImsiRegistry,
}

impl Amf {
    pub fn new() -> Self {
        Self {
            world:    CoreWorld::new(),
            registry: ImsiRegistry::new(),
        }
    }

    /// Process an incoming NGAP message from a gNodeB.
    pub async fn process_ngap(&mut self, msg: NgapMessage) -> Vec<NgapMessage> {
        match msg {
            NgapMessage::InitialUeMessage(_ium) => {
                tracing::debug!("NGAP InitialUeMessage received");
                // TODO Phase 3: 5G Registration procedure
                vec![]
            }
            _ => {
                tracing::warn!("Unhandled NGAP message type");
                vec![]
            }
        }
    }

    pub fn subscriber_count(&self) -> usize { self.world.len() }
}

impl Default for Amf {
    fn default() -> Self { Self::new() }
}
