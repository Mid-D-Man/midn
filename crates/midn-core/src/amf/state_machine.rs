// crates/midn-core/src/amf/state_machine.rs
//! AMF top-level state machine — 5G NR.
//!
//! Phase 3 stub — mirrors `mme::state_machine`'s structure (same `World` +
//! `ImsiRegistry` pair from `midn_ecs`, same "drive an ECS world from
//! incoming control-plane messages" shape), implements 5G NR procedures.
//!
//! ## Fixed: dead pre-ECS-extraction import path
//!
//! This file previously imported `crate::ecs::registry::ImsiRegistry` and
//! `crate::ecs::world::CoreWorld` — module paths that predate the
//! `midn-ecs` crate extraction and don't exist anymore (`midn-core` has no
//! `ecs` module at all — see `lib.rs`). This compiled without ever being
//! caught because `amf` isn't declared in `midn-core::lib.rs` (`pub mod
//! amf;` is absent), so it was never actually part of the build graph —
//! dead scaffold code from whatever generated the initial project
//! structure. Fixed here to use `midn_ecs::{ImsiRegistry, World}`, the same
//! import `mme::state_machine` and `mme::attach` already use — per
//! `midn-ecs`'s own crate doc, this is exactly why it was pulled out as its
//! own crate: "so a future `midn-core::amf` ... can share the same storage
//! `midn-core::mme` drives."
//!
//! Still NOT wired into `lib.rs` (`pub mod amf;` still absent) — that's the
//! next increment, once the registration procedure below actually does
//! something. Wiring it in now, with `process_ngap` still a stub, would
//! just turn a currently-invisible-and-harmless dead file into a
//! visible-and-harmless empty one; no benefit until there's a real
//! procedure to expose.

use midn_ecs::{ImsiRegistry, World};
use midn_proto::ngap::messages::NgapMessage;

/// Access and Mobility Function (5G NR).
pub struct Amf {
    pub world:    World,
    pub registry: ImsiRegistry,
}

impl Amf {
    pub fn new() -> Self {
        Self {
            world:    World::new(),
            registry: ImsiRegistry::new(),
        }
    }

    /// Process an incoming NGAP message from a gNodeB.
    pub async fn process_ngap(&mut self, msg: NgapMessage) -> Vec<NgapMessage> {
        match msg {
            NgapMessage::InitialUeMessage(ium) => {
                tracing::debug!(
                    ran_ue_ngap_id = ium.ran_ue_ngap_id,
                    "NGAP InitialUeMessage received"
                );
                // TODO Phase 3B: 5G Registration procedure — mirrors
                // mme::attach::handle_initial_ue_message, but:
                //   - SUCI-based identity instead of plain IMSI-in-the-clear
                //   - 5G-AKA (TS 33.501 Annex A) instead of TS 33.401's
                //     Milenage/Kasme derivation — reuses the same f1-f5
                //     primitives from midn-auth, different KDF wrapping
                //   - RegistrationAccept instead of AttachAccept as the
                //     NAS PDU piggybacked on InitialContextSetupRequest
                vec![]
            }
            _ => {
                tracing::warn!("Unhandled NGAP message type");
                vec![]
            }
        }
    }

    pub fn subscriber_count(&self) -> usize { self.world.subscriber_count() }
}

impl Default for Amf {
    fn default() -> Self { Self::new() }
    }
