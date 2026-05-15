// crates/midn-core/src/mme/state_machine.rs
//! MME top-level state machine and message dispatcher.

use crate::ecs::registry::ImsiRegistry;
use crate::ecs::world::CoreWorld;
use midn_proto::s1ap::messages::S1apMessage;

/// Mobility Management Entity.
///
/// Owns the ECS world and IMSI registry. Processes incoming S1AP messages
/// from eNodeBs and returns outbound S1AP messages to be sent back.
pub struct Mme {
    pub world:    CoreWorld,
    pub registry: ImsiRegistry,
}

impl Mme {
    /// Create a new MME with a fresh ECS world and IMSI registry.
    pub fn new() -> Self {
        Self {
            world:    CoreWorld::new(),
            registry: ImsiRegistry::new(),
        }
    }

    /// Process an incoming S1AP message from an eNodeB.
    ///
    /// Returns zero or more S1AP messages to be sent in response.
    ///
    /// # Phase 2 target
    ///
    /// Implement the full attach procedure dispatching logic here.
    /// Each message type routes to the appropriate procedure handler.
    pub async fn process_s1ap(
        &mut self,
        msg: S1apMessage,
    ) -> Vec<S1apMessage> {
        match msg {
            S1apMessage::InitialUeMessage(ium) => {
                tracing::debug!("InitialUeMessage from eNB-UE-S1AP-ID={}", ium.enb_ue_s1ap_id);
                // TODO Phase 2: decode NAS PDU → route to attach::handle_attach_request
                vec![]
            }
            S1apMessage::UplinkNasTransport(unt) => {
                tracing::debug!("UplinkNasTransport from MME-UE-S1AP-ID={}", unt.mme_ue_s1ap_id);
                // TODO Phase 2: decode NAS PDU → route based on NAS message type
                vec![]
            }
            S1apMessage::S1SetupRequest(req) => {
                tracing::info!("S1 Setup from eNodeB name={:?}", req.enb_name);
                // TODO Phase 2: register eNodeB, respond with S1SetupResponse
                vec![]
            }
            S1apMessage::UeContextReleaseComplete { .. } => {
                // TODO Phase 2: despawn the UE entity, deregister IMSI
                vec![]
            }
            _ => {
                tracing::warn!("Unhandled S1AP message type");
                vec![]
            }
        }
    }

    /// Subscriber count snapshot.
    pub fn subscriber_count(&self) -> usize { self.world.len() }
}

impl Default for Mme {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mme_starts_empty() {
        let mme = Mme::new();
        assert_eq!(mme.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn s1_setup_request_returns_empty_until_phase2() {
        let mut mme = Mme::new();
        let req = S1apMessage::S1SetupRequest(
            midn_proto::s1ap::messages::S1SetupRequest {
                global_enb_id:      [0u8; 8],
                enb_name:           Some("test-enb-1".to_string()),
                supported_tas:      vec![],
                default_paging_drx: 32,
            }
        );
        let responses = mme.process_s1ap(req).await;
        // Phase 1: no response yet — Phase 2 adds S1SetupResponse
        assert!(responses.is_empty(), "Phase 2 will populate this");
    }
}
