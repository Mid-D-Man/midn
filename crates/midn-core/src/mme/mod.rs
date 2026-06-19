// crates/midn-core/src/mme/mod.rs
//! MME — Mobility Management Entity (3GPP TS 23.401 / 36.413)
//!
//! The MME is the control plane brain of LTE:
//!   - Authenticates UEs via Milenage (calls midn-auth)
//!   - Manages NAS security contexts (activates ciphering + integrity)
//!   - Interfaces with eNodeBs via S1AP
//!   - Coordinates bearer setup with S-GW/P-GW
//!
//! ## Subscriber lifecycle (MME perspective)
//!
//! ```text
//! eNodeB sends InitialUeMessage (S1AP)
//!   → extract NAS PDU → decode AttachRequest
//!   → lookup/create ECS entity for IMSI
//!   → call midn-auth: generate_vector(Ki, OPc, SQN)
//!   → send AuthenticationRequest (NAS) to UE
//!   → UE sends AuthenticationResponse (RES)
//!   → verify RES == XRES (constant-time)
//!   → send SecurityModeCommand (NAS)
//!   → UE sends SecurityModeComplete
//!   → activate EPS bearer, assign IP
//!   → send AttachAccept (NAS) + InitialContextSetupRequest (S1AP)
//!   → UE sends AttachComplete → subscriber online
//! ```
//!
//! ## Subscriber teardown — two triggers, one path
//!
//! ```text
//! Network-initiated:  (anything) → MME → S1AP UeContextReleaseCommand
//! UE-initiated:        UE → NAS DetachRequest → mme::detach → S1AP UeContextReleaseCommand
//! ```
//!
//! Both converge on `UeContextReleaseComplete`, which is the only place that
//! actually despawns the entity, deregisters the IMSI, releases the TEID back
//! to `TeidAllocator`, and emits `UpfEvent::RemoveSession`.

pub mod attach;
pub mod detach;
pub mod state_machine;

pub use state_machine::{Mme, TeidAllocator, UpfEvent};
