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


//! MME — Mobility Management Entity (3GPP TS 23.401 / 36.413)

pub mod attach;
pub mod state_machine;

pub use state_machine::{Mme, UpfEvent};
