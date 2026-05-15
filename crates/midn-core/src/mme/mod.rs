//! MME — Mobility Management Entity (LTE / 4G)
//!
//! The MME is the control plane brain of LTE:
//!   - Authenticates UEs via HSS
//!   - Manages security contexts
//!   - Coordinates with eNodeB via S1AP
//!   - Sets up PDN connections via S-GW/P-GW

pub mod state_machine;
pub mod attach;

pub use state_machine::Mme;
