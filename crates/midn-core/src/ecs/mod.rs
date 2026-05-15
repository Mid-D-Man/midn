//! ECS — Entity Component System for subscriber state.
//!
//! Entities  = Subscribers (UEs)
//! Components = IMSI, AuthState, SecurityContext, Session, Tunnel
//! Systems    = Attach, Authenticate, Activate, Detach

pub mod components;
pub mod systems;
pub mod world;
pub mod registry;
