//! GTP-U tunnel manager — lifecycle of GTP tunnels.
//!
//! A tunnel is created when a subscriber attaches and a PDN bearer
//! is established. It is destroyed when the subscriber detaches.
//! Each tunnel is identified by a pair of TEIDs (UL + DL).
// Auto-generated stub — Phase 2
