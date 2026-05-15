//! MME Attach procedure — 3GPP TS 23.401 Section 5.3.2
//!
//! Sequence:
//!   1. UE sends Attach Request (NAS) via eNodeB (S1AP)
//!   2. MME authenticates UE via Milenage (midn-auth)
//!   3. MME activates NAS security
//!   4. MME creates default PDN connection
//!   5. MME sends Attach Accept with GUTI + IP address
// Auto-generated stub — Phase 2
