//! ECS component definitions for subscriber state.
//!
//! `NasSecurityContext` is intentionally NOT a field on [`SecurityContext`]
//! — different lifecycle (created once, post-SecurityModeComplete, lives
//! for the rest of the session) from the AKA material here (live only
//! during the attach challenge, cleared once consumed).

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub struct IdentityComponent {
    pub imsi: u64,
    pub enb_ue_s1ap_id: u32,
    pub ue_ip: [u8; 4],
}

impl IdentityComponent {
    pub fn empty() -> Self {
        Self { imsi: 0, enb_ue_s1ap_id: 0, ue_ip: [0; 4] }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    Unauthenticated,
    ChallengeIssued,
    Authenticated,
    Failed(AuthFailReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailReason {
    ResMismatch,
    MacFailure,
    SqnOutOfRange,
    InternalError,
}

/// AKA security material in flight during authentication + Kasme
/// derivation. `plmn`/`sqn_used` aren't secret — `#[zeroize(skip)]`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecurityContext {
    pub pending_rand: [u8; 16],
    pub pending_xres: [u8; 8],
    pub ck: [u8; 16],
    pub ik: [u8; 16],
    pub ak: [u8; 6],
    #[zeroize(skip)]
    pub plmn: [u8; 3],
    #[zeroize(skip)]
    pub sqn_used: [u8; 6],
}

impl SecurityContext {
    pub fn new_empty() -> Self {
        Self {
            pending_rand: [0; 16], pending_xres: [0; 8],
            ck: [0; 16], ik: [0; 16], ak: [0; 6],
            plmn: [0; 3], sqn_used: [0; 6],
        }
    }

    /// Wipe RAND/XRES — call right after RES verification, pass or fail.
    pub fn clear_pending_challenge(&mut self) {
        self.pending_rand.zeroize();
        self.pending_xres.zeroize();
    }

    /// Wipe CK/IK/AK — call right after Kasme has been derived from them.
    pub fn clear_post_kasme(&mut self) {
        self.ck.zeroize();
        self.ik.zeroize();
        self.ak.zeroize();
    }
}

impl core::fmt::Debug for SecurityContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecurityContext")
            .field("plmn", &self.plmn)
            .field("sqn_used", &self.sqn_used)
            .field("pending_rand", &"[REDACTED]")
            .field("pending_xres", &"[REDACTED]")
            .field("ck", &"[REDACTED]")
            .field("ik", &"[REDACTED]")
            .field("ak", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelComponent {
    pub ul_teid: u32,
    pub dl_teid: u32,
    pub enb_addr: [u8; 4],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_pending_challenge_zeros_only_challenge_fields() {
        let mut ctx = SecurityContext::new_empty();
        ctx.pending_rand = [0xAA; 16];
        ctx.ck = [0xCC; 16];
        ctx.clear_pending_challenge();
        assert_eq!(ctx.pending_rand, [0u8; 16]);
        assert_eq!(ctx.ck, [0xCC; 16]);
    }

    #[test]
    fn clear_post_kasme_zeros_only_kasme_inputs() {
        let mut ctx = SecurityContext::new_empty();
        ctx.ck = [0xCC; 16];
        ctx.pending_rand = [0xAA; 16];
        ctx.clear_post_kasme();
        assert_eq!(ctx.ck, [0u8; 16]);
        assert_eq!(ctx.pending_rand, [0xAA; 16]);
    }
}
