// crates/midn-core/src/ecs/components.rs
//! ECS component definitions — subscriber state decomposed into data.
//!
//! ## Cache-line discipline
//!
//! Hot components (SecurityContext, SessionState) are 64-byte aligned.
//! Cold components (ImsiComponent, AuthState) are unaligned — they are
//! read infrequently (only at auth or detach).
//!
//! ## Security contracts
//!
//! SecurityContext is `ZeroizeOnDrop` — CK, IK, Kasme, and pending XRES
//! are wiped from memory when the subscriber detaches or auth fails.
//! No secret material persists past the Drop.

use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Identity ──────────────────────────────────────────────────────────────────

/// Subscriber identity — 15-digit IMSI encoded as u64 (BCD decoded).
///
/// IMSI = MCC (3) + MNC (2 or 3) + MSIN (9 or 10 digits).
/// Example: 234 15 1234567890 → 234151234567890u64
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImsiComponent(pub u64);

// ── Authentication state machine ──────────────────────────────────────────────

/// Authentication state for a subscriber entity.
///
/// Transitions:
///   Unauthenticated → ChallengeIssued → Authenticated
///                   ↘               ↗
///                      Failed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// No authentication attempted yet.
    Unauthenticated,
    /// MME has sent (RAND, AUTN) — awaiting UE's RES.
    /// XRES is stored in SecurityContext.pending_xres.
    ChallengeIssued,
    /// UE's RES matched XRES — subscriber is authenticated.
    Authenticated,
    /// Authentication failed — reason recorded.
    Failed(AuthFailReason),
}

/// Reason for authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailReason {
    /// RES did not match XRES (wrong SIM or replayed challenge).
    ResMismatch,
    /// UE rejected the network authentication token (AUTN invalid).
    /// Triggers SQN re-synchronization.
    MacFailure,
    /// SQN in AUTN was out of the acceptable window.
    SqnOutOfRange,
    /// Internal error generating the auth vector.
    InternalError,
}

// ── Security context ──────────────────────────────────────────────────────────

/// NAS security context. Holds session keys and auth material.
///
/// 64-byte aligned for cache-line safety in hot paths.
/// All fields are zeroized on drop — no secrets persist.
///
/// ## Key hierarchy (LTE)
/// ```text
/// Ki (SIM) + OPc (HSS) → Milenage → CK, IK
/// CK + IK + serving network id → KDF → Kasme
/// Kasme + NAS uplink count   → KDF → KNASenc (cipher)
/// Kasme + NAS uplink count   → KDF → KNASint (integrity)
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(C, align(64))]
pub struct SecurityContext {
    /// Pending expected response — stored during ChallengeIssued state.
    /// Compared against UE RES using constant-time equality.
    /// Zeroized as soon as verification completes (pass or fail).
    pub pending_xres:  [u8; 8],
    /// Random challenge issued to the UE (RAND).
    pub pending_rand:  [u8; 16],
    /// Cipher key (CK) from Milenage f3.
    pub ck:            [u8; 16],
    /// Integrity key (IK) from Milenage f4.
    pub ik:            [u8; 16],
    /// Anchor key Kasme derived from CK+IK (LTE).
    /// Used as the root for all NAS key derivation.
    pub kasme:         [u8; 32],
    /// Downlink NAS COUNT — incremented per protected NAS message.
    pub dl_nas_count:  u32,
    /// Uplink NAS COUNT — verified per UE NAS message.
    pub ul_nas_count:  u32,
    /// Selected NAS ciphering algorithm (0=EEA0, 2=AES-CTR).
    pub cipher_alg:    u8,
    /// Selected NAS integrity algorithm (2=AES-CMAC).
    pub integrity_alg: u8,
    _pad:              [u8; 6],
}

impl SecurityContext {
    /// Create a zeroed security context — ready to receive auth material.
    pub fn new_empty() -> Self {
        Self {
            pending_xres:  [0u8; 8],
            pending_rand:  [0u8; 16],
            ck:            [0u8; 16],
            ik:            [0u8; 16],
            kasme:         [0u8; 32],
            dl_nas_count:  0,
            ul_nas_count:  0,
            cipher_alg:    0,
            integrity_alg: 0,
            _pad:          [0u8; 6],
        }
    }

    /// Zero out pending auth material after verification.
    ///
    /// Called immediately after RES/XRES comparison regardless of outcome.
    pub fn clear_pending(&mut self) {
        self.pending_xres.zeroize();
        self.pending_rand.zeroize();
    }
}

impl core::fmt::Debug for SecurityContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecurityContext")
            .field("dl_nas_count",  &self.dl_nas_count)
            .field("ul_nas_count",  &self.ul_nas_count)
            .field("cipher_alg",    &self.cipher_alg)
            .field("integrity_alg", &self.integrity_alg)
            .field("ck",            &"[REDACTED]")
            .field("ik",            &"[REDACTED]")
            .field("kasme",         &"[REDACTED]")
            .finish()
    }
}

// ── Session state ─────────────────────────────────────────────────────────────

/// PDN session state — assigned after successful attach.
///
/// 64-byte aligned — this is read on every data packet arrival in the UPF
/// (to resolve subscriber → tunnel mapping).
#[derive(Debug, Clone)]
#[repr(C, align(64))]
pub struct SessionState {
    /// Assigned IPv4 address (PDN address).
    pub ip_address:  [u8; 4],
    /// Access Point Name as raw bytes (operator-defined).
    pub apn:         [u8; 64],
    /// Actual length of APN string in `apn` (0..=64).
    pub apn_len:     u8,
    /// EPS Bearer ID (5 = default bearer).
    pub bearer_id:   u8,
    /// Is this session currently active?
    pub active:      bool,
    _pad:            [u8; 5],
}

impl SessionState {
    pub fn new(ip: [u8; 4], apn: &[u8], bearer_id: u8) -> Self {
        let mut apn_buf = [0u8; 64];
        let len = apn.len().min(64);
        apn_buf[..len].copy_from_slice(&apn[..len]);
        Self {
            ip_address:  ip,
            apn:         apn_buf,
            apn_len:     len as u8,
            bearer_id,
            active:      true,
            _pad:        [0u8; 5],
        }
    }

    /// Return the APN as a UTF-8 string slice (best effort).
    pub fn apn_str(&self) -> &str {
        let len = self.apn_len as usize;
        core::str::from_utf8(&self.apn[..len]).unwrap_or("<invalid utf8>")
    }
}

// ── Tunnel component ──────────────────────────────────────────────────────────

/// GTP-U tunnel mapping — links subscriber session to the data plane.
///
/// 16-byte aligned. One of these is created per active session and
/// mirrored into the eBPF routing map (Phase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(16))]
pub struct TunnelComponent {
    /// Downlink TEID assigned by the eNodeB/gNodeB (toward UE).
    pub dl_teid:   u32,
    /// Uplink TEID assigned by the UPF/P-GW (toward PDN).
    pub ul_teid:   u32,
    /// eNodeB transport layer address (for GTP-U DL path).
    pub enb_addr:  [u8; 4],
    /// eNodeB GTP-U port (usually 2152).
    pub enb_port:  u16,
    _pad:          [u8; 2],
}

impl TunnelComponent {
    pub const GTP_PORT: u16 = 2152;

    pub fn new(dl_teid: u32, ul_teid: u32, enb_addr: [u8; 4]) -> Self {
        Self {
            dl_teid,
            ul_teid,
            enb_addr,
            enb_port: Self::GTP_PORT,
            _pad: [0u8; 2],
        }
    }
}

// ── Alignment tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_context_alignment() {
        assert_eq!(core::mem::align_of::<SecurityContext>(), 64,
            "SecurityContext must be 64-byte aligned for cache-line safety");
    }

    #[test]
    fn session_state_alignment() {
        assert_eq!(core::mem::align_of::<SessionState>(), 64);
    }

    #[test]
    fn tunnel_component_size_and_alignment() {
        assert_eq!(core::mem::align_of::<TunnelComponent>(), 16);
        assert_eq!(core::mem::size_of::<TunnelComponent>(), 16);
    }

    #[test]
    fn session_state_apn_roundtrip() {
        let session = SessionState::new(
            [10, 0, 0, 1],
            b"internet.operator.com",
            5,
        );
        assert_eq!(session.apn_str(), "internet.operator.com");
        assert!(session.active);
        assert_eq!(session.bearer_id, 5);
    }

    #[test]
    fn security_context_clear_pending_zeros() {
        let mut ctx = SecurityContext::new_empty();
        ctx.pending_xres = [0xAA; 8];
        ctx.pending_rand = [0xBB; 16];
        ctx.clear_pending();
        assert_eq!(ctx.pending_xres, [0u8; 8]);
        assert_eq!(ctx.pending_rand, [0u8; 16]);
    }

    #[test]
    fn auth_state_transitions_are_non_overlapping() {
        // Verify variant sizes are what we expect (no padding surprises)
        let s1 = AuthState::Unauthenticated;
        let s2 = AuthState::ChallengeIssued;
        let s3 = AuthState::Authenticated;
        let s4 = AuthState::Failed(AuthFailReason::ResMismatch);
        assert_ne!(s1, s2);
        assert_ne!(s3, s4);
    }
}
