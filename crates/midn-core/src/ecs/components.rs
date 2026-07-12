//! ECS Components — subscriber state decomposed into data.
//!
//! Each component is cache-line conscious. Hot components
//! (SessionState, TunnelState) are 64-byte aligned.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Unique subscriber identity. 15-digit IMSI encoded as u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImsiComponent(pub u64);

/// Authentication state of a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    Unauthenticated,
    Challenged { rand: [u8; 16], xres: [u8; 8] },
    Authenticated,
    Failed,
}

/// NAS security context — cipher + integrity keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(C, align(64))]
pub struct SecurityContext {
    pub ck:          [u8; 16],
    pub ik:          [u8; 16],
    pub kasme:       [u8; 32],
    pub dl_count:    u32,
    pub ul_count:    u32,
    pub cipher_alg:  u8,
    pub integr_alg:  u8,
    _pad:            [u8; 10],
}

/// PDN session state — IP address and APN.
#[derive(Debug, Clone)]
#[repr(C, align(64))]
pub struct SessionState {
    pub ip_address:  [u8; 4],
    pub apn:         [u8; 64],
    pub apn_len:     u8,
    pub bearer_id:   u8,
    pub active:      bool,
    _pad:            [u8; 5],
}

/// GTP tunnel component — maps subscriber to TEID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(16))]
pub struct TunnelComponent {
    /// Downlink TEID (assigned by eNodeB/gNodeB)
    pub dl_teid:     u32,
    /// Uplink TEID (assigned by UPF/P-GW)
    pub ul_teid:     u32,
    /// eNodeB/gNodeB transport address
    pub enb_addr:    [u8; 4],
    pub enb_port:    u16,
    _pad:            [u8; 2],
}

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
    fn tunnel_component_alignment() {
        assert_eq!(core::mem::align_of::<TunnelComponent>(), 16);
    }
}
