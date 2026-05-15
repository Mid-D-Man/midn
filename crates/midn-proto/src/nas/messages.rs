// crates/midn-proto/src/nas/messages.rs
//! NAS message type definitions.
//!
//! Based on 3GPP TS 24.301 (LTE EPS Mobility Management).
//! 5G NR equivalents (24.501) are noted in comments.

/// Top-level NAS message discriminant.
///
/// Each variant carries its Information Elements (IEs) as a struct.
#[derive(Debug, Clone, PartialEq)]
pub enum NasMessage {
    // ── Mobility Management ───────────────────────────────────────────────
    /// UE → MME: initiate attachment to the network.
    AttachRequest(AttachRequest),
    /// MME → UE: send RAND + AUTN challenge.
    AuthenticationRequest(AuthenticationRequest),
    /// UE → MME: send RES (response to challenge).
    AuthenticationResponse(AuthenticationResponse),
    /// MME → UE: authentication failed.
    AuthenticationReject,
    /// MME → UE: activate NAS security (cipher + integrity algorithm).
    SecurityModeCommand(SecurityModeCommand),
    /// UE → MME: NAS security activated, send NAS MAC.
    SecurityModeComplete,
    /// MME → UE: attach accepted, assign GUTI + IP address.
    AttachAccept(AttachAccept),
    /// UE → MME: attach complete, data plane can open.
    AttachComplete,
    /// UE → MME / MME → UE: detach from network.
    DetachRequest { reattach_required: bool },
    /// MME → UE: detach accepted.
    DetachAccept,
    // ── Service Request ───────────────────────────────────────────────────
    /// UE → MME: request service (paging response or data).
    ServiceRequest { ksi: u8, sequence_number: u8 },
}

/// Attach Request IEs — 3GPP TS 24.301 Section 8.2.4.
#[derive(Debug, Clone, PartialEq)]
pub struct AttachRequest {
    /// EPS attach type: 1=EPS, 2=combined EPS/IMSI, 6=EPS emergency
    pub attach_type:    u8,
    /// Mobile identity: IMSI (8 bytes BCD) or GUTI (10 bytes)
    pub imsi:           Option<[u8; 8]>,
    pub guti:           Option<[u8; 10]>,
    /// UE network capabilities (ciphering/integrity algorithm support)
    pub ue_network_cap: u32,
    /// PDN connectivity request (bundled with attach)
    pub pdn_type:       u8,
}

/// Authentication Request IEs — 3GPP TS 24.301 Section 8.2.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationRequest {
    /// Key Set Identifier in ASME (KSI_ASME) — 3 bits
    pub ksi_asme: u8,
    /// Random challenge from Milenage
    pub rand:     [u8; 16],
    /// Authentication token (SQN XOR AK || AMF || MAC-A)
    pub autn:     [u8; 16],
}

/// Authentication Response IEs — 3GPP TS 24.301 Section 8.2.8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationResponse {
    /// UE's response (f2 output). MME compares against XRES.
    pub res: [u8; 8],
}

/// Security Mode Command IEs — 3GPP TS 24.301 Section 8.2.20.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityModeCommand {
    /// Selected NAS ciphering algorithm (0=EEA0, 1=128-EEA1, 2=128-EEA2)
    pub nas_cipher_alg:     u8,
    /// Selected NAS integrity algorithm (0=EIA0, 1=128-EIA1, 2=128-EIA2)
    pub nas_integrity_alg:  u8,
    /// Replayed UE security capabilities (for binding)
    pub replayed_ue_sec_cap: u32,
}

/// Attach Accept IEs — 3GPP TS 24.301 Section 8.2.1.
#[derive(Debug, Clone, PartialEq)]
pub struct AttachAccept {
    /// Attach result: 1=EPS, 3=combined EPS/IMSI
    pub attach_result: u8,
    /// T3412 periodic tracking area update timer (encoded)
    pub t3412_value:   u8,
    /// Tracking Area Identity List
    pub tai_list:      Vec<[u8; 5]>,
    /// Assigned GUTI (Globally Unique Temporary UE Identity)
    pub guti:          [u8; 10],
    /// Access Point Name
    pub apn:           String,
    /// Assigned IPv4 address
    pub ip_address:    [u8; 4],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_request_round_trip_fields() {
        let req = AuthenticationRequest {
            ksi_asme: 0x07,
            rand: [0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D,
                   0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35],
            autn: [0xAA, 0x68, 0x9C, 0x64, 0x83, 0x70, 0x00, 0x00,
                   0xB9, 0xB9, 0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF],
        };
        assert_eq!(req.rand[0], 0x23);
        assert_eq!(req.autn[0], 0xAA);
    }
}
