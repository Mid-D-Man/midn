//! NAS message types — 3GPP TS 24.301 (LTE) / 24.501 (5G)

/// Top-level NAS message discriminant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NasMessage {
    /// UE → MME/AMF: initiate attach
    AttachRequest(AttachRequest),
    /// MME/AMF → UE: send RAND + AUTN
    AuthenticationRequest(AuthenticationRequest),
    /// UE → MME/AMF: send RES
    AuthenticationResponse(AuthenticationResponse),
    /// MME/AMF → UE: reject auth
    AuthenticationReject,
    /// MME/AMF → UE: activate NAS security
    SecurityModeCommand(SecurityModeCommand),
    /// UE → MME/AMF: confirm security mode
    SecurityModeComplete,
    /// MME/AMF → UE: assign IP + bearer
    AttachAccept(AttachAccept),
    /// UE → MME/AMF: confirm attach
    AttachComplete,
    /// Any → Any: detach
    DetachRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachRequest {
    pub imsi:    Option<[u8; 8]>,
    pub guti:    Option<[u8; 10]>,
    pub ue_caps: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationRequest {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationResponse {
    pub res: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityModeCommand {
    pub selected_nas_cipher:    u8,
    pub selected_nas_integrity: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachAccept {
    pub guti:        [u8; 10],
    pub apn:         heapless::String<64>,
    pub ip_address:  [u8; 4],
}
