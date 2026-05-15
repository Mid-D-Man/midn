//! NGAP message types — 3GPP TS 38.413
//! Auto-generated stub — Phase 2 (5G extension)

#[derive(Debug, Clone)]
pub enum NgapMessage {
    /// gNodeB → AMF: UE initiates registration
    InitialUeMessage,
    /// AMF → gNodeB: forward NAS PDU
    DownlinkNasTransport,
    /// gNodeB → AMF: forward NAS PDU
    UplinkNasTransport,
    /// AMF → gNodeB: establish PDU session
    PduSessionResourceSetupRequest,
    /// gNodeB → AMF: PDU session established
    PduSessionResourceSetupResponse,
}
