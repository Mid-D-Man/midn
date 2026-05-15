//! S1AP message types — 3GPP TS 36.413

#[derive(Debug, Clone)]
pub enum S1apMessage {
    /// eNodeB → MME: UE initiates attach
    InitialUeMessage(InitialUeMessageIe),
    /// MME → eNodeB: forward NAS PDU
    DownlinkNasTransport(DownlinkNasTransportIe),
    /// eNodeB → MME: forward NAS PDU
    UplinkNasTransport(UplinkNasTransportIe),
    /// MME → eNodeB: establish E-RAB for data
    InitialContextSetupRequest,
    /// eNodeB → MME: E-RAB established
    InitialContextSetupResponse,
    /// Any: release UE context
    UeContextRelease,
}

#[derive(Debug, Clone)]
pub struct InitialUeMessageIe {
    pub enb_ue_s1ap_id: u32,
    pub nas_pdu:        bytes::Bytes,
    pub tai:            [u8; 5],
}

#[derive(Debug, Clone)]
pub struct DownlinkNasTransportIe {
    pub mme_ue_s1ap_id: u32,
    pub enb_ue_s1ap_id: u32,
    pub nas_pdu:        bytes::Bytes,
}

#[derive(Debug, Clone)]
pub struct UplinkNasTransportIe {
    pub mme_ue_s1ap_id: u32,
    pub enb_ue_s1ap_id: u32,
    pub nas_pdu:        bytes::Bytes,
}
