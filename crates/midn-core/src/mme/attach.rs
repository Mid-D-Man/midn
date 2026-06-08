// crates/midn-core/src/mme/attach.rs
//! LTE Attach procedure — 3GPP TS 23.401 Section 5.3.2

use bytes::Bytes;
use midn_auth::milenage::MilenageContext;
use midn_proto::nas::codec::{
    decode_nas, encode_attach_accept, encode_auth_request,
    encode_sec_mode_cmd, NasPdu,
};
use midn_proto::nas::ie::{NasEeaAlgorithm, NasEiaAlgorithm};

use crate::ecs::components::{
    AuthFailReason, AuthState, ImsiComponent, SecurityContext, SessionState, TunnelComponent,
};
use crate::ecs::world::{CoreWorld, EntityId};
use crate::ecs::registry::ImsiRegistry;
use crate::hss::Hss;

/// Tracks the state of a single UE's attach procedure.
pub struct AttachContext {
    pub entity_id:      EntityId,
    pub enb_ue_s1ap_id: u32,
    pub mme_ue_s1ap_id: u32,
    pub imsi:           u64,
    pub state:          AttachState,
    pub ue_capability:  Vec<u8>,
    /// Uplink TEID pre-allocated by the MME for this session's UPF route.
    /// Set by `handle_security_mode_complete`. Used to build the ICSR
    /// and to emit `UpfEvent::UpdateBearer` when the ICSRSP arrives.
    pub ul_teid:        Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachState {
    ChallengeIssued,
    SecurityPending,
    AcceptPending,
    Attached,
    Failed(AttachFailReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachFailReason {
    ImsiNotProvisioned,
    AuthResponseMismatch,
    NasDecodeError,
    InternalError,
}

/// NAS PDU plus done flag — returned by attach step handlers.
pub struct AttachStep {
    pub nas_pdu: Bytes,
    pub done:    bool,
}

// ── Attach Request ────────────────────────────────────────────────────────────

pub fn handle_attach_request(
    nas_pdu:        &Bytes,
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    world:          &mut CoreWorld,
    registry:       &mut ImsiRegistry,
    hss:            &mut Hss,
) -> Result<(AttachContext, AttachStep), AttachFailReason> {
    let decoded = decode_nas(nas_pdu).map_err(|e| {
        tracing::warn!("NAS decode error in AttachRequest: {e}");
        AttachFailReason::NasDecodeError
    })?;

    let ar = match decoded {
        NasPdu::AttachRequest(ar) => ar,
        _ => return Err(AttachFailReason::NasDecodeError),
    };

    let imsi = ar.imsi.ok_or_else(|| {
        tracing::warn!("AttachRequest without IMSI — GUTI re-attach not yet supported");
        AttachFailReason::InternalError
    })?;

    tracing::info!(imsi, "Attach Request received");

    let auth_info = hss.get_auth_vector(imsi).ok_or_else(|| {
        tracing::warn!(imsi, "IMSI not provisioned in HSS");
        AttachFailReason::ImsiNotProvisioned
    })?;

    let entity_id = world.spawn();
    world.imsi.insert(entity_id, ImsiComponent(imsi));
    world.auth.insert(entity_id, AuthState::ChallengeIssued);

    let mut sec_ctx = SecurityContext::new_empty();
    sec_ctx.pending_rand.copy_from_slice(&auth_info.vector.rand.0);
    sec_ctx.pending_xres.copy_from_slice(&auth_info.vector.xres);
    sec_ctx.ck.copy_from_slice(&auth_info.vector.ck);
    sec_ctx.ik.copy_from_slice(&auth_info.vector.ik);
    world.security.insert(entity_id, sec_ctx);

    if let Some(old_entity) = registry.register(imsi, entity_id) {
        tracing::warn!(imsi, old_id = ?old_entity, new_id = ?entity_id,
            "IMSI already registered — possible re-attach without detach");
        world.despawn(old_entity);
    }

    let auth_req_pdu = encode_auth_request(
        0x07,
        &auth_info.vector.rand.0,
        &auth_info.vector.autn,
    );

    tracing::debug!(imsi, entity_id = ?entity_id, "Auth challenge issued");

    let ctx = AttachContext {
        entity_id,
        enb_ue_s1ap_id,
        mme_ue_s1ap_id,
        imsi,
        state:         AttachState::ChallengeIssued,
        ue_capability: ar.ue_network_cap,
        ul_teid:       None,
    };
    Ok((ctx, AttachStep { nas_pdu: auth_req_pdu, done: false }))
}

// ── Authentication Response ───────────────────────────────────────────────────

pub fn handle_auth_response(
    ctx:     &mut AttachContext,
    nas_pdu: &Bytes,
    world:   &mut CoreWorld,
) -> Result<AttachStep, AttachFailReason> {
    let decoded = decode_nas(nas_pdu).map_err(|_| AttachFailReason::NasDecodeError)?;
    let ar = match decoded {
        NasPdu::AuthenticationResponse(ar) => ar,
        _ => return Err(AttachFailReason::NasDecodeError),
    };

    let sec_ctx = world.security.get_mut(&ctx.entity_id)
        .ok_or(AttachFailReason::InternalError)?;
    let xres     = sec_ctx.pending_xres;
    let verified = MilenageContext::verify_res(&xres, &ar.res);
    sec_ctx.clear_pending();

    if !verified {
        tracing::warn!(imsi = ctx.imsi, "Authentication failed: RES mismatch");
        world.set_auth_state(ctx.entity_id, AuthState::Failed(AuthFailReason::ResMismatch));
        ctx.state = AttachState::Failed(AttachFailReason::AuthResponseMismatch);
        return Err(AttachFailReason::AuthResponseMismatch);
    }

    world.set_auth_state(ctx.entity_id, AuthState::Authenticated);
    ctx.state = AttachState::SecurityPending;
    tracing::info!(imsi = ctx.imsi, entity_id = ?ctx.entity_id, "UE authenticated");

    let sec_cmd_pdu = encode_sec_mode_cmd(
        NasEeaAlgorithm::Eea2,
        NasEiaAlgorithm::Eia2,
        0x07,
        &ctx.ue_capability,
    );

    let sec_ctx = world.security.get_mut(&ctx.entity_id)
        .ok_or(AttachFailReason::InternalError)?;
    sec_ctx.cipher_alg    = 2;
    sec_ctx.integrity_alg = 2;

    Ok(AttachStep { nas_pdu: sec_cmd_pdu, done: false })
}

// ── Security Mode Complete ────────────────────────────────────────────────────

/// Process Security Mode Complete.
///
/// Allocates an IP address, creates the PDN session, creates the GTP-U
/// `TunnelComponent` using the pre-allocated `ul_teid`, and builds the
/// `AttachAccept` NAS PDU.
///
/// The caller (state machine) decides whether to send the AttachAccept
/// directly via DownlinkNasTransport (Phase 2) or to embed it in an
/// InitialContextSetupRequest (Phase 3).
pub fn handle_security_mode_complete(
    ctx:      &mut AttachContext,
    nas_pdu:  &Bytes,
    world:    &mut CoreWorld,
    ip_pool:  &mut IpPool,
    ul_teid:  u32,
) -> Result<AttachStep, AttachFailReason> {
    let decoded = decode_nas(nas_pdu).map_err(|_| AttachFailReason::NasDecodeError)?;
    if !matches!(decoded, NasPdu::SecurityModeComplete) {
        return Err(AttachFailReason::NasDecodeError);
    }

    ctx.state   = AttachState::AcceptPending;
    ctx.ul_teid = Some(ul_teid);

    let ip = ip_pool.allocate(ctx.entity_id)
        .ok_or(AttachFailReason::InternalError)?;

    world.session.insert(ctx.entity_id, SessionState::new(ip, b"internet", 5));

    // TunnelComponent: ul_teid is pre-allocated; dl_teid and enb_addr are
    // placeholders until InitialContextSetupResponse arrives from eNodeB.
    world.tunnel.insert(ctx.entity_id, TunnelComponent::new(0, ul_teid, [0, 0, 0, 0]));

    tracing::info!(imsi = ctx.imsi, ip = ?ip, ul_teid, "Session created");

    let attach_accept_pdu = encode_attach_accept(
        0x01, 0x54, &[], Some(ip), Some("internet"),
    );

    Ok(AttachStep { nas_pdu: attach_accept_pdu, done: false })
}

// ── Initial Context Setup Response ───────────────────────────────────────────

/// Process the real DL TEID and eNodeB address from an
/// `InitialContextSetupResponse`.
///
/// Updates the `TunnelComponent` in the ECS world. The state machine then
/// emits a `UpfEvent::UpdateBearer` so the user-plane routing table can be
/// updated to match.
pub fn handle_initial_context_setup_response(
    ctx:      &AttachContext,
    dl_teid:  u32,
    enb_addr: [u8; 4],
    world:    &mut CoreWorld,
) -> Result<(), AttachFailReason> {
    let tunnel = world.tunnel.get_mut(&ctx.entity_id)
        .ok_or(AttachFailReason::InternalError)?;
    tunnel.dl_teid  = dl_teid;
    tunnel.enb_addr = enb_addr;
    tunnel.enb_port = TunnelComponent::GTP_PORT;
    tracing::info!(
        imsi     = ctx.imsi,
        dl_teid,
        enb_addr = ?enb_addr,
        "DL TEID and eNodeB address set from ICSRSP"
    );
    Ok(())
}

// ── Attach Complete ───────────────────────────────────────────────────────────

pub fn handle_attach_complete(
    ctx:     &mut AttachContext,
    nas_pdu: &Bytes,
) -> Result<(), AttachFailReason> {
    let decoded = decode_nas(nas_pdu).map_err(|_| AttachFailReason::NasDecodeError)?;
    if !matches!(decoded, NasPdu::AttachComplete) {
        return Err(AttachFailReason::NasDecodeError);
    }
    ctx.state = AttachState::Attached;
    tracing::info!(imsi = ctx.imsi, entity_id = ?ctx.entity_id, "Attach Complete — subscriber online");
    Ok(())
}

// ── IP Pool ───────────────────────────────────────────────────────────────────

/// Simple sequential IPv4 address pool. Phase 3: replace with IPAM.
pub struct IpPool {
    next:     u32,
    capacity: u32,
    assigned: std::collections::HashMap<EntityId, [u8; 4]>,
}

impl IpPool {
    pub fn new(base_ip: [u8; 4], capacity: u32) -> Self {
        let base = u32::from_be_bytes(base_ip);
        Self { next: base, capacity, assigned: std::collections::HashMap::new() }
    }

    pub fn allocate(&mut self, entity: EntityId) -> Option<[u8; 4]> {
        if self.assigned.len() >= self.capacity as usize { return None; }
        let ip = self.next.to_be_bytes();
        self.next = self.next.wrapping_add(1);
        self.assigned.insert(entity, ip);
        Some(ip)
    }

    pub fn release(&mut self, entity: EntityId) {
        self.assigned.remove(&entity);
    }
}

impl Default for IpPool {
    fn default() -> Self { Self::new([10, 0, 1, 1], 65_534) }
                               }
