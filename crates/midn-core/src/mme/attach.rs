// crates/midn-core/src/mme/attach.rs
//! LTE Attach procedure — 3GPP TS 23.401 Section 5.3.2
//!
//! Implements the full attach state machine driven by NAS messages
//! relayed through S1AP. Each `handle_*` method advances the state machine
//! by one step and returns the NAS response to send back to the UE.

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachState {
    /// Attach Request received — auth vector generated, challenge sent.
    ChallengeIssued,
    /// RES verified — Security Mode Command sent.
    SecurityPending,
    /// Security mode active — Attach Accept sent.
    AcceptPending,
    /// Attach Complete received — subscriber online.
    Attached,
    /// Attach failed.
    Failed(AttachFailReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachFailReason {
    ImsiNotProvisioned,
    AuthResponseMismatch,
    NasDecodeError,
    InternalError,
}

/// Result of one step of the attach procedure.
pub struct AttachStep {
    /// NAS PDU to send to the UE (wrapped in DownlinkNasTransport by caller).
    pub nas_pdu: Bytes,
    /// Whether the attach procedure is complete (terminal state).
    pub done:    bool,
}

// ── Attach Request handler ────────────────────────────────────────────────────

/// Process an initial Attach Request.
///
/// Returns `Ok(AttachContext, AttachStep)` if auth vector generation succeeded.
/// The AttachStep contains the NAS Authentication Request to send to the UE.
pub fn handle_attach_request(
    nas_pdu:        &Bytes,
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    world:          &mut CoreWorld,
    registry:       &mut ImsiRegistry,
    hss:            &mut Hss,
) -> Result<(AttachContext, AttachStep), AttachFailReason> {
    // Decode the NAS AttachRequest
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

    // Look up subscriber in HSS
    let auth_info = hss.get_auth_vector(imsi).ok_or_else(|| {
        tracing::warn!(imsi, "IMSI not provisioned in HSS");
        AttachFailReason::ImsiNotProvisioned
    })?;

    // Create ECS entity for this subscriber
    let entity_id = world.spawn();
    world.imsi.insert(entity_id, ImsiComponent(imsi));
    world.auth.insert(entity_id, AuthState::ChallengeIssued);

    // Store pending auth material in SecurityContext
    let mut sec_ctx = SecurityContext::new_empty();
    sec_ctx.pending_rand.copy_from_slice(&auth_info.vector.rand.0);
    sec_ctx.pending_xres.copy_from_slice(&auth_info.vector.xres);
    sec_ctx.ck.copy_from_slice(&auth_info.vector.ck);
    sec_ctx.ik.copy_from_slice(&auth_info.vector.ik);
    world.security.insert(entity_id, sec_ctx);

    // Register IMSI → entity mapping
    if let Some(old_entity) = registry.register(imsi, entity_id) {
        tracing::warn!(imsi, old_id = ?old_entity, new_id = ?entity_id,
            "IMSI already registered — possible re-attach without detach");
        world.despawn(old_entity);
    }

    // Build NAS AuthenticationRequest
    let auth_req_pdu = encode_auth_request(
        0x07, // NAS KSI = 7 (no valid cached context, force new)
        &auth_info.vector.rand.0,
        &auth_info.vector.autn,
    );

    tracing::debug!(imsi, entity_id = ?entity_id, "Auth challenge issued");

    let ctx = AttachContext {
        entity_id,
        enb_ue_s1ap_id,
        mme_ue_s1ap_id,
        imsi,
        state:          AttachState::ChallengeIssued,
        ue_capability:  ar.ue_network_cap,
    };

    Ok((ctx, AttachStep { nas_pdu: auth_req_pdu, done: false }))
}

// ── Authentication Response handler ──────────────────────────────────────────

/// Process a NAS Authentication Response (UE's RES).
///
/// Verifies RES against stored XRES using constant-time comparison.
/// On success, clears pending auth material and sends Security Mode Command.
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

    // Retrieve stored XRES and verify — constant-time comparison
    let sec_ctx = world.security.get_mut(&ctx.entity_id)
        .ok_or(AttachFailReason::InternalError)?;

    let xres = sec_ctx.pending_xres;
    let verified = MilenageContext::verify_res(&xres, &ar.res);

    // Wipe XRES and RAND immediately regardless of outcome
    sec_ctx.clear_pending();

    if !verified {
        tracing::warn!(imsi = ctx.imsi, "Authentication failed: RES mismatch");
        world.set_auth_state(ctx.entity_id, AuthState::Failed(AuthFailReason::ResMismatch));
        ctx.state = AttachState::Failed(AttachFailReason::AuthResponseMismatch);
        return Err(AttachFailReason::AuthResponseMismatch);
    }

    // Auth succeeded — update state
    world.set_auth_state(ctx.entity_id, AuthState::Authenticated);
    ctx.state = AttachState::SecurityPending;
    tracing::info!(imsi = ctx.imsi, entity_id = ?ctx.entity_id, "UE authenticated");

    // Send Security Mode Command — select EEA2 (AES-CTR) + EIA2 (AES-CMAC)
    let sec_cmd_pdu = encode_sec_mode_cmd(
        NasEeaAlgorithm::Eea2,
        NasEiaAlgorithm::Eia2,
        0x07,               // NAS KSI
        &ctx.ue_capability,
    );

    // Update selected algorithms in security context
    let sec_ctx = world.security.get_mut(&ctx.entity_id)
        .ok_or(AttachFailReason::InternalError)?;
    sec_ctx.cipher_alg    = 2; // EEA2
    sec_ctx.integrity_alg = 2; // EIA2

    Ok(AttachStep { nas_pdu: sec_cmd_pdu, done: false })
}

// ── Security Mode Complete handler ────────────────────────────────────────────

/// Process a NAS Security Mode Complete.
///
/// Creates the PDN session, assigns an IP address, and sends Attach Accept.
pub fn handle_security_mode_complete(
    ctx:       &mut AttachContext,
    nas_pdu:   &Bytes,
    world:     &mut CoreWorld,
    ip_pool:   &mut IpPool,
) -> Result<AttachStep, AttachFailReason> {
    let decoded = decode_nas(nas_pdu).map_err(|_| AttachFailReason::NasDecodeError)?;
    if !matches!(decoded, NasPdu::SecurityModeComplete) {
        return Err(AttachFailReason::NasDecodeError);
    }

    ctx.state = AttachState::AcceptPending;

    // Allocate an IP address for the subscriber
    let ip = ip_pool.allocate(ctx.entity_id)
        .ok_or(AttachFailReason::InternalError)?;

    // Create PDN session in ECS
    let session = SessionState::new(ip, b"internet", 5);
    world.session.insert(ctx.entity_id, session);

    // Allocate GTP-U tunnel TEIDs (placeholder — real TEID exchange happens via S1AP)
    let tunnel = TunnelComponent::new(
        0x0000_0001, // dl_teid placeholder — replaced by InitialContextSetupResponse
        0x0000_0002, // ul_teid placeholder
        [0, 0, 0, 0], // enb_addr — set when eNodeB responds
    );
    world.tunnel.insert(ctx.entity_id, tunnel);

    tracing::info!(
        imsi = ctx.imsi,
        ip   = ?ip,
        "Session created, sending Attach Accept"
    );

    // Send Attach Accept with assigned IP
    let attach_accept_pdu = encode_attach_accept(
        0x01,           // EPS attach result: EPS only
        0x54,           // T3412 timer = 54 minutes
        &[],            // TAI list (empty for Phase 2)
        Some(ip),
        Some("internet"),
    );

    Ok(AttachStep { nas_pdu: attach_accept_pdu, done: false })
}

// ── Attach Complete handler ───────────────────────────────────────────────────

/// Process a NAS Attach Complete — subscriber is online.
pub fn handle_attach_complete(
    ctx:    &mut AttachContext,
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

// ── Simple IP pool ────────────────────────────────────────────────────────────

/// Minimal sequential IP address pool for Phase 2.
/// Allocates from 10.0.1.1 upward. Phase 3: IPAM integration.
pub struct IpPool {
    next:     u32,
    capacity: u32,
    assigned: std::collections::HashMap<EntityId, [u8; 4]>,
}

impl IpPool {
    /// Create a pool starting at `base_ip` with `capacity` addresses.
    /// Example: base=0x0A000101 (10.0.1.1), capacity=65534
    pub fn new(base_ip: [u8; 4], capacity: u32) -> Self {
        let base = u32::from_be_bytes(base_ip);
        Self { next: base, capacity, assigned: std::collections::HashMap::new() }
    }

    /// Allocate the next available IP for a subscriber entity.
    pub fn allocate(&mut self, entity: EntityId) -> Option<[u8; 4]> {
        if self.assigned.len() >= self.capacity as usize { return None; }
        let ip = self.next.to_be_bytes();
        self.next = self.next.wrapping_add(1);
        self.assigned.insert(entity, ip);
        Some(ip)
    }

    /// Release an IP address when a subscriber detaches.
    pub fn release(&mut self, entity: EntityId) {
        self.assigned.remove(&entity);
        // TODO: add to free list instead of just removing
    }
}

impl Default for IpPool {
    fn default() -> Self {
        Self::new([10, 0, 1, 1], 65_534)
    }
}
