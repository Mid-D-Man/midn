// crates/midn-userplane/src/upf/forwarder.rs
//! GTP-U UDP forwarder — userspace data plane.
//!
//! Binds a Tokio UdpSocket on port 2152 and drives both directions:
//!
//! ## UL path (UE → Internet)
//!   1. recv_from() on port 2152
//!   2. GtpuParser::parse → TEID + inner IP
//!   3. routing.lookup_ul(teid) → RouteEntry
//!   4. Emit UlPacket on ul_tx channel to PDN egress
//!
//! ## DL path (Internet → UE)
//!   1. Receive DlPacket on dl_rx channel from PDN ingress
//!   2. routing.lookup_dl(ue_ip) → RouteEntry
//!   3. Prepend GTP-U header with dl_teid
//!   4. send_to(enb_addr:enb_port)
//!
//! ## Phase 3 (XDP) handoff
//!
//! When the XDP program is loaded, the UL hot path moves to the kernel.
//! This forwarder then handles only:
//!   - Packets that miss the BPF map (XDP_PASS fallback / session setup race)
//!   - Control plane packets (Echo Request/Response)
//!
//! ## Concurrency model
//!
//! `run()` spawns two Tokio tasks (UL recv loop + DL send loop) and
//! races them via `tokio::select!`. The routing table is shared via
//! `Arc<std::sync::Mutex<RoutingTable>>`. The mutex is held only for the
//! duration of a single O(1) lookup — never across an `.await` point.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use midn_proto::gtp::header::GtpuHeader;
use midn_proto::gtp::parser::GtpuParser;

use crate::upf::routing::{RouteEntry, RoutingTable};

/// Standard GTP-U UDP port.
pub const GTP_PORT: u16 = 2152;

// ── Packet types ──────────────────────────────────────────────────────────────

/// A decapsulated uplink inner-IP packet ready for PDN forwarding.
#[derive(Debug)]
pub struct UlPacket {
    /// Inner IP packet bytes (copied from the receive buffer).
    pub inner_ip: Bytes,
    /// Routing entry resolved from the UL TEID — identifies the subscriber.
    pub route:    RouteEntry,
}

/// A downlink inner-IP packet to be GTP-U encapsulated and sent to the eNodeB.
#[derive(Debug)]
pub struct DlPacket {
    /// Inner IP packet bytes destined for a UE.
    pub inner_ip: Bytes,
    /// UE IPv4 address — used for `lookup_dl` to find the route.
    pub ue_ip:    [u8; 4],
}

// ── ForwardAction ─────────────────────────────────────────────────────────────

/// Decision produced by `GtpForwarder::process_uplink` for one received datagram.
#[derive(Debug)]
pub enum ForwardAction {
    /// G-PDU for a known subscriber — forward inner IP to PDN.
    ForwardUl(UlPacket),
    /// Echo Request — send an Echo Response back to the eNodeB.
    EchoRequest { src: SocketAddr, teid: u32 },
    /// Other GTP-U control message — log and ignore for now.
    ControlMessage { msg_type: u8 },
    /// Packet too short / malformed — discard silently.
    Discard,
    /// G-PDU for an unknown TEID — session may not exist or map race.
    UnknownSession { teid: u32 },
}

// ── GtpForwarder ──────────────────────────────────────────────────────────────

/// GTP-U UDP forwarder. Owns the port 2152 socket for one UPF instance.
///
/// ## Usage
///
/// ```rust,ignore
/// let (ul_tx, mut ul_rx) = mpsc::channel(256);
/// let routing = Arc::new(Mutex::new(RoutingTable::new()));
/// let (fwd, dl_tx) = GtpForwarder::bind(Arc::clone(&routing), ul_tx).await?;
///
/// tokio::spawn(fwd.run());
///
/// // Feed DL packets:
/// dl_tx.send(DlPacket { inner_ip: ..., ue_ip: [10,0,0,1] }).await?;
///
/// // Consume UL packets:
/// while let Some(pkt) = ul_rx.recv().await { /* route to internet */ }
/// ```
pub struct GtpForwarder {
    socket:  Arc<UdpSocket>,
    routing: Arc<Mutex<RoutingTable>>,
    ul_tx:   mpsc::Sender<UlPacket>,
    dl_tx:   mpsc::Sender<DlPacket>,
    dl_rx:   Option<mpsc::Receiver<DlPacket>>,
}

impl GtpForwarder {
    /// Bind to `0.0.0.0:2152`.
    pub async fn bind(
        routing: Arc<Mutex<RoutingTable>>,
        ul_tx:   mpsc::Sender<UlPacket>,
    ) -> std::io::Result<(Self, mpsc::Sender<DlPacket>)> {
        Self::bind_addr(&format!("0.0.0.0:{GTP_PORT}"), routing, ul_tx).await
    }

    /// Bind to an explicit address — useful for tests on ephemeral ports.
    pub async fn bind_addr(
        addr:    &str,
        routing: Arc<Mutex<RoutingTable>>,
        ul_tx:   mpsc::Sender<UlPacket>,
    ) -> std::io::Result<(Self, mpsc::Sender<DlPacket>)> {
        let socket          = Arc::new(UdpSocket::bind(addr).await?);
        let (dl_tx, dl_rx)  = mpsc::channel(1024);
        let fwd = Self {
            socket,
            routing,
            ul_tx,
            dl_tx: dl_tx.clone(),
            dl_rx: Some(dl_rx),
        };
        Ok((fwd, dl_tx))
    }

    /// Return a sender for injecting downlink packets from outside.
    pub fn dl_sender(&self) -> mpsc::Sender<DlPacket> { self.dl_tx.clone() }

    /// Local address the socket is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Run the forwarder until either the UL or DL task exits.
    ///
    /// Consumes `self`. Call exactly once.
    pub async fn run(mut self) {
        let dl_rx      = self.dl_rx.take().expect("GtpForwarder::run called more than once");
        let socket_ul  = Arc::clone(&self.socket);
        let socket_dl  = Arc::clone(&self.socket);
        let routing_ul = Arc::clone(&self.routing);
        let routing_dl = Arc::clone(&self.routing);
        let ul_tx      = self.ul_tx.clone();

        // ── UL receive loop ───────────────────────────────────────────────────
        let ul_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let (len, src) = match socket_ul.recv_from(&mut buf).await {
                    Ok(r)  => r,
                    Err(e) => {
                        tracing::error!(error = %e, "GTP-U recv_from error");
                        break;
                    }
                };

                // Lock for the duration of a single lookup — no await while held.
                let action = {
                    let rt = routing_ul.lock().unwrap();
                    GtpForwarder::process_uplink(&buf[..len], &rt, src)
                };

                match action {
                    ForwardAction::ForwardUl(pkt) => {
                        if ul_tx.send(pkt).await.is_err() {
                            tracing::warn!("UL channel closed — stopping UL loop");
                            break;
                        }
                    }
                    ForwardAction::EchoRequest { src, teid } => {
                        tracing::debug!(teid, %src, "GTP-U Echo Request");
                        let rsp = GtpForwarder::build_echo_response(teid);
                        let _   = socket_ul.send_to(&rsp, src).await;
                    }
                    ForwardAction::UnknownSession { teid } => {
                        tracing::warn!(teid, "GTP-U packet for unknown TEID — dropped");
                    }
                    ForwardAction::ControlMessage { msg_type } => {
                        tracing::debug!(msg_type, "GTP-U control message — not handled");
                    }
                    ForwardAction::Discard => {}
                }
            }
        });

        // ── DL send loop ──────────────────────────────────────────────────────
        let dl_handle = tokio::spawn(async move {
            let mut dl_rx = dl_rx;
            while let Some(pkt) = dl_rx.recv().await {
                let result = {
                    let rt = routing_dl.lock().unwrap();
                    GtpForwarder::encapsulate_downlink(&pkt, &rt)
                };
                match result {
                    Some((dgram, dst)) => {
                        if let Err(e) = socket_dl.send_to(&dgram, dst).await {
                            tracing::error!(error = %e, "GTP-U DL send error");
                        }
                    }
                    None => {
                        tracing::warn!(ue_ip = ?pkt.ue_ip, "no DL route — packet dropped");
                    }
                }
            }
        });

        tokio::select! {
            _ = ul_handle => tracing::warn!("GTP-U UL task exited"),
            _ = dl_handle => tracing::warn!("GTP-U DL task exited"),
        }
    }

    // ── Stateless processing — testable without a live socket ─────────────────

    /// Classify and process one incoming UDP datagram.
    ///
    /// Stateless: takes a buffer and a routing table reference.
    /// All allocations are confined to the `ForwardUl` branch
    /// (`Bytes::copy_from_slice` — one memcpy of the inner IP payload).
    pub fn process_uplink(buf: &[u8], routing: &RoutingTable, src: SocketAddr) -> ForwardAction {
        let pkt = match GtpuParser::parse(buf) {
            Some(p) => p,
            None    => return ForwardAction::Discard,
        };

        if pkt.header.msg_type == GtpuHeader::MSG_ECHO_REQ {
            return ForwardAction::EchoRequest { src, teid: pkt.header.teid };
        }

        if !pkt.header.is_gpdu() {
            return ForwardAction::ControlMessage { msg_type: pkt.header.msg_type };
        }

        match routing.lookup_ul(pkt.header.teid) {
            Some(&route) => ForwardAction::ForwardUl(UlPacket {
                inner_ip: Bytes::copy_from_slice(pkt.payload),
                route,
            }),
            None => ForwardAction::UnknownSession { teid: pkt.header.teid },
        }
    }

    /// Encapsulate a downlink inner-IP packet in a GTP-U header.
    ///
    /// Returns `(gtp_u_datagram, eNB_SocketAddr)` or `None` if no route found.
    /// Stateless — testable without a live socket.
    pub fn encapsulate_downlink(
        pkt:     &DlPacket,
        routing: &RoutingTable,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        let route = routing.lookup_dl(&pkt.ue_ip)?;
        let inner = pkt.inner_ip.as_ref();
        let hdr   = GtpuHeader::new_gpdu(route.dl_teid, inner.len() as u16);
        let mut dgram = Vec::with_capacity(GtpuHeader::SIZE + inner.len());
        dgram.extend_from_slice(&hdr.to_bytes());
        dgram.extend_from_slice(inner);
        let dst = SocketAddr::from((route.enb_addr, route.enb_port));
        Some((dgram, dst))
    }

    /// Build a minimal GTP-U Echo Response (12 bytes: 8-byte header + 4 optional fields).
    pub fn build_echo_response(teid: u32) -> [u8; 12] {
        let t = teid.to_be_bytes();
        // flags=0x22 (version=1, PT=1, S=1), msg_type=Echo RSP, length=4
        [
            0x22, GtpuHeader::MSG_ECHO_RSP, 0x00, 0x04,
            t[0], t[1], t[2], t[3],
            0x00, 0x00, // sequence = 0
            0x00,       // N-PDU = 0
            0x00,       // next ext hdr type = 0 (none)
        ]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::upf::routing::RouteEntry;

    fn src() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 2152)
    }

    fn make_gpdu(teid: u32, payload: &[u8]) -> Vec<u8> {
        let hdr = GtpuHeader::new_gpdu(teid, payload.len() as u16);
        let mut buf = Vec::with_capacity(8 + payload.len());
        buf.extend_from_slice(&hdr.to_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    fn make_route(ue_ip: [u8; 4], dl_teid: u32) -> RouteEntry {
        RouteEntry::new(ue_ip, dl_teid, [192, 168, 1, 100], 9)
    }

    // ── process_uplink ────────────────────────────────────────────────────────

    #[test]
    fn uplink_known_teid_forwarded() {
        let mut rt = RoutingTable::new();
        rt.install(0x1111_0001, make_route([10, 0, 0, 1], 0xDDDD_0001));

        let buf = make_gpdu(0x1111_0001, &[0x45u8, 0x00, 0x00, 0x14]);

        match GtpForwarder::process_uplink(&buf, &rt, src()) {
            ForwardAction::ForwardUl(pkt) => {
                assert_eq!(pkt.inner_ip.as_ref(), &[0x45u8, 0x00, 0x00, 0x14]);
                assert_eq!(pkt.route.dl_teid, 0xDDDD_0001);
            }
            other => panic!("expected ForwardUl, got {other:?}"),
        }
    }

    #[test]
    fn uplink_unknown_teid_reported() {
        let rt = RoutingTable::new();
        let buf = make_gpdu(0xDEAD_BEEF, &[0x45u8; 20]);
        match GtpForwarder::process_uplink(&buf, &rt, src()) {
            ForwardAction::UnknownSession { teid } => assert_eq!(teid, 0xDEAD_BEEF),
            other => panic!("expected UnknownSession, got {other:?}"),
        }
    }

    #[test]
    fn uplink_echo_request_detected() {
        let rt  = RoutingTable::new();
        // Echo Request: flags=0x22 (S set), msg_type=0x01, length=4, TEID=0 + optional fields
        let buf = [0x22u8, 0x01, 0x00, 0x04,
                   0x00,   0x00, 0x00, 0x00,
                   0x00,   0x00, 0x00, 0x00];
        match GtpForwarder::process_uplink(&buf, &rt, src()) {
            ForwardAction::EchoRequest { teid, .. } => assert_eq!(teid, 0),
            other => panic!("expected EchoRequest, got {other:?}"),
        }
    }

    #[test]
    fn uplink_too_short_discarded() {
        let rt = RoutingTable::new();
        match GtpForwarder::process_uplink(&[0x30, 0xFF], &rt, src()) {
            ForwardAction::Discard => {}
            other => panic!("expected Discard, got {other:?}"),
        }
    }

    #[test]
    fn uplink_non_gpdu_control_message() {
        let rt  = RoutingTable::new();
        // Error Indication (0x1A) — G-PDU flag not set in msg_type
        let buf = [0x20u8, 0x1A, 0x00, 0x04,
                   0x00,   0x00, 0x00, 0x00];
        match GtpForwarder::process_uplink(&buf, &rt, src()) {
            ForwardAction::ControlMessage { msg_type } => assert_eq!(msg_type, 0x1A),
            other => panic!("expected ControlMessage, got {other:?}"),
        }
    }

    // ── encapsulate_downlink ──────────────────────────────────────────────────

    #[test]
    fn downlink_known_ue_encapsulated() {
        let mut rt = RoutingTable::new();
        rt.install(0x2222_0001, make_route([10, 0, 0, 2], 0xEEEE_0001));

        let pkt = DlPacket {
            inner_ip: Bytes::from_static(&[0x45, 0x00, 0x00, 0x14]),
            ue_ip:    [10, 0, 0, 2],
        };

        let (dgram, dst) = GtpForwarder::encapsulate_downlink(&pkt, &rt).unwrap();
        // 8-byte GTP-U header + 4-byte inner IP = 12
        assert_eq!(dgram.len(), 12);
        let teid = u32::from_be_bytes([dgram[4], dgram[5], dgram[6], dgram[7]]);
        assert_eq!(teid, 0xEEEE_0001);
        assert_eq!(dst.port(), 2152);
        // Inner IP preserved
        assert_eq!(&dgram[8..], &[0x45, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn downlink_unknown_ue_returns_none() {
        let rt  = RoutingTable::new();
        let pkt = DlPacket {
            inner_ip: Bytes::from_static(&[0x45u8; 20]),
            ue_ip:    [10, 0, 0, 99],
        };
        assert!(GtpForwarder::encapsulate_downlink(&pkt, &rt).is_none());
    }

    // ── Echo Response ─────────────────────────────────────────────────────────

    #[test]
    fn echo_response_correct_type_and_teid() {
        let rsp  = GtpForwarder::build_echo_response(0xABCD_1234);
        assert_eq!(rsp[1], GtpuHeader::MSG_ECHO_RSP, "wrong msg_type");
        let teid = u32::from_be_bytes([rsp[4], rsp[5], rsp[6], rsp[7]]);
        assert_eq!(teid, 0xABCD_1234);
    }

    // ── Integration: bind socket + send/receive ───────────────────────────────

    #[tokio::test]
    async fn socket_ul_receive_and_forward() {
        let (ul_tx, mut ul_rx) = mpsc::channel(16);
        let routing = Arc::new(Mutex::new(RoutingTable::new()));

        {
            let mut rt = routing.lock().unwrap();
            rt.install(0xAAAA_0001, make_route([10, 0, 0, 1], 0xCCCC_0001));
        }

        let (fwd, _dl_tx) = GtpForwarder::bind_addr(
            "127.0.0.1:0", Arc::clone(&routing), ul_tx,
        ).await.unwrap();

        let local = fwd.local_addr().unwrap();
        tokio::spawn(fwd.run());

        // Mock eNB sends a G-PDU
        let sender    = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let inner_ip  = [0x45u8, 0x00, 0x00, 0x14,
                          0x00, 0x01, 0x40, 0x00, 0x40, 0x11,
                          0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
                          0x08, 0x08, 0x08, 0x08];
        let pkt = make_gpdu(0xAAAA_0001, &inner_ip);
        sender.send_to(&pkt, local).await.unwrap();

        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ul_rx.recv(),
        )
        .await
        .expect("timeout waiting for UL packet")
        .expect("channel closed");

        assert_eq!(received.inner_ip.as_ref(), &inner_ip);
        assert_eq!(received.route.dl_teid, 0xCCCC_0001);
    }

    #[tokio::test]
    async fn socket_dl_encapsulate_and_send() {
        let (ul_tx, _ul_rx) = mpsc::channel(16);
        let routing = Arc::new(Mutex::new(RoutingTable::new()));
        {
            let mut rt = routing.lock().unwrap();
            rt.install(0xBBBB_0001, make_route([10, 0, 0, 5], 0xFFFF_0001));
        }

        let (fwd, dl_tx) = GtpForwarder::bind_addr(
            "127.0.0.1:0", Arc::clone(&routing), ul_tx,
        ).await.unwrap();

        // Receiver simulating eNB on an ephemeral port
        let enb_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let enb_addr = enb_sock.local_addr().unwrap();

        // Update route to point at mock eNB address
        {
            let mut rt = routing.lock().unwrap();
            rt.remove(0xBBBB_0001);
            let entry = RouteEntry::new(
                [10, 0, 0, 5], 0xFFFF_0001,
                [127, 0, 0, 1], 9,
            );
            // Override port to mock eNB port
            let mut e2 = entry;
            e2.enb_port = enb_addr.port();
            rt.install(0xBBBB_0001, e2);
        }

        tokio::spawn(fwd.run());

        let inner_ip = [0x45u8, 0x00, 0x00, 0x14, 0xAB, 0xCD,
                         0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
                         0x08, 0x08, 0x08, 0x08, 0x0A, 0x00, 0x00, 0x05];

        dl_tx.send(DlPacket {
            inner_ip: Bytes::copy_from_slice(&inner_ip),
            ue_ip:    [10, 0, 0, 5],
        }).await.unwrap();

        let mut buf = vec![0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            enb_sock.recv_from(&mut buf),
        )
        .await
        .expect("timeout waiting for DL packet")
        .unwrap();

        // GTP-U header (8) + inner IP (20) = 28
        assert_eq!(len, 28);
        let teid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(teid, 0xFFFF_0001);
        assert_eq!(&buf[8..len], &inner_ip);
    }
}
