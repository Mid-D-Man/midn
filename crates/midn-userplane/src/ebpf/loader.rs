// crates/midn-userplane/src/ebpf/loader.rs
//! XDP program loader and kernel BPF map management.
//!
//! ## Activation matrix
//!
//! | Platform  | Feature | load_xdp result                           |
//! |-----------|---------|-------------------------------------------|
//! | non-Linux | any     | Err — platform not supported              |
//! | Linux     | —       | Err — rebuild with --features ebpf        |
//! | Linux     | ebpf    | Ok(BpfHandle) or Err (kernel/verifier)    |
//!
//! ## Phase 3.1 activation (UL — eNodeB-facing interface)
//!
//! ```bash
//! rustup toolchain install nightly --component rust-src
//! cargo install bpf-linker
//! cargo build -p midn-userplane --features ebpf
//! ```
//!
//! UPF startup sequence:
//! ```rust,ignore
//! let mut bpf = load_xdp("eth0").await?;
//! bpf.set_pdn_gw_config(&PdnGwConfig::new(gw_mac, nic_mac))?;
//! session_manager.set_bpf_handle(bpf);
//! ```
//!
//! ## Phase 3.2 activation (DL — PDN-facing interface)
//!
//! Both `midn_gtp_xdp` (UL) and `midn_gtp_dl_xdp` (DL) live in the same
//! compiled BPF object (`BPF_OBJECT`) — one `aya::Ebpf::load` loads both;
//! each is then individually pulled out by name and attached to its own
//! interface (which may be the same physical NIC or a different one,
//! depending on deployment topology):
//!
//! ```rust,ignore
//! let mut bpf = load_xdp("eth0").await?;                       // UL: eNodeB-facing
//! bpf.set_pdn_gw_config(&PdnGwConfig::new(gw_mac, nic_mac))?;
//!
//! bpf.attach_dl("eth1").await?;                                // DL: PDN-facing
//! bpf.set_dl_tunnel_config(&DlTunnelConfig::new(
//!     enb_dst_mac, enb_iface_mac, upf_transport_ip, enb_iface_ifindex,
//! ))?;
//!
//! session_manager.set_bpf_handle(bpf);
//! ```
//!
//! Until `set_dl_tunnel_config` is called, `DL_TUNNEL_CONFIG[0]` reads as
//! all-zero (`redirect_ifindex = 0`, not a valid ifindex), so the DL XDP
//! program falls through to `XDP_PASS` — same fail-safe convention as the
//! UL path's unconfigured `PDN_GW_CONFIG`.
//!
//! ## Rule 3 compliance
//!
//! BPF map entries are written in two phases, mirrored identically across
//! both the UL (`TEID_TO_ROUTE`, keyed by `ul_teid`) and DL
//! (`UE_IP_TO_ROUTE`, keyed by `ue_ip`) maps:
//!   - `CreateSession` → placeholder (`dl_teid = 0`, `enb_ip = [0;4]`):
//!     entry present; UL side passes on presence alone (dl_teid unused for
//!     UL forwarding). DL side additionally checks `dl_teid == 0` in-kernel
//!     before trusting `enb_ip`, since DL forwarding actually depends on
//!     both fields being real — see `gtp_dl_xdp.rs` module doc.
//!   - `UpdateBearer`  → real entry, atomic BPF_ANY overwrite.
//!     Fires from ICSRSP handler, before AttachAccept reaches UE via RRC.
//!     No UL or DL packet can race the map entry.

use crate::upf::xdp_types::{DlTunnelConfig, PdnGwConfig, XdpRouteEntry};

// ── Error type ────────────────────────────────────────────────────────────────

pub type LoadXdpError = Box<dyn std::error::Error + Send + Sync + 'static>;

// ── Embedded BPF object (Linux + ebpf feature only) ───────────────────────────

/// Compiled XDP program(s) embedded by aya-build.
/// Path: $OUT_DIR/midn_userplane_ebpf.bpf.o
/// (aya-build names by package name, hyphens replaced with underscores)
///
/// Contains both `midn_gtp_xdp` (UL) and `midn_gtp_dl_xdp` (DL) as separate
/// ELF sections within the one object — see main.rs doc comment.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
static BPF_OBJECT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/midn_userplane_ebpf.bpf.o"));

// ── BpfHandle ─────────────────────────────────────────────────────────────────

/// Owned handle to loaded XDP program(s) and their BPF maps.
///
/// Dropping detaches whichever XDP program(s) were attached from their NICs.
/// Keep alive for the lifetime of the UPF process.
#[cfg(target_os = "linux")]
pub struct BpfHandle {
    bpf: aya::Ebpf,
}

/// Non-Linux stub — zero-sized, never constructed (load_xdp always errors).
#[cfg(not(target_os = "linux"))]
pub struct BpfHandle;

// ── load_xdp ─────────────────────────────────────────────────────────────────

/// Load the BPF object and attach the UL (`midn_gtp_xdp`) program to a
/// network interface. Call `attach_dl` separately to additionally activate
/// the Phase 3.2 DL fast path.
///
/// Errors on non-Linux or when built without `--features ebpf`.
pub async fn load_xdp(iface: &str) -> Result<BpfHandle, LoadXdpError> {
    load_xdp_impl(iface).await
}

#[cfg(not(target_os = "linux"))]
async fn load_xdp_impl(_iface: &str) -> Result<BpfHandle, LoadXdpError> {
    Err("eBPF/XDP requires Linux — not supported on this platform".into())
}

#[cfg(all(target_os = "linux", not(feature = "ebpf")))]
async fn load_xdp_impl(_iface: &str) -> Result<BpfHandle, LoadXdpError> {
    Err("XDP fast path not compiled in — rebuild with `--features ebpf` \
         (requires bpf-linker + nightly with rust-src)"
        .into())
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
async fn load_xdp_impl(iface: &str) -> Result<BpfHandle, LoadXdpError> {
    let mut bpf = aya::Ebpf::load(BPF_OBJECT)?;

    // Kernel-side eBPF logging. Non-fatal — some kernels/configs lack the
    // ring-buffer logging module; we just lose eBPF printk output.
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        tracing::warn!("BPF logger init failed (non-fatal): {e}");
    }

    let prog: &mut aya::programs::Xdp = bpf
        .program_mut("midn_gtp_xdp")
        .ok_or("XDP program 'midn_gtp_xdp' not found in BPF object \
                (check function name in midn-userplane-ebpf/src/main.rs)")?
        .try_into()?;
    prog.load()?;
    prog.attach(iface, aya::programs::XdpFlags::default())?;

    tracing::info!(iface = iface, "GTP-U UL XDP program attached — fast path active");
    Ok(BpfHandle { bpf })
}

// ── BpfHandle methods (Linux only) ───────────────────────────────────────────

#[cfg(target_os = "linux")]
impl BpfHandle {
    // ── DL program attach (Phase 3.2) ────────────────────────────────────────

    /// Attach the DL (`midn_gtp_dl_xdp`) program to the PDN-facing interface.
    ///
    /// `midn_gtp_dl_xdp` is already loaded as bytecode as part of the same
    /// `BPF_OBJECT` that `load_xdp` loaded — this just pulls it out by name
    /// and attaches it, mirroring `load_xdp_impl`'s handling of the UL
    /// program. Call once at startup, before `set_dl_tunnel_config`.
    ///
    /// `iface` may be the same interface `load_xdp` attached to (single-NIC
    /// deployments) or a different one (dedicated PDN-facing NIC) — the two
    /// programs are independent BPF_PROG_TYPE_XDP attachments and don't
    /// interfere with each other either way.
    pub fn attach_dl(&mut self, iface: &str) -> Result<(), LoadXdpError> {
        let prog: &mut aya::programs::Xdp = self.bpf
            .program_mut("midn_gtp_dl_xdp")
            .ok_or("XDP program 'midn_gtp_dl_xdp' not found in BPF object \
                    (check function name in midn-userplane-ebpf/src/main.rs)")?
            .try_into()?;
        prog.load()?;
        prog.attach(iface, aya::programs::XdpFlags::default())?;

        tracing::info!(iface = iface, "GTP-U DL XDP program attached — fast path active");
        Ok(())
    }

    // ── TEID routing map (UL) ─────────────────────────────────────────────────

    /// Insert or overwrite a TEID route in the kernel `TEID_TO_ROUTE` map.
    /// `flags = 0` → BPF_ANY (insert or replace, atomic).
    ///
    /// Lifecycle:
    ///   CreateSession → placeholder (dl_teid = 0); XDP_PASS until bearer confirmed.
    ///   UpdateBearer  → real entry; XDP_TX active for this TEID.
    pub fn insert_teid(
        &mut self,
        ul_teid: u32,
        entry:   &XdpRouteEntry,
    ) -> Result<(), LoadXdpError> {
        use aya::maps::HashMap;
        let map_data = self.bpf
            .map_mut("TEID_TO_ROUTE")
            .ok_or("TEID_TO_ROUTE map not found in BPF object")?;
        let mut map: HashMap<_, u32, XdpRouteEntry> = map_data.try_into()?;
        map.insert(&ul_teid, entry, 0)?;
        tracing::debug!(ul_teid, dl_teid = entry.dl_teid, "BPF TEID_TO_ROUTE insert");
        Ok(())
    }

    /// Remove a TEID entry. After removal, UL packets fall through to XDP_PASS
    /// and are handled (or dropped) by the userspace GtpForwarder.
    pub fn remove_teid(&mut self, ul_teid: u32) -> Result<(), LoadXdpError> {
        use aya::maps::HashMap;
        let map_data = self.bpf
            .map_mut("TEID_TO_ROUTE")
            .ok_or("TEID_TO_ROUTE map not found in BPF object")?;
        let mut map: HashMap<_, u32, XdpRouteEntry> = map_data.try_into()?;
        map.remove(&ul_teid)?;
        tracing::debug!(ul_teid, "BPF TEID_TO_ROUTE remove");
        Ok(())
    }

    // ── UE IP routing map (DL — Phase 3.2) ───────────────────────────────────

    /// Insert or overwrite a UE-IP route in the kernel `UE_IP_TO_ROUTE` map.
    /// `flags = 0` → BPF_ANY (insert or replace, atomic).
    ///
    /// Same two-phase lifecycle as `insert_teid`, keyed by `ue_ip` instead of
    /// `ul_teid`:
    ///   CreateSession → placeholder (dl_teid = 0, enb_ip = [0;4]).
    ///   UpdateBearer  → real entry; DL XDP_REDIRECT active for this UE.
    ///
    /// `SessionManager` calls this alongside `insert_teid` (same session,
    /// same lifecycle event, two different map keys — same value shape).
    pub fn insert_ue_route(
        &mut self,
        ue_ip: [u8; 4],
        entry: &XdpRouteEntry,
    ) -> Result<(), LoadXdpError> {
        use aya::maps::HashMap;
        let map_data = self.bpf
            .map_mut("UE_IP_TO_ROUTE")
            .ok_or("UE_IP_TO_ROUTE map not found in BPF object")?;
        let mut map: HashMap<_, [u8; 4], XdpRouteEntry> = map_data.try_into()?;
        map.insert(&ue_ip, entry, 0)?;
        tracing::debug!(?ue_ip, dl_teid = entry.dl_teid, "BPF UE_IP_TO_ROUTE insert");
        Ok(())
    }

    /// Remove a UE-IP entry. After removal, DL packets for this UE fall
    /// through to `XDP_PASS` on the PDN-facing interface.
    pub fn remove_ue_route(&mut self, ue_ip: [u8; 4]) -> Result<(), LoadXdpError> {
        use aya::maps::HashMap;
        let map_data = self.bpf
            .map_mut("UE_IP_TO_ROUTE")
            .ok_or("UE_IP_TO_ROUTE map not found in BPF object")?;
        let mut map: HashMap<_, [u8; 4], XdpRouteEntry> = map_data.try_into()?;
        map.remove(&ue_ip)?;
        tracing::debug!(?ue_ip, "BPF UE_IP_TO_ROUTE remove");
        Ok(())
    }

    // ── PDN gateway config map (UL) ────────────────────────────────────────────

    /// Write Ethernet rewrite parameters into `PDN_GW_CONFIG[0]`.
    ///
    /// Call ONCE at startup after `load_xdp` succeeds, BEFORE any sessions
    /// are created. Until called, the XDP program reads all-zero MACs and
    /// falls through to XDP_PASS.
    ///
    /// How to get the values:
    /// ```bash
    /// # gw_mac — next-hop router toward internet
    /// ip neigh show $(ip route show default | awk '/default/ {print $3}')
    /// # nic_mac — UPF interface
    /// ip link show eth0 | awk '/ether/ {print $2}'
    /// ```
    pub fn set_pdn_gw_config(&mut self, config: &PdnGwConfig) -> Result<(), LoadXdpError> {
        use aya::maps::Array;
        let map_data = self.bpf
            .map_mut("PDN_GW_CONFIG")
            .ok_or("PDN_GW_CONFIG map not found in BPF object")?;
        let mut map: Array<_, PdnGwConfig> = map_data.try_into()?;
        map.set(0, config, 0)?;
        tracing::info!(
            gw_mac  = ?config.gw_mac,
            nic_mac = ?config.nic_mac,
            "PDN gateway config written to BPF PDN_GW_CONFIG[0]"
        );
        Ok(())
    }

    // ── DL tunnel config map (Phase 3.2) ──────────────────────────────────────

    /// Write Ethernet/IP/redirect parameters into `DL_TUNNEL_CONFIG[0]`.
    ///
    /// Call ONCE at startup after `attach_dl` succeeds, BEFORE any sessions
    /// are created. Until called, the DL XDP program reads
    /// `redirect_ifindex = 0` (not a valid ifindex) and falls through to
    /// XDP_PASS.
    ///
    /// How to get the values: see `DlTunnelConfig` doc comment in
    /// `xdp_types.rs`.
    pub fn set_dl_tunnel_config(&mut self, config: &DlTunnelConfig) -> Result<(), LoadXdpError> {
        use aya::maps::Array;
        let map_data = self.bpf
            .map_mut("DL_TUNNEL_CONFIG")
            .ok_or("DL_TUNNEL_CONFIG map not found in BPF object")?;
        let mut map: Array<_, DlTunnelConfig> = map_data.try_into()?;
        map.set(0, config, 0)?;
        tracing::info!(
            eth_dst_mac      = ?config.eth_dst_mac,
            eth_src_mac      = ?config.eth_src_mac,
            upf_ip           = ?config.upf_ip,
            redirect_ifindex = config.redirect_ifindex,
            "DL tunnel config written to BPF DL_TUNNEL_CONFIG[0]"
        );
        Ok(())
    }
    }
