# Phase 3 — User Plane

## Goal

Packets routed at XDP speed through GTP-U tunnels:
- Packets from internet → UPF → GTP-U → eNodeB → UE
- Packets from UE → eNodeB → GTP-U → UPF → internet

## XDP Architecture

```
[NIC] → [XDP hook (midn_gtp_xdp)] → [BPF map lookup]
                                          |
                                   hit: XDP_TX (forward)
                                   miss: XDP_PASS (userspace)
```

## BPF Maps Required

| Map | Key | Value | Purpose |
|---|---|---|---|
| teid_to_route | u32 (UL TEID) | RouteEntry | UL packet steering |
| ue_to_teid | [u8;4] (UE IP) | u32 (DL TEID) | DL packet steering |

## Linux Kernel Requirements

- Kernel ≥ 5.8 (BPF ring buffer support)
- XDP native mode requires driver support (ixgbe, i40e, mlx5, etc.)
- Fallback: XDP generic mode (slower but works on any driver)
