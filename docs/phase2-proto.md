# Phase 2 — Protocol Stack

## Goal

Full LTE attach procedure simulated end-to-end without real hardware:
- Mock eNodeB (sends S1AP messages)
- MME processes attach, authenticates via midn-auth
- ECS world tracks subscriber state through all steps

## LTE Attach Sequence

```
UE → eNodeB: RRC Connection + Attach Request (NAS)
eNodeB → MME: S1AP InitialUeMessage (contains NAS PDU)
MME → HSS:   Authentication Info Request
HSS → MME:   Auth Vectors (RAND, AUTN, XRES, CK, IK)
MME → UE:    Authentication Request (NAS)
UE → MME:    Authentication Response (RES)
MME: verify RES == XRES (constant-time)
MME → UE:    Security Mode Command (NAS)
UE → MME:    Security Mode Complete
MME → UE:    Attach Accept + IP address
UE → MME:    Attach Complete
```

## Performance Target

Full attach: < 50 ms (network latency dominates, not CPU)
ECS subscriber creation: < 1 µs
