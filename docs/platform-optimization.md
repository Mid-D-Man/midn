# Midn Core — Platform Optimization Rules

> Inherits all rules from Mid Engine platform-optimization.md.
> Additional telecom-specific rules below.

## Rule 0 (Inherited)

An optimization that cannot be benchmarked does not exist.
All Criterion numbers must include build mode labels.

## Telecom Rule 1 — Constant-Time is Non-Negotiable

Any comparison involving authentication material (RES, MAC, keys)
MUST use `subtle::ConstantTimeEq`. A timing oracle on the auth path
is a real attack surface (MITM on authentication challenge).

## Telecom Rule 2 — Zero-Copy on the Hot Path

The GTP-U parser must never allocate. The XDP program never can.
All packet processing from NIC to routing decision must be a series
of pointer arithmetic operations on the original packet buffer.

## Telecom Rule 3 — BPF Map Updates Are Atomic

When a subscriber attaches, the control plane (midn-core) must
install the routing entry in the BPF map BEFORE signaling Attach
Accept. If a packet arrives before the map entry exists, it falls
to userspace (XDP_PASS) and is handled correctly but slowly.

## Performance Baseline Targets

| Operation | Target | Measurement Method |
|---|---|---|
| Milenage AKA | < 10 µs | Criterion bench |
| GTP-U header parse | < 500 ns | Criterion bench |
| ECS subscriber spawn | < 1 µs | Criterion bench |
| BPF map update | < 1 µs | perf stat |
| XDP packet decision | < 200 ns | packet timestamping |
