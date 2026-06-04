# Platform Optimization Rules

> Inherits all rules from Mid Engine `docs/platform-optimization.md`.
> Telecom-specific additions below.

## Rule 0 (Inherited)

An optimization that cannot be benchmarked does not exist.
`[RELEASE]` label required on all performance claims.
Debug-mode numbers are not performance numbers.

## Rule 1 — Constant-Time is Non-Negotiable

Any comparison involving `pending_xres`, MAC values, or session keys
MUST use `subtle::ConstantTimeEq`. A timing oracle on the auth path
enables a MITM authentication attack.

```rust
// WRONG — timing leaks whether the guess is close:
if xres == res { ... }

// CORRECT — constant time regardless of input values:
use subtle::ConstantTimeEq;
if xres.ct_eq(&res).into() { ... }
```

**Corollary:** do NOT tighten the `verify_res_constant_time` bench gate below
15 ns. The 12-15 ns cost is the point — it means the compiler has not
eliminated the constant-time property. A result of < 5 ns would indicate
the compiler optimized away the safety guarantee.

## Rule 2 — Zero-Copy on the Packet Path

GTP-U parsing MUST NOT allocate. `GtpuHeader::parse` and `GtpuParser::parse`
return slices into the caller's buffer. The XDP program cannot allocate.

## Rule 3 — BPF Map Updates Before AttachAccept

Install the BPF routing map entry BEFORE sending AttachAccept.
A packet arriving before the map entry exists falls to XDP_PASS
(userspace), which is slower but correct.

---

## Build #5 Baselines — Official (rustc 1.95.0, ubuntu-latest, 2026-05-26)

Phase 1 and Phase 2 complete. First build with real Milenage numbers pending (Build #6).

### midn-auth

| Benchmark | Mean [RELEASE] | Gate | Status |
|---|---|---|---|
| `milenage_generate_vector` | **pending Build #6** | < 10 µs | real bench active as of Build #6 |
| `milenage_core_fixed_rand` | **pending Build #6** | < 10 µs | new bench — pure AES cost, no getrandom |
| `verify_res_constant_time` | 10.370 ns | < 25 ns | ✅ |
| `generate_rand_os_csprng` | 36.356 ns | < 100 ns | ✅ |

**Notes:**
- `milenage_generate_vector` stub removed in Build #6. Expected ~1.0–1.1 µs on AES-NI.
- `milenage_core_fixed_rand` is a new bench isolating pure crypto from getrandom.
  The difference between these two benches should track the getrandom baseline (~36 ns).
- `verify_res` at 10.4 ns is correct constant-time behavior. Do not "optimize" it.

### midn-proto

| Benchmark | Mean [RELEASE] | Gate | Status |
|---|---|---|---|
| `gtpu_parser_gpdu_minimal` | 1.736 ns | < 500 ns | ✅ (~288× under gate) |
| `gtpu_parser_gpdu_with_seq` | 1.738 ns | < 500 ns | ✅ |
| `gtpu_header_serialize_round_trip` | 1.767 ns | < 500 ns | ✅ |
| `nas_encode_auth_request` | 102.69 ns | < 500 ns | ✅ |
| `nas_decode_auth_request` | 15.571 ns | < 500 ns | ✅ |
| `nas_imsi_bcd_encode` | 22.311 ns | < 100 ns | ✅ |
| `nas_imsi_bcd_decode` | 24.409 ns | < 100 ns | ✅ |
| `nas_auth_round_trip` | 126.32 ns | < 1000 ns | ✅ |

### midn-core

| Benchmark | Mean [RELEASE] | Gate | Status |
|---|---|---|---|
| `ecs_spawn` | 770.45 ps | < 1 µs | ✅ (1298× headroom) |
| `ecs_spawn_with_all_components` | 940.55 ns | < 5 µs | ✅ |
| `ecs_despawn_zeroize` | 182.44 ns | < 5 µs | ✅ |
| `ecs_lookup_auth_state` | 12.929 ns | < 100 ns | ✅ |
| `registry_lookup_hit` | 14.176 ns | < 100 ns | ✅ |
| `hss_provision_subscriber` | 94.924 ns | < 1000 ns | ✅ |

### midn-userplane

| Benchmark | Mean [RELEASE] | Gate | Status |
|---|---|---|---|
| `routing_table_lookup_ul` | 12.705 ns | < 50 ns | ✅ |
| `routing_table_lookup_dl` | 13.725 ns | < 50 ns | ✅ |
| `tunnel_create` | 237.64 ns | < 1 µs | ✅ |
| `tunnel_destroy` | 69.353 ns | < 500 ns | ✅ |

---

## Optimization Priority Queue (Post Build #5)

**CLOSED — GTP-U parser** (~288× under gate, LLVM auto-vectorized, no action needed)

**CLOSED — verify_res** (correct at 10.4 ns, constant-time working as intended)

**CLOSED — Phase 1 Milenage** (generate_vector implemented, Build #52 validates all test sets 1-3)

Build #6 will establish the real `milenage_generate_vector` baseline.
If it comes in above 5 µs, investigate AES-NI feature flag in Cargo.toml.
If it comes in above 10 µs (gate breach), profile with perf/flamegraph.

**Phase 3 — GTP-U UDP socket (active)**

The userspace routing table benchmarks at 12 ns/lookup. Next step is
wiring it to a real Tokio `UdpSocket` on port 2152. The full
receive-parse-lookup-forward path should target < 5 µs userspace,
then < 200 ns once XDP takes over the fast path.

**Phase 3 — eBPF/XDP routing (pending GTP-U socket)**

XDP packet decision target: < 200 ns. Baseline to be established
once the userspace path is working and the BPF map is populated.
