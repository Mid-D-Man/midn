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
15 ns. The 12–15 ns cost is the point — the compiler has not eliminated the
constant-time property. A result of < 5 ns means the safety guarantee was
optimized away.

## Rule 2 — Zero-Copy on the Packet Path

GTP-U parsing MUST NOT allocate. `GtpuHeader::parse` and `GtpuParser::parse`
return slices into the caller's buffer. `GtpForwarder::process_uplink` is
stateless and allocates only on the `ForwardUl` branch (one `Bytes::copy_from_slice`
of the inner IP payload). The XDP program (Phase 3) cannot allocate at all.

## Rule 3 — BPF Map Updates Before AttachAccept

Install the BPF routing map entry BEFORE sending AttachAccept.
A packet arriving before the map entry exists falls to XDP_PASS
(userspace), which is slower but correct.

## Rule 4 — Mutex Never Held Across `.await`

`Arc<Mutex<RoutingTable>>` is shared between `SessionManager` and `GtpForwarder`.
The lock is acquired only for a single O(1) lookup or install and released
before any `.await` point. Holding the lock across an async boundary would
stall the forwarder's recv loop.

---

## Build #7 Baselines — Official (rustc 1.96.0, ubuntu-latest, 2026-06-04)

All phases complete through Phase 3 userspace path. XDP fast path pending.

### midn-auth

| Benchmark | Mean [RELEASE] | Gate | Status |
|---|---|---|---|
| `milenage_generate_vector` | **514.32 ns** | < 10 µs | ✅ ~19× under gate |
| `milenage_core_fixed_rand` | **510.30 ns** | < 10 µs | ✅ ~19× under gate |
| `verify_res_constant_time` | **14.465 ns** | < 25 ns | ✅ intentional ~14 ns |
| `generate_rand_os_csprng`  | **45.128 ns** | < 100 ns | ✅ |

**Note:** `milenage_generate_vector` came in at 514 ns — roughly 2× faster than
the 1 µs estimate. The 4-5 ns difference between `generate_vector` and
`milenage_core_fixed_rand` (510 vs 514 ns) is the getrandom(2) overhead,
which is now just ~4 ns on this runner (likely batched RDRAND, not a full
syscall). The ~36–45 ns `generate_rand_os_csprng` bench measures a different
call path — confirm with `strace` if the discrepancy matters.

### midn-proto

| Benchmark | Mean [RELEASE] | Gate | Status |
|---|---|---|---|
| `gtpu_parser_gpdu_minimal`        | 1.76 ns  | < 500 ns | ✅ 283× under gate |
| `gtpu_parser_gpdu_with_seq`       | 2.00 ns  | < 500 ns | ✅ |
| `gtpu_header_serialize_round_trip`| 3.17 ns  | < 500 ns | ✅ |
| `nas_encode_auth_request`         | 82.98 ns | < 500 ns | ✅ |
| `nas_decode_auth_request`         | 22.52 ns | < 500 ns | ✅ |
| `nas_encode_attach_request`       | 80.57 ns | < 1 µs   | ✅ |
| `nas_decode_attach_request`       | 64.72 ns | < 1 µs   | ✅ |
| `nas_encode_attach_accept`        | 116.24 ns| < 1 µs   | ✅ |
| `nas_decode_attach_accept`        | 45.03 ns | < 1 µs   | ✅ |
| `nas_auth_round_trip`             | 139.42 ns| < 1 µs   | ✅ |
| `nas_imsi_bcd_encode`             | 27.76 ns | < 100 ns | ✅ |
| `nas_imsi_bcd_decode`             | 29.53 ns | < 100 ns | ✅ |

### midn-core

| Benchmark | Mean [RELEASE] | Gate | Status |
|---|---|---|---|
| `ecs_spawn`                        | 1.07 ns  | < 1 µs  | ✅ 935× under gate |
| `ecs_spawn_with_all_components`    | 397.06 ns| < 5 µs  | ✅ |
| `ecs_despawn_with_zeroize`         | 208.07 ns| < 5 µs  | ✅ |
| `ecs_lookup_auth_state`            | 14.11 ns | < 100 ns| ✅ |
| `registry_lookup_hit`              | 17.65 ns | < 100 ns| ✅ |
| `registry_lookup_miss`             | 17.52 ns | < 100 ns| ✅ |
| `registry_register`                | 152.43 ns| < 500 ns| ✅ |
| `hss_provision_subscriber`         | 90.54 ns | < 1 µs  | ✅ |
| `hss_lookup_hit`                   | 14.56 ns | < 50 ns | ✅ |
| `hss_lookup_miss`                  | 14.02 ns | < 50 ns | ✅ |

`ecs_authenticated_count_10k` = 11.010 µs (informational — linear scan of
10k entities; SoA Vec upgrade in Phase 2 extension would reduce to ~1 µs).

### midn-userplane

| Benchmark | Mean [RELEASE] | Gate | Status |
|---|---|---|---|
| `routing_table_install`     | 328.72 ns | < 500 ns | ✅ |
| `routing_table_lookup_ul`   | 13.58 ns  | < 50 ns  | ✅ |
| `routing_table_lookup_dl`   | 14.49 ns  | < 50 ns  | ✅ |
| `routing_table_lookup_ul_miss` | 13.71 ns | < 50 ns | ✅ |
| `routing_table_remove`      | 75.78 ns  | < 500 ns | ✅ |
| `tunnel_create`             | 219.92 ns | < 1 µs   | ✅ |
| `tunnel_destroy`            | 80.32 ns  | < 500 ns | ✅ |

---

## Build #5 Baselines — Historical (rustc 1.95.0, 2026-05-26)

| Benchmark | Build #5 | Build #7 | Delta |
|---|---|---|---|
| `milenage_generate_vector` | stub (~600 ps) | 514.32 ns | first real number |
| `verify_res_constant_time` | 10.37 ns | 14.47 ns | +4 ns (expected — new runner) |
| `generate_rand_os_csprng`  | 36.36 ns | 45.13 ns | +9 ns (runner variance) |
| `gtpu_parser_gpdu_minimal` | 1.736 ns | 1.764 ns | stable |
| `ecs_spawn`                | 770.45 ps | 1.07 ns  | slight regression — still 935× under gate |
| `ecs_spawn_with_all_components` | 940.55 ns | 397.06 ns | **2.4× improvement** (iter_batched fix) |
| `ecs_despawn_zeroize`      | 182.44 ns | 208.07 ns | within variance |
| `routing_table_lookup_ul`  | 12.705 ns | 13.58 ns  | stable |
| `tunnel_create`            | 237.64 ns | 219.92 ns | slight improvement |

`ecs_spawn_with_all_components` improvement from 940 ns → 397 ns was the
`iter_batched` fix in Build #5: the old bench accumulated entities across
iterations, measuring HashMap resize rather than the actual insert cost.

---

## Optimization Priority Queue

### CLOSED

**GTP-U parser** (~283× under gate, LLVM auto-vectorized, no action needed)

**verify_res** (correct at 14 ns — constant-time working as intended, do not touch)

**Phase 1 Milenage** (514 ns, test sets 1–3 ✅, sets 4–6 pending TS 35.207 values)

**Phase 2 full attach** (end-to-end NAS + ECS + HSS, gate test passing)

**GTP-U UDP forwarder** (`GtpForwarder` — stateless process_uplink/encapsulate_downlink,
Tokio socket binding, Echo Request handling. Full socket integration tests pass.)

**SessionManager Phase 3 API** (`create_session_with_teid` + `update_bearer_info` —
maps `UpfEvent::CreateSession` and `UpfEvent::UpdateBearer` to routing table updates.)

**Phase 3 ICSR flow** (MME `with_phase3()` mode: SecModeComplete → ICSR → ICSRSP →
real DL TEID propagated to ECS + UpfEvent::UpdateBearer. Gate test passing.)

### ACTIVE — P1

**XDP program** (`gtp_xdp.rs::process` is a stub returning `XDP_PASS`.) Implement
the 8-step decision tree: ETH→IP→UDP→GTP-U header parse→TEID map lookup→header
rewrite→XDP_TX. BPF stack ≤ 512 bytes. Target < 200 ns per packet.

**eBPF loader** (`load_xdp` returns an error stub.) Activate the `aya-build`
pipeline in `midn-userplane/build.rs`, uncomment `BPF_OBJECT` embed, and wire
`load_xdp` into startup. Prerequisite: XDP program above compiles and passes
the BPF verifier.

**BPF map population** When `SessionManager::create_session_with_teid` creates a
session, also write the entry into the kernel `BPF_MAP_TYPE_HASH` so the XDP
program can find it without falling to XDP_PASS. Same for `update_bearer_info`
(atomic BPF map update per Rule 3) and `remove_session`.

### ACTIVE — P2

**Test sets 4–6** Fill `#[ignore]` tests in `milenage.rs` with values from
3GPP TS 35.207. No code changes required — just the expected hex constants.

**Detach procedure** `UeContextReleaseComplete` is handled (despawns entity,
emits `RemoveSession`). Missing: `DetachRequest` path from the UE side — NAS
Detach Request → MME → S1AP UE Context Release Command.

**TEID free list** `SessionManager::remove_session` removes entries but does not
recycle TEIDs. Add a free list or bump-allocator reset when the counter wraps.

**S1AP binary codec** `s1ap/messages.rs` has structs only. Actual ASN.1 PER
encode/decode needed for real eNodeB interop. Consider the `rasn` crate.

### FUTURE — P3

**SoA ECS upgrade** Replace `HashMap<EntityId, ComponentT>` with dense `Vec`
indexed by generation slots. `ecs_authenticated_count_10k` is 11 µs (linear
HashMap scan) — would drop to ~1 µs with Vec. Interface unchanged.

**NAS security EEA2/EIA2** `nas/security.rs` is a stub. NAS messages currently
run plaintext. Implement AES-CTR (EEA2) + AES-CMAC (EIA2) for real UE interop.

**TUAK** (`tuak.rs` stub) — Keccak-based AKA for quantum-resistant deployments.
Implement after Milenage test sets 4–6 are validated.
