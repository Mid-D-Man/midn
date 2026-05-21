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

## Build #11 Baseline — Official (rustc 1.95.0, ubuntu-latest, 2026)

First confirmed `[RELEASE]` numbers. These are the reference point for
all future optimization decisions.

### midn-auth

| Benchmark | Mean [RELEASE] | Gate | Status |
|---|---|---|---|
| `verify_res_constant_time` | 12.800 ns | < 25 ns | ✅ |
| `generate_rand_os_csprng` | 42.047 ns | < 100 ns | ✅ |
| `milenage_generate_vector` | ~1 ns (stub) | < 10 µs | stub — not real |

**Notes:**
- `verify_res` at 12.8 ns is the expected cost of `subtle::ConstantTimeEq`
  on an 8-byte array. This is correct behavior.
- `milenage_generate_vector` measures only `black_box` overhead; the actual
  function is `todo!()`. Gate becomes meaningful at Phase 1 completion.
- `generate_rand_os_csprng` at 42 ns reflects one `getrandom(2)` syscall.
  Batching RANDs (generate N at once) is a Phase 1 optimization if needed.

### midn-proto

| Benchmark | Mean [RELEASE] | Gate | Status |
|---|---|---|---|
| `gtpu_header_parse` | 6.539 ns | < 500 ns | ✅ (~76× under gate) |
| `gtpu_parser_gpdu_minimal` | 1.881 ns | < 500 ns | ✅ (~265× under gate) |
| `gtpu_parser_gpdu_with_seq` | 2.208 ns | < 500 ns | ✅ |
| `gtpu_header_serialize_round_trip` | 2.804 ns | < 500 ns | ✅ |
| `bulk_parse/10` | 16.527 ns | — | 1.65 ns/packet |
| `bulk_parse/100` | 164.31 ns | — | 1.64 ns/packet |
| `bulk_parse/1000` | 1.684 µs | — | 1.68 ns/packet |

**Notes:**
- GTP-U parser is well under gate at all batch sizes. No Tier 2 work needed.
- Linear scaling in bulk parse (1.65-1.68 ns/packet) confirms no per-batch
  overhead — LLVM is auto-vectorizing the parse loop.
- 500 ns gate is intentionally conservative. It will only become relevant
  if a regression occurs, not as an optimization target.

---

## Optimization Priority Queue (Post Build #11)

Based on the first baseline:

**Not needed — GTP-U parser (already ~265× under gate)**

The parser is allocation-free and LLVM-auto-vectorized. Adding manual
intrinsics would provide no measurable benefit. Closed.

**Not needed — verify_res (correct at 12.8 ns)**

Constant-time is working as intended. Any "optimization" that reduces this
below ~10 ns is a regression in security, not a performance win. Closed.

**Phase 1 — Milenage generate_vector (stub)**

The only current performance gap is that `generate_vector` is not
implemented. Phase 1 target: < 10 µs after f1..f5 are in place.
AES-128 on modern x86_64 using AES-NI intrinsics (via the `aes` crate)
should reach 1-3 µs. Scalar fallback for non-AES-NI targets should
reach 5-8 µs.

**Phase 3 — eBPF/XDP routing (not yet measurable)**

XDP packet decision target: < 200 ns. Baseline will be established
in Build #1 of the Phase 3 branch.
