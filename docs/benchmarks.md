# Performance follow-up

These are local development measurements, not production capacity guarantees.
The starting tree was commit `148a52f`. The native backend was enabled unless
specified; both backend test suites and RFC vectors remain validation gates.

| Workload | Before | After |
|---|---:|---:|
| Authorize last holder among 10,000 grants | 223 µs | 0.53 µs |
| Revoke a root with 5,000 children | 530 ms | 4.63 ms |
| Zone-widening lookup among 10,000 entries | 411 µs | 1.98 µs |
| Contact absent custody addressee among 10,000 bundles | 383 µs | 0.68 µs |
| Route through a chain of 500 centers | 3.01 ms | 250 µs |
| 20,000 journal events, retained allocation | 4.47 MB | 2.23 MB (10,000 retained) |

A separate 50-exchange loopback comparison verified every reply: opening a new
TCP connection for each request took median 465 µs and accepted 50 connections;
the pool took median 43 µs and accepted one connection. Exchanges were sequential,
not multiplexed, and all resources were closed at the end.

Before integrating the separately published v0.2.10 stateless schedule cache,
a repeated 2 KB native encryption workload
measured 125 µs through the stateless function versus 65 µs with an explicit
SecureContext. Decryption measured 132 µs versus 73 µs. These compare the two
current APIs on the same data and exclude context construction from per-message
timing; a context is owned and reused for a link key's lifetime.

The repaired benchmark can be reproduced with:

```sh
python experiments/bench.py --iterations 10 --node-frames 2000
```

It verified 2,000/2,000 delivered envelopes at about 9.6 µs/frame in one local run.
Do not compare that with earlier reported node throughput: the previous harness
counted 128 unknown-service replies and 1,872 quota refusals as 2,000 processed
messages, and crypto timing executed once while dividing by 200. New timing uses
three repeated runs, real iteration counts, warmed tables, precomputed decryption
inputs, and a valid two-party VKO exchange whose derived keys must match.


The release also incorporates the newer v0.2.10 stateless key-schedule cache.
Its reuse is retained with a 64-key FIFO bound; explicit contexts bypass the
process-global cache. Consequently the stateless/context timing comparison above
describes the earlier implementation stage, not the final merged release.

The final merged local run measured stateless/context 2 KB encryption at about
66/79 µs and decryption at 66/64 µs. Small-run scheduling variation is visible;
contexts are intended for explicit key lifetime and bounded node ownership, not
a promised speedup over v0.2.10's warmed stateless cache.

## v0.3.6 — per-frame overhead

The v0.3.6 round targeted the work that happens **per frame** rather than
per call: lock acquisitions, buffer copies and socket syscalls.

| Workload | v0.3.5 | v0.3.6 |
|---|---:|---:|
| Repository harness — 2,000 envelopes over a loopback channel | 10.12 µs/frame (98,787 frames/s) | **7.79 µs/frame (128,449 frames/s)** |
| Local envelope dispatch — 100,000 frames in-process | 3.06 µs/frame (avg) | 2.95 µs/frame (avg) |

Methodology: `experiments/bench.py --iterations 20 --node-frames 2000`, native
backend enabled, 2,000/2,000 envelopes verified as delivered. The A/B was run
by stashing the five changed source files and re-running the same command on
the baseline tree, on the same machine, back to back. The in-process row is
best-of-6 alternating runs of 100,000 frames through `handle_frame`.

What changed, and why it is worth ~2.3 µs per frame on the wire path:

- **Two directory locks per frame became one.** The quota charge and the
  registration check were separate calls, each taking the directory lock;
  they are now one operation under a single acquisition.
- **The read path stopped locking.** `directory.resolve` now reads the
  index with a plain `dict.get` (atomic under the GIL) and only locks for
  the zone-widening fallback, which walks the service index.
- **Three buffer copies per frame became none.** The JSON line buffer is a
  `bytearray` on the channel, consumed in place; the old code copied it
  into a fresh `bytearray` and then copied the remainder back out as
  `bytes` — for every frame, in both directions.
- **One `setsockopt` per frame became one per connection.** The socket
  read timeout was re-applied on every read; it is now cached per channel
  and the remaining time is quantized to 5 ms so consecutive reads ask for
  the same value.
- **The stdlib fallback stopped padding the wire.** Compact separators
  (`","`/`":"`) instead of the default `", "`/`": "` — the same JSON value
  with ~10–15 % fewer bytes.

Caveats: single machine, one harness, and the envelope row is dominated by
the JSON round trip and the channel, not by the dispatch. The VKO
agreement row (≈35 ms per two-party exchange) was unchanged by this round
— it is dominated by the pure-Python elliptic-curve arithmetic, which is
the obvious next target and is not addressed here.

## VKO analysis (follow-up)

Profiling the VKO agreement (the ≈35 ms two-party exchange) shows the cost
is almost entirely the elliptic-curve arithmetic in pure Python:

| Component | Measured |
|---|---:|
| Two-party 512A VKO handshake | ~37 ms |
| One 512-bit scalar mult (pure Python, 8-bit window) | ~11 ms |
| A single 512-bit `x·x % p` (Python big-int) | ~0.6 µs |
| `_jdouble` body (the profile's dominant frame) | ~11 µs, ~69% of a mult |

A handshake does **four** scalar mults (two parties × {own private·G,
peer-public·ephemeral}), so ≈4 × 11 ms ≈ 37 ms — the number checks out.
Window size is NOT the lever: an 8-bit→4-bit window saves only ~1.2× and
the `a = p−3` (Curve 512A) specialization of the doubling formula saves
~4%, because the floor is Python's 512-bit modular multiply, not the
addition count. The only order-of-magnitude win is moving the field
arithmetic out of the interpreter.

**Status:** the natural target — a native Rust scalar mult in
`native/mlacp-gost` (the project already ships a Rust backend) — is
implemented and now fully verified (`src/ec.rs`, a self-contained
512/256-bit Montgomery field + Jacobian windowed double-and-add, no new
dependencies, ~3–4× faster than `num_bigint`'s u32-digit division). The
earlier runtime fault was a genuine reduction bug, now fixed: the GOST
512 prime `p` is a full 512-bit prime with `2p > 2^512`, so the CIOS
reduction can return a value up to `2p < 2^513` — one bit above the
2w-limb accumulator — and the discarded top carry had to be added back
as `2^512 − p`, followed by two conditional subtractions. The module
passes 11 Rust tests (including a 200-iteration full-range random field
test and `inv_check`) and matches a Python oracle on 30,000 random
reductions in `[0, 2^1024)`. It is **not yet wired into the wheel**:
the pure-Python reference (`mlacp_core/gost_ec.py`) remains the active,
fully-tested path (31 EC/GOST tests + RFC 7836 vectors pass);
`MLACP_PURE=1` still forces it. `ec.rs` is exported (`pub mod ec`) and
unit-tested, so the shipped wheel is unchanged.
