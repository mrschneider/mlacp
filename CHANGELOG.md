# Changelog

## [0.3.2] — 2026-11-08

MLACP v0.3.2 accelerates the two remaining hot paths: the native Streebog
digest (`l64`) and the pure-Python VKO scalar multiplication. The Python API,
wire format, native wheel version (0.2.1) and public behaviour are unchanged;
all RFC vectors pass on both backends.

## Changes

- **Native Streebog `l64` (Rust):** replace the 64 masked `count_ones`
  column-parity loop with GF(2)-linear byte-decomposition tables
  (`l64_tabs`): 8 lookups + 7 XORs per 64-bit group, 16 KB resident,
  bit-for-bit identical to the old path (verified against 20 M random
  64-bit inputs and the RFC 9058 A.112 full-tag vector through the native
  path). Removes the dead `l_cols` column-mask builder.
- **Pure-Python VKO scalar multiplication (`mlacp_core/gost_ec.py`):** the
  8-bit window table is now built per point (bounded to 16 entries) and
  window additions use a general Jacobian add (`_jadd_jac`) instead of
  converting each table entry to affine. A full 512-bit scalar mult now uses
  ONE modular inverse (the final Jacobian→affine) instead of ~512.

## Validation

- 110 Python tests pass on both the native and pure-Python backends; 8 Rust
  tests pass, `cargo fmt --check` and `cargo clippy --release` are clean.
- Local measurements (`experiments/bench.py --iterations 50 --node-frames
  2000`, native backend, 50 calls/run, best of 3): Streebog-256/512 on 64 KB
  drop from ≈16.05/16.38 ms to ≈2.57/2.38 ms (≈6.3×/6.9×); VKO_512 symmetric
  agreement drops from ≈67.9 ms to ≈37.2 ms (≈1.8×). Pure-Python VKO_512
  (same handshake, `MLACP_PURE=1`, best of 3) drops from ≈79 ms to ≈50 ms
  (≈1.6×). Development measurements, not production guarantees.

## [0.3.1] — 2026-11-07

MLACP v0.3.1 fixes the native GOST-RS authentication tag to be fully RFC 6072-2 / RFC 9058 compliant and accelerates the native crypto path. The Python API, wire format and public behaviour are unchanged.

## Changes

- Correct the native Rust `ctr_decrypt` counter path for RFC 6072-2: the ciphertext block is now byte-reversed before applying the keystream, and the base advances by the block number (the previous block number was used, corrupting every tag after block 0).
- Replace the 128-iteration bit loop in `mgm_mul` with precomputed byte tables (`mgm_byte_tbls` / `mgm_mul_with`): 16 lookups + 15 XORs per multiply, bit-for-bit identical output.
- Add `mgm_mul_block` for AAD/CT blocks: LSB-first byte folding with in-place zero padding of the final partial block (no reallocation), roughly half the work of the original loop.
- Cache the Streebog round constants in a `OnceLock` (`c_constants`) instead of re-parsing 12 hex strings per 64-byte block (~12,000 redundant decodes for a 64 KB digest).
- Add permanent regression guards to the Rust crate (`mgm_mul_reference`): naive schoolbook GF(2^128) cross-checks for `mgm_mul` and `mgm_mul_block`, plus the full RFC 9058 A.112 tag vector computed entirely through the native path.

## Compatibility

- Protocol wire version remains 1.0; native wheel package version is 0.2.1.
- No API changes; tags produced by the native backend now match the pure-Python reference exactly.

## Validation

- 110 Python tests pass with both the native and pure-Python backends (1.40 s); previously failing `tests/test_performance_followup.py` (5 tests) now passes.
- 8 Rust tests pass, including the RFC 9058 A.112 full-tag vector through the native path.
- Local measurements: native `secure_encrypt` ≈ 35 µs (256 B) vs ≈ 1.2 ms pure-Python (~35× faster at 256 B, ~44× at 4 KB); full 110-test suite ≈ 1.4 s native vs ≈ 1.5 s pure-Python. Development measurements, not production guarantees.

## [0.3.0] — 2026-11-02

MLACP v0.3.0 improves authority, routing, lookup and peer transport performance while bounding event and connection resources. It includes the newer v0.2.10 native optimization.

## Changes

- Index capability grants by holder and descendants by parent; revoke deep trees iteratively while preserving deterministic history.
- Use heap-based weighted routing and fix the direct-neighbor shortcut that selected expensive direct links over cheaper multi-hop routes.
- Index directory zone widening and custody contacts, preserving exact-zone precedence, sequence order, TTL windows and acknowledgement-based retention.
- Reuse up to 32 outbound peer connections by default, serialize each connection's exchanges, retire idle transports and bound serving workers to 64 per listener.
- Add explicit native SecureContext key schedules and precomputed public constants. Preserve v0.2.10 stateless schedule reuse with a 64-key FIFO bound; node contexts bypass that cache and follow the three-epoch key window.
- Bound node journals and capability histories to 10,000 events by default, independently of live authority and custody state.
- Repair the benchmark to run actual iteration counts, verify symmetric VKO agreements and count successful deliveries rather than error replies.

## Compatibility and configuration

- Protocol wire version remains 1.0; native wheel package version is 0.2.0.
- Set journal_limit/history_limit to zero to disable history, or None for explicit unlimited retention.
- Configure peer_capacity, peer_idle_timeout, max_connections and idle_timeout for deployments. Close standalone nodes with node.close(). Excess server connections are closed; fully busy peer pools refuse new peers.
- Failed or ambiguous exchanges are never retried automatically: custody may already have been accepted. A later explicit call reconnects.
- JSON lines are bounded at 4 MiB. Partial reads survive receive timeouts; channel writes are serialized.
- Update indexed state through the provided registration, delegation and custody APIs rather than mutating identity/address metadata or private stores.

## Validation

- 110 Python tests pass with both the native and pure-Python backends; 5 Rust tests, strict Clippy, Rust formatting, and both cross-language experiments pass locally.
- Local measurements: revoking 5,000 descendants fell from about 530 ms to 4.6 ms; pooled loopback exchanges measured median 43 µs versus 465 µs with fresh connections (1 connection versus 50 for 50 verified exchanges).
- These are development measurements, not production capacity guarantees. See docs/benchmarks.md for methodology and historical timing caveats.

Earlier releases: https://github.com/mrschneider/mlacp/releases
