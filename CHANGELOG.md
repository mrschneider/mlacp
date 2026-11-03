# Changelog

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
