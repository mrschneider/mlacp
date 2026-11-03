# MLACP — Multi-Layered Agentic Communication Protocol

[![CI](https://github.com/mrschneider/mlacp/actions/workflows/ci.yml/badge.svg)](https://github.com/mrschneider/mlacp/actions/workflows/ci.yml)
[![Release](https://github.com/mrschneider/mlacp/actions/workflows/release.yml/badge.svg)](https://github.com/mrschneider/mlacp/actions/workflows/release.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

An agent-to-agent communication protocol whose layers are **ported from
reference architectures of communications tradition** —
national network doctrines, military store-and-dump relaying, field
communications grids and the GOST cryptographic standards. See
[docs/research/soviet-communications-architectures.md](docs/research/soviet-communications-architectures.md)
for the sources behind every layer and
[docs/architecture.html](docs/architecture.html) for the **drawing of the
implemented architecture** (open it in any browser — self-contained HTML).

## The six layers

| Layer | Module | Ported from |
|---|---|---|
| 1 — primary network / channels | `mlacp_engine.channels` | ЕАСС/ГСПД primary-secondary network doctrine |
| 2 — store-and-dump custody | `mlacp_core.custody` | Strela / Gonets relays |
| 3 — communications grid | `mlacp_core.grid` | PASS field-grid doctrine (arteries, laterals, autonomy) |
| 4 — hierarchical directory | `mlacp_core.directory` | OGAS / Akademset registration, zone-widening, per-org quota |
| 5 — capability chain of custody | `mlacp_core.authority` | АСУ authority pyramid (delegation shrinks, revocation cascades) |
| 6 — GOST cryptographic layer | `mlacp_core.gost` | Kuznyechik + Magma (GOST R 34.12-2015), CTR, MGM (RFC 9058), GOST MAC, Streebog (GOST R 34.11-2012), VKO handshake (RFC 7836), ACPKM key meshing |

## Performance & native backend

`native/mlacp-gost/` is a **Rust/PyO3 backend for the crypto hot path** —
Kuznyechik, CTR, MGM secure frames, Streebog in both conventions and the raw
block primitives, ported function-for-function from `mlacp_core.gost` (the
pure-Python module remains the readable reference specification).
`mlacp_core.gost` uses the native module automatically when installed; set
`MLACP_PURE=1` to force the pure-Python path. **Both backends are verified
by the SAME RFC vector suite** — conformance is per-backend, never assumed.

Measured (4 KB): secure frame **~0.6 ms native vs ~15 ms pure** (26–36×),
CTR ~0.2 ms vs ~4.8 ms, Streebog **~1.3 ms vs ~300 ms (225×)**; block cipher
~150 ns/block. Against the original table-free pure-Python baseline the
frame went from 1.41 s to 0.6 ms (~2,300×).

**Release wheels** (`v0.2.7+`): one `abi3-py310` wheel per platform covers
Python 3.10–3.14 — musl x86_64, musl aarch64, manylinux aarch64, macOS
Intel, macOS ARM, Windows amd64. On any platform without a wheel the pure
Python runs automatically, with identical conformance.

Known non-constant-time behavior: the table-driven S-box/T-table
implementations (both backends) index memory by secret data — acceptable
for peer-authenticated links, not for hostile co-tenancy. Tag verification
in the native backend is constant-time (`ct_eq` XOR-fold). For the hostile
co-tenancy threat model the crate also ships a **table-free constant-time
S∘L** (`kuznyechik_encrypt_block_ct`): the S-box evaluated through its
algebraic normal form (branchless AND/XOR circuit) and L as a 128×128 GF(2)
matrix — verified against the same RFC 7801 vectors and pinned equal to the
table path on random inputs; the price is ~7× per raw call (honest cost of
no secret-indexed access in software).

The wire vocabulary is **closed**: eight kinds (`hello`, `envelope`,
`custody`, `custody_ack`, `route_update`, `error`, `close`, `handshake`).
An unknown verb is refused *naming the word the peer sent and listing the
legal set* — the refusal is the feature. Every refusal is typed and answered
in-protocol.

## Verified results

- **87 unit tests pass on BOTH crypto backends** (`python -m pytest tests/ -q`
  runs the native Rust backend when installed; `MLACP_PURE=1 python -m pytest
  tests/ -q` runs the pure-Python reference — the same RFC vectors gate each
  backend separately).
- **Kuznyechik verified against every official example of RFC 7801 §5** —
  substitution, linear transform, key schedule (K1..K10), encryption and
  decryption, byte for byte.
- **Magma verified against the official GOST R 34.12-2015 vector**
  (`fedcba9876543210 → 4ee901e5c2d8ca3d`, param-Z S-boxes).
- **MGM verified against RFC 9058** (A.1.2 tag + A.1.1 ciphertext; the A.1.1
  printed A-block is internally inconsistent in the RFC — see the test).
- **GOST MAC (34.13-2015, OMAC1/K¹/K²) verified against the official A.1
  vector** (`336f4d296059fbe3`).
- **Streebog verified against RFC 6986 §10** — M1 and M2, both digest sizes,
  in the mathematical convention; plus the practical (CryptoPro byte-stream)
  convention verified against gostcrypto 1.2.5.
- **VKO verified against RFC 7836 Appendix B examples 7 and 8** — public
  keys reproduced from the private keys on
  id-tc26-gost-3410-12-512-paramSetA, both KEK values byte-for-byte, and the
  agreement proven symmetric. The **256-bit curve** (tc26-256-A, a
  cofactor-4 twisted Edwards curve in Weierstrass model) verifies:
  generator on curve, q·G = O, order 4·q.
- **ACPKM key meshing verified against the official test examples of
  draft-irtf-cfrg-re-keying-12 Appendix A.2** — CTR-ACPKM, CTR-ACPKM-Master,
  OMAC-ACPKM-Master, **GCM-ACPKM and GCM-ACPKM-Master** (AES as the test
  cipher; the construction is cipher-agnostic and the Kuznyechik/Magma
  instantiations share the same verified code path).
- **VKO handshake over the wire**: the `handshake` frame kind (the closed
  vocabulary is now eight verbs) lets two centers with NO pre-shared key
  derive their link key from ephemeral ГОСТ Р 34.10-2012 keys — the offer
  carries the ephemeral public point (LE) + UKM, the acceptor replies, and
  both sides hold the identical KEK_256 (symmetry proven on the wire in the
  test); the derived key immediately protects envelope traffic, and a
  public point not on the curve is refused in-protocol. **Epoch re-keying**
  (`rekey()`): an ESTABLISHED link rotates to a fresh KEK from fresh
  ephemerals — new traffic is NEVER decryptable under the previous epoch's
  key (forward secrecy, proven in the test), while the bounded in-flight
  window still opens traffic captured before the rotation, and replayed
  accept frames are a no-op.
- **Cross-language E2E**: a Node.js client (`experiments/client.js`) drives
  the Python reference center over TCP through registration, envelope
  ping-pong, custody with dump-on-return, and typed refusals:

```
[mlacp] node up on 127.0.0.1:PORT as mlacp:ministry/north/ct-1/center
PASS: register: hello answered with the node urn
PASS: register: directory contains the relay service
CLIENT_REGISTER: PASS
PASS: ping: both bound
PASS: ping: envelope crossed the node
PASS: ping: pong came back
CLIENT_PING: PASS
PASS: custody: node took custody and acked
PASS: custody: dump on re-registration
CLIENT_CUSTODY: PASS
PASS: node journal shows the custody dump (1 bundle)
PASS: refusals: unknown verb named and listed
PASS: refusals: bad address refused
CLIENT_REFUSALS: PASS
PASS: 3 refusals journaled with typed codes: badaddress, unknownbundle, unknownkind

EXPERIMENT_MLACP_E2E: PASS
```

- **Federation E2E**: two centers (ct-1, ct-2) linked by an arterial route;
  a client bound at ct-1 sends an envelope for a service homed at ct-2 —
  ct-1 forwards over the primary network, ct-2 delivers locally and answers
  the hop-by-hop `custody_ack`; ct-2 also serves clients over **UDS**
  (layer-1 media heterogeneity):

```
PASS: federation: relay service registered at ct-2 over UDS
PASS: federate: bound at the local center
PASS: federate: hop answered with a custody_ack
PASS: ct-2 journal shows the local delivery

EXPERIMENT_MLACP_FEDERATION: PASS
```

Run them yourself: `python experiments/run_e2e.py` and
`python experiments/run_federation.py` (requires Node.js ≥ 18).

## Quickstart

```python
from mlacp_core import Kuznyechik, CustodyRelay, CommunicationsGrid, \
    HierarchicalDirectory, CapabilityChain, Bundle, Envelope

# layer 6: real GOST cipher
cipher = Kuznyechik(bytes(range(32)))

# layer 2: hold traffic for an offline addressee, dump on return
relay = CustodyRelay()
relay.accept(Bundle("b1", "mlacp:org/zone/node/svc", 4, {"k": 1},
                    "mlacp:org/zone/src/svc", seq=1))
out = relay.contact("mlacp:org/zone/node/svc")   # in seq order

# layer 3: the grid reroutes around a dead artery
grid = CommunicationsGrid()
grid.add_link("moskva", "omsk", "arterial")
grid.add_link("omsk", "taishet", "lateral", cost=2)
grid.add_link("taishet", "vladivostok", "lateral", cost=2)

# layer 5: authority only shrinks on the way down
chain = CapabilityChain()
root = chain.issue_root("mlacp:stavka/main/command", ["send", "revoke"])
chain.delegate(root, "mlacp:front/west/hq", ["send"])        # ok
chain.delegate(root, "mlacp:front/west/hq", ["nuclear"])     # DelegationEscalation
```

## Honest gaps (deliberately not implemented)

- **Streebog conventions**: both the RFC 6986 mathematical convention
  (`streebog_*`) and the CryptoPro practical one (`streebog_practical`) are
  implemented and verified — but they produce DIFFERENT digests for the
  same input, and every consumer must pick one explicitly.
- **MGM ICN top bit**: reserved per RFC 9058 (V_{n-1}); the node generates
  ICNs accordingly.
- Envelope bodies on an open wire WITHOUT a link key (or before a
  `handshake`) remain plaintext JSON.
- MGM-ACPKM is not a standardized mode (the draft defines GCM/CBC/CTR over
  meshed keys); the MGM path uses single-key AEAD, the meshed AEAD path is
  GCM-ACPKM(-Master).
- The handshake derives one KEK per center pair per EPOCH; the re-key is
  initiated manually (`rekey()`) — automatic rotation on traffic volume or
  time is future work.

## Layout

```
mlacp_core/     IO-free contract: messages, addresses, custody, grid,
                directory, authority, gost — no sockets
mlacp_engine/   reference participant: channels + the CenterNode
native/         Rust/PyO3 backend for the GOST hot path (mlacp-gost crate)
tests/          87 tests: RFC/draft vectors (both crypto backends), per-layer
                contracts, node behavior
experiments/    the Node.js client + the cross-language E2E driver
docs/           research (with sources), architecture, requirements
.github/        CI (fmt/clippy/tests/E2E + native crate gate) and the
                release pipeline (test gate + 6-platform wheel matrix)
```

## Performance and resource controls

Authority validation uses a holder index; iterative cascading revocation visits
only descendants and retains deterministic history order. Directory zone widening
uses an ordered `(organization, node, service)` index, preserving exact-zone
precedence and registration order. Custody contact looks up only its addressee,
with sequence-ordered release and acknowledgement-based retention unchanged.
Advance custody TTLs through `age_one_window()`. Use registration/delegation and
custody APIs to change indexed state; do not mutate identity/address metadata or
private backing dictionaries directly. Compound index updates are synchronized
for the reference engine's connection threads.

Grid routing uses heap-based Dijkstra with non-negative integer costs. Both
`route()` and `next_hop()` honor weighted shortest paths, including when a direct
neighbor is more expensive than a multi-hop path. Updates and management decay
are reflected immediately; no stale route cache is retained.

`CenterNode(..., journal_limit=10000)` and
`CapabilityChain(history_limit=10000)` retain bounded event suffixes by default.
A limit of zero disables retention; `None` explicitly retains all events. These
are in-memory histories, not durable audit logs. Live grants, revocation decisions,
and custody state are independent of event-history retention.

Outbound peers use a bounded connection pool (`peer_capacity=32`,
`peer_idle_timeout=10.0`). Exchanges on each connection are serialized because the
protocol has no general request/response multiplexing identifier. Idle transports
are retired on pool activity or the serving loop's periodic checks; idle entries
can be evicted to make room, while a fully busy pool refuses new peers. Errors
invalidate the affected connection. **An ambiguous failed exchange is never
retried automatically**: the peer may already have accepted custody. The next
explicit call reconnects. Changed peer endpoints use separate transports.

`serve(node, listener, stop, max_connections=64, idle_timeout=30.0)` bounds accepted
connection workers and closes excess connections immediately. Shutdown closes
accepted and pooled transports and waits briefly for workers. Call `node.close()`
when using outbound forwarding without `serve()`. Keep the client pool idle
retirement shorter than the peer server's idle timeout. Framing retains partial
reads across timeouts, uses a total receive deadline, and bounds JSON lines at
4 MiB. Channel writes are serialized to prevent interleaved frames.

The native `gost.SecureContext(key)` retains an expanded Kuznyechik schedule;
`encrypt(iv, data)` and `decrypt(payload)` preserve secure-frame bytes and tag
validation. Nodes retain contexts only for their current three-epoch key window.
Nodes generate a fresh MGM IV for each encryption. Public key-schedule constants are shared globally. The stateless API retains
v0.2.10 schedule reuse through a process-wide FIFO cache bounded to 64 keys;
explicit contexts bypass that cache, so node keys follow their epoch lifetime. Native calls continue
releasing the GIL. Older wheels and `MLACP_PURE=1` retain a compatible Python
context API; rebuild the native wheel to obtain schedule reuse.

The corrected benchmark runs the requested number of iterations, separates
steady-state timing from warmup, uses valid symmetric VKO agreements, and verifies
successful deliveries instead of timing error replies:

```sh
python experiments/bench.py --iterations 20 --node-frames 2000
MLACP_PURE=1 python experiments/bench.py --iterations 1 --node-frames 100
```

Local measurements and their limits are recorded in [docs/benchmarks.md](docs/benchmarks.md).
