# MLACP — Multi-Layered Agentic Communication Protocol

[![CI](https://github.com/mrschneider/mlacp/actions/workflows/ci.yml/badge.svg)](https://github.com/mrschneider/mlacp/actions/workflows/ci.yml)
[![Release](https://github.com/mrschneider/mlacp/actions/workflows/release.yml/badge.svg)](https://github.com/mrschneider/mlacp/actions/workflows/release.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

An agent-to-agent communication protocol whose layers are **ported from
reference architectures of the Soviet / Russian communications tradition** —
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
| 6 — GOST cryptographic layer | `mlacp_core.gost` | Kuznyechik (GOST R 34.12-2015), CTR, CBC-MAC |

The wire vocabulary is **closed**: seven kinds (`hello`, `envelope`,
`custody`, `custody_ack`, `route_update`, `error`, `close`). An unknown verb
is refused *naming the word the peer sent and listing the legal set* — the
refusal is the feature. Every refusal is typed and answered in-protocol.

## Verified results

- **87 unit tests pass** (`python -m pytest tests/ -q`).
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
tests/          80 tests: RFC/draft vectors, per-layer contracts, node behavior
experiments/    the Node.js client + the cross-language E2E driver
docs/           research (with sources), architecture, requirements
```
