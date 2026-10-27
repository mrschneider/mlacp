# MLACP — Multi-Layered Agentic Communication Protocol

An agent-to-agent communication protocol whose layers are **ported from
reference architectures of the Soviet / Russian communications tradition** —
national network doctrines, military store-and-dump relaying, field
communications grids and the GOST cryptographic standards. See
[docs/research/soviet-communications-architectures.md](docs/research/soviet-communications-architectures.md)
for the sources behind every layer.

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

- **55 unit tests pass** (`python -m pytest tests/ -q`).
- **Kuznyechik verified against every official example of RFC 7801 §5** —
  substitution, linear transform, key schedule (K1..K10), encryption and
  decryption, byte for byte.
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

Run it yourself: `python experiments/run_e2e.py` (requires Node.js ≥ 18).

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

- **MGM authenticated mode** (RFC 9058) — integrity is CBC-MAC (simplified).
- **Streebog** (RFC 6986), **GOST R 34.13-2015 MAC with K^1/K^2 derivation**.
- **GOST R 34.10-2012 / VKO** (RFC 7091, RFC 7836) — no handshake: link keys
  are pre-shared (`CenterNode(link_key=...)`).
- **Kuznyechik in the wire's secure mode is only exercised through the
  custody path** — the envelope path on an open wire is plaintext JSON.
- Layer 3's multi-hop forwarding is implemented at the model level
  (`grid.route`, `next_hop`) but the reference node only exercises
  single-center delivery + custody; a two-center federation test is future
  work.
- Layer 1 has TCP + loopback channels; UDS and the "channel multiplexing"
  of the primary-network doctrine are not implemented.

## Layout

```
mlacp_core/     IO-free contract: messages, addresses, custody, grid,
                directory, authority, gost — no sockets
mlacp_engine/   reference participant: channels + the CenterNode
tests/          55 tests: RFC vectors, per-layer contracts, node behavior
experiments/    the Node.js client + the cross-language E2E driver
docs/           research (with sources), architecture, requirements
```
