# Research: reference communications architectures of the Soviet / Russian
# tradition, and what each contributes to MLACP

MLACP (Multi-Layered Agentic Communication Protocol) ports structural elements
from six real architectures of the Soviet / Russian communications tradition.
This document is the source of the vocabulary; every module in `mlacp_core`
cites its layer back to one entry here.

## 1. ЕАСС / ГСПД — the Unified Automated Communications Network

The Soviet national network doctrine (Единая автоматизированная сеть связи)
was organized as **primary and secondary networks**: a primary network of
"generic channels" (physical/multiplexed links carrying no service semantics)
and, layered on top, secondary switched networks (telephone, telegraph, data)
that **consume channels** and add service semantics. Services never saw each
other's wire details; every secondary service could run on any channel.

**Ported as**: MLACP layer 1 (`mlacp_engine.channels`). A `Channel` moves
bytes and knows nothing about messages; secondary planes (messaging, custody,
management) ride any channel. An agent peer is reachable over loopback, UDS or
TCP with an identical secondary-plane behavior.

## 2. Strela / Gonets — store-and-dump relaying

Military LEO satellites (Strela series, 1960s-; civilian derivative Gonets)
implemented **store-and-dump**: a low-power station transmits when the
satellite is overhead; the satellite **holds the message in onboard memory and
retransmits it to the destination during a later pass**. Two principles:

- the relay **does not interpret the payload** — no routing decisions on
  board, only hold/release by schedule or by contact. Simplicity was the
  survivability argument (no on-board software to corrupt, nothing to jam
  selectively);
- delivery is **by custody transfer**: the origin hands the message to the
  relay, the relay owns it until the destination (or the next relay)
  acknowledges, and messages expire after a TTL.

**Ported as**: MLACP layer 2 (`mlacp_core.custody`). `CustodyRelay` takes
bundles, holds them for an offline addressee, releases **in sequence order**
on re-registration, acknowledges each release (releasing custody), and expires
bundles whose TTL passed. The relay never opens a bundle: retention is
by-addressee, not by-content.

## 3. PASS / PASUV — the field communications grid doctrine

The Warsaw Pact automated communications doctrine (front-level "передовая
сеть связи", PASS) prescribed a **grid of communications centers** connected
point-to-point, composed of **communication arteries** (trunks between major
centers), **lateral lines** (cross-links that bypass damaged arteries) and
**communications grids** (local meshes). Its management principles:

- **autonomy**: a centralized management system collects status and delivers
  decisions, but "centralization should not exclude" local autonomy — a
  center that loses contact with management must keep switching with its last
  known state;
- **comprehensive use of heterogeneous media**: radio-relay, tropospheric and
  landline channels are one addressing space; the grid re-routes around
  destroyed or jammed links;
- redundancy by **route diversity**, not by duplicating the same route.

**Ported as**: MLACP layer 3 (`mlacp_core.grid`). `CommunicationsGrid` keeps
arterial and lateral routes between center nodes, re-computes a route when an
arterial fails (preferring the lateral bypass), and runs an autonomous
management tick that decays stale routes — a node that stops being heard from
drops out of the routing table without a manual deprovision step.

## 4. OGAS — hierarchical directories and unified information formats

Glushkov's national network proposal (1962-) was built around a hierarchy of
computing centers — regional centers serving zones, a national center
coordinating them — with **mandatory registration of organizations** in the
hierarchy and **standard formats** for the information exchanged. The
hierarchical address (organization → zone → center) was the routing key.

**Ported as**: MLACP layer 4 (`mlacp_core.directory`). `HierarchicalDirectory`
binds services under URNs of the form
`mlacp:<org>/<zone>/<node>/<service>`, resolves with zone-widening (exact
zone first, then the whole org), and keeps **per-organization accounting**
(quota of messages registered/passed — the Akademset rateo principle).

## 5. АСУ military command systems — capability chain of custody

Soviet automated command-and-control (the ASURK family in air defense, and
the general АСУ doctrine) was a **rigid authority pyramid**: engagement
authorization flows downward through the chain, and a lower echelon can never
possess an authority its superior does not carry. A command channel that lost
its authorization link fell silent; it did not improvise.

**Ported as**: MLACP layer 5 (`mlacp_core.authority`). `CapabilityChain`
issues delegations that can only **shrink** (a delegation carries a subset of
the parent's capabilities), validates every send against the sender's chain,
and records the chain of custody of each delegation. Authority is revocable
down the chain: revoking a parent silently kills every descendant's
capability.

## 6. ГОСТ — the cryptographic standards

The Russian federal standards form a complete, IETF-documented suite:

- **Magma** (ГОСТ Р 34.12-2015, RFC 7801 — descended from ГОСТ 28147-89,
  RFC 5830): 64-bit block, 256-bit key, 32 rounds of substitution-permutation
  with eight 4-bit S-boxes;
- **Kuznyechik** (ГОСТ Р 34.12-2015, RFC 7801): 128-bit block, 128-bit key,
  10 rounds of S-P with a linear transform over GF(2⁸);
- **MGM** (ГОСТ Р 34.13-2015, RFC 9058): authenticated-encryption mode;
- **Streebog** (ГОСТ Р 34.11-2012, RFC 6986): hash, 256/512-bit;
- **ГОСТ Р 34.10-2012 / VKO** (RFC 7091 / 7836): signatures and key
  agreement on Russian elliptic curves.

**Ported as**: MLACP layer 6 (`mlacp_core.gost`). **Magma is implemented in
full and verified against the official test vector** of ГОСТ Р 34.12-2015
(key `ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`,
plaintext `fedcba9876543210` → ciphertext `4ee901e5c2d8ca3d`), plus the
**CTR** encryption mode and the **CMAC** message authentication code of
ГОСТ Р 34.13-2015. Kuznyechik, MGM, Streebog and VKO are *not* implemented —
see the gap list in the README.

## Sources

- OGAS — Wikipedia: https://en.wikipedia.org/wiki/OGAS
- Aeon, "How the Soviets invented the internet and why it didn't work":
  https://aeon.co/essays/how-the-soviets-invented-the-internet-and-why-it-didnt-work
- Strela satellite (store-and-dump description):
  https://en.wikipedia.org/wiki/Strela_(satellite) ; Gonets/Strela:
  https://www.russianspaceweb.com/gonets.html
- Warsaw Pact PASS/PASUV communications report (Wilson Center Digital
  Archive, doc 114555): https://digitalarchive.wilsoncenter.org/document/114555
- ГОСТ R 34.12-2015 test vectors / RFC 7801 (Kuznyechik, Magma):
  https://datatracker.ietf.org/doc/rfc7801/
- ГОСТ 28147-89 / RFC 5830: https://datatracker.ietf.org/doc/rfc5830/
- MGM mode / RFC 9058: https://datatracker.ietf.org/doc/rfc9058/
- Streebog / RFC 6986: https://datatracker.ietf.org/doc/rfc6986/
- VKO / RFC 7836: https://datatracker.ietf.org/doc/rfc7836/
- RustCrypto gost-crypto: https://crates.io/crates/gost-crypto
