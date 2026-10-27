# MLACP architecture — concept-to-code map

## Invariants (each enforced where noted)

1. **The wire vocabulary is closed.** Seven kinds; `parse_frame` refuses
   unknown verbs naming the verb and the legal set (`messages.parse_frame`).
2. **One validation entrance.** Every frame passes `parse_frame` +
   `Envelope.from_value` / `Bundle.from_value`; handlers trust the result.
3. **Every refusal is typed and in-protocol.** Business refusals are
   permanent, infrastructure failures carry a `retryable` flag
   (`errors.py`); the node answers violations with `error` frames, never
   ad-hoc objects (`node.handle_frame`).
4. **The relay never inspects bundle bodies.** Retention is by addressee
   (`custody.CustodyRelay`).
5. **Custody release is by ack.** A released bundle stays pending until
   `custody_ack` — at-least-once delivery, exactly the Strela contract.
6. **Delegation only shrinks.** Escalation is refused naming the excess
   capabilities (`authority.CapabilityChain.delegate`).
7. **Revocation cascades.** Killing a parent grant kills every descendant
   (`authority.CapabilityChain.revoke`).
8. **Registration is mandatory.** An unregistered addressee is refused
   `unknown_service` BEFORE custody is considered (`node._on_envelope`).
9. **Accounting is per organization.** Quotas are enforced at the directory
   (`directory.account`), the Akademset rateo.
10. **The grid decays silence.** Centers not heard from drop out after
    `decay_after` management ticks — autonomous, no manual deprovision
    (`grid.management_tick`).
11. **Hello binds idempotently.** Re-binding a registered URN is a
    reconnect: the entry is updated, not refused (`node._on_hello`).
12. **Different major version is refused; different minor is additive**
    (`messages.parse_frame`).

## Layer wiring

```
frame (closed vocabulary)
  └─ handle_frame  ─── one entrance, typed errors
       ├─ hello        → layer 4 registration + layer 2 dump-on-return
       ├─ envelope     → layer 5 authorize → layer 4 account/resolve
       │                 → layer 3 route → deliver | layer 2 custody
       ├─ custody      → layer 2 accept (relay)
       ├─ custody_ack  → layer 2 release
       ├─ route_update → layer 3 management plane
       ├─ error        → journal
       └─ close        → connection teardown
```

Secure bodies (`link_key` set) travel as
`{"__secure__": true, "iv": b64, "payload": b64}` where payload is
`CBC-MAC(body) || CTR(body)` under Kuznyechik — the relay holds ciphertext
only.

## Porting fidelity notes

- Layer 6 is byte-verified against RFC 7801 §5 (all six example groups).
- Layer 2's discipline (no routing decisions in the relay, release by
  contact, per-contact TTL) mirrors the Strela store-and-dump description.
- Layer 3's arteries/laterals/autonomy mirror the PASS doctrine text
  (Wilson Center doc 114555): point-to-point grid between centers,
  heterogeneous-media agnostic routing, management plane separate from data.
- Layer 4's zone-widening mirrors OGAS hierarchy: exact zone first, then
  the organization — the org is the accounting domain (Akademset).
- Layer 5's rules are the АСУ authority pyramid verbatim: authority flows
  down, can only shrink, and dies with the revoking parent.
