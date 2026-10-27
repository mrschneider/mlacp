# MLACP requirements (implementation-agnostic)

R1. **Closed vocabulary.** The protocol defines 7 wire kinds. A frame whose
    kind is outside the set MUST be refused with an error naming the
    received kind and the legal set. (verified: test_messages, client.js)
R2. **One entrance.** All structural validation (version, addressing, field
    presence/types/bounds) happens in exactly one parse path; handlers trust
    the message. (verified: test_messages, test_node)
R3. **Typed refusals.** Business refusals are permanent; infrastructure
    failures carry a retryable flag; both are answered in-protocol. No
    refusal may be a bare string or ad-hoc object. (verified: tests + E2E)
R4. **Version policy.** Different major → refusal; different minor →
    accepted as additive. (verified: test_messages)
R5. **Custody contract.** A relay holds bundles for offline addressees,
    releases them in origin-sequence order on re-contact, releases its copy
    only on ack, expires bundles past their TTL of contact windows, and
    never interprets a bundle body. Capacity overflow refuses, never drops.
    (verified: test_custody)
R6. **Grid contract.** Centers connect via arterial or lateral links with
    administrative costs; routes minimize cost; a silent center is dropped
    autonomously after a decay window; route diversity between two centers
    is computable as edge-disjoint arterial paths. (verified: test_grid)
R7. **Directory contract.** Registration under a 4-level URN is mandatory
    before an envelope may be delivered or held; resolution widens zones
    within the organization; per-organization quotas are enforced with a
    named refusal. (verified: test_directory, test_node)
R8. **Authority contract.** Capabilities are granted from a root, delegated
    strictly downward (subset-only), validated per send, and revocation is
    transitive down the chain. (verified: test_authority, test_node)
R9. **Crypto contract.** The cipher layer is the GOST standard Kuznyechik
    (128-bit block, 256-bit key) and MUST match the official RFC 7801 test
    vectors; secured bodies carry MAC||ciphertext and MUST fail closed on
    tampering. (verified: test_gost)
R10. **Interop.** The protocol MUST be drivable by a client in a language
     other than the reference implementation, over a byte channel, with no
     shared code. (verified: experiments/run_e2e.py with Node.js)
