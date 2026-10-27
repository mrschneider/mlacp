"""MLACP layer 2 — store-and-dump custody (Strela / Gonets heritage).

The relay receives bundles for addressees that are not on the air, holds
them, and releases them **in sequence order per addressee** when the
addressee re-registers. Release is by **custody transfer**: each released
bundle is individually acknowledged (custody_ack), and only the ack releases
the relay's copy. Bundles expire after their TTL of contact windows. The
relay never inspects a bundle body.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from .errors import BusinessRefusal
from .messages import Bundle


class UnknownBundle(BusinessRefusal):
    def __init__(self, bundle_id: str):
        super().__init__(f"no bundle '{bundle_id}' held in custody")


@dataclass
class Release:
    """A bundle the relay released on re-registration, awaiting its ack."""

    bundle: Bundle


@dataclass
class CustodyRelay:
    """The store-and-dump agent. ``capacity`` bounds the onboard memory —
    refusing at admission (not silently dropping) is the feature."""

    capacity: int = 256
    _held: dict[str, Bundle] = field(default_factory=dict)   # bundle_id -> bundle
    _pending: dict[str, Release] = field(default_factory=dict)  # released, unacked
    _next: dict[str, int] = field(default_factory=dict)      # addressee -> next seq
    _counter = itertools.count()

    # -- taking custody -------------------------------------------------------
    def accept(self, bundle: Bundle) -> str:
        if len(self._held) + len(self._pending) >= self.capacity:
            raise BusinessRefusal("relay onboard memory full — custody refused")
        if bundle.bundle_id in self._held or bundle.bundle_id in self._pending:
            return bundle.bundle_id  # idempotent re-upload (station retransmit)
        self._held[bundle.bundle_id] = bundle
        return bundle.bundle_id

    # -- contact windows ------------------------------------------------------
    def contact(self, addressee_urn: str) -> list[Bundle]:
        """The addressee is on the air: release its held bundles IN SEQ ORDER
        (the Strela dump discipline). Each release becomes pending until its
        ack. Bundles whose TTL expired at this contact are dropped here —
        expiry is journaled by the engine, not silently."""
        self._expire()
        ready = sorted(
            (b for b in self._held.values() if b.addressee == addressee_urn),
            key=lambda b: b.seq,
        )
        out = []
        for b in ready:
            del self._held[b.bundle_id]
            self._pending[b.bundle_id] = Release(b)
            out.append(b)
        return out

    def acknowledge(self, bundle_id: str) -> None:
        """The custody ack: the relay's copy is released."""
        if bundle_id not in self._pending:
            raise UnknownBundle(bundle_id)
        del self._pending[bundle_id]

    # -- time passes ----------------------------------------------------------
    def age_one_window(self) -> list[str]:
        """One contact window passes: decrement every held TTL, return the
        ids of bundles that expired (the caller journals them)."""
        expired = []
        for b in list(self._held.values()):
            b.ttl -= 1
            if b.ttl <= 0:
                del self._held[b.bundle_id]
                expired.append(b.bundle_id)
        return expired

    def _expire(self) -> None:
        for b in [b for b in self._held.values() if b.ttl <= 0]:
            del self._held[b.bundle_id]

    # -- inspection -----------------------------------------------------------
    def held_for(self, addressee_urn: str) -> list[Bundle]:
        return sorted(
            (b for b in self._held.values() if b.addressee == addressee_urn),
            key=lambda b: b.seq,
        )

    def pending_acks(self) -> list[str]:
        return sorted(self._pending)

    def __len__(self) -> int:
        return len(self._held) + len(self._pending)
