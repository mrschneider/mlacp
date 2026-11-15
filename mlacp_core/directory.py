"""MLACP layer 4 — the hierarchical directory (OGAS / Akademset heritage).

Mandatory registration of services under a four-level URN; resolution with
zone-widening (exact zone first, then the whole organization); and
**per-organization accounting** — the Akademset principle that traffic is
attributed and rationed per organization.
"""

from __future__ import annotations

import threading
from ._locking import locked
from dataclasses import dataclass, field

from .addresses import Address
from .errors import DuplicateName, QuotaExceeded, UnknownService


@dataclass
class Entry:
    urn: str
    org: str
    zone: str
    node: str
    service: str
    capabilities: list[str] = field(default_factory=list)


@dataclass
class HierarchicalDirectory:
    """Registration + zone-widening resolution + per-org quota accounting."""

    org_quota: int = 128   # messages per accounting window, per organization
    _entries: dict[str, Entry] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)

    _by_service: dict = field(default_factory=dict, init=False, repr=False)
    _lock: object = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self):
        for entry in self._entries.values():
            self._by_service.setdefault((entry.org, entry.node, entry.service), {})[entry.urn] = entry

    # -- registration (mandatory, per OGAS) ------------------------------------
    @locked
    def register(self, urn: str, capabilities: list[str] | None = None) -> Entry:
        addr = Address.parse(urn)
        if urn in self._entries:
            raise DuplicateName(urn)
        entry = Entry(urn, addr.org, addr.zone, addr.node, addr.service,
                      list(capabilities or []))
        self._entries[urn] = entry
        self._by_service.setdefault((entry.org, entry.node, entry.service), {})[urn] = entry
        return entry

    @locked
    def unregister(self, urn: str) -> None:
        entry = self._entries.pop(urn, None)
        if entry is not None:
            key = (entry.org, entry.node, entry.service)
            bucket = self._by_service[key]
            bucket.pop(urn)
            if not bucket:
                del self._by_service[key]

    # -- resolution with zone-widening ------------------------------------------
    def resolve(self, urn: str) -> Entry:
        # Fast path: the wire URN IS the canonical string (validated at
        # parse_frame / Envelope.from_value).  A direct dict hit skips
        # the Address.parse → to_urn round-trip entirely.
        #
        # The hit path takes NO LOCK: a dict.get is atomic under the
        # GIL, and a read cannot observe a torn dict — the lock only
        # matters for the slow path (the zone-widening fallback, which
        # walks the index).
        entry = self._entries.get(urn)
        if entry is not None:
            return entry
        with self._lock:
            # Zone-widening: any zone of the same org, same node+service
            addr = Address.parse(urn)
            candidates = self._by_service.get((addr.org, addr.node, addr.service), {})
            if candidates:
                return next(iter(candidates.values()))
            raise UnknownService(urn)

    @locked
    def query(self, predicate) -> list[Entry]:
        """Query by attribute predicate (e.g. ``lambda e: 'time' in e.capabilities``)."""
        return [e for e in self._entries.values() if predicate(e)]

    # -- accounting (Akademset rateo) -------------------------------------------
    def account(self, org: str) -> int:
        """Charge one message to the organization, enforcing its quota."""
        with self._lock:
            n = self._counts.get(org, 0) + 1
            if n > self.org_quota:
                raise QuotaExceeded(
                    f"organization '{org}' exceeded its quota of {self.org_quota}"
                )
            self._counts[org] = n
            return n

    def charge_and_resolve(self, org: str, urn: str) -> Entry:
        """Charge the organization AND resolve the addressee under ONE lock.

        The hot path needs both: the per-message quota (Akademset
        accounting) and the mandatory registration check (the OGAS rule).
        Two separate calls took the lock twice per frame — every message
        serialized behind two acquisitions. The quota is charged FIRST, so
        the refusal order (quota before registration) is unchanged.

        The lock is taken EXPLICITLY (not through the ``@locked``
        decorator): the decorator repacks the arguments into ``*args,
        **kwargs`` on every call, which cost more than the lock it saved.
        """
        with self._lock:
            n = self._counts.get(org, 0) + 1
            if n > self.org_quota:
                raise QuotaExceeded(
                    f"organization '{org}' exceeded its quota of {self.org_quota}"
                )
            self._counts[org] = n
            entry = self._entries.get(urn)
            if entry is not None:
                return entry
            addr = Address.parse(urn)
            candidates = self._by_service.get((addr.org, addr.node, addr.service), {})
            if candidates:
                return next(iter(candidates.values()))
            raise UnknownService(urn)

    @locked
    def usage(self, org: str) -> int:
        return self._counts.get(org, 0)

    @locked
    def reset_accounting(self) -> None:
        self._counts.clear()

    @locked
    def all_entries(self) -> list[Entry]:
        return sorted(self._entries.values(), key=lambda e: e.urn)
