"""MLACP layer 4 — the hierarchical directory (OGAS / Akademset heritage).

Mandatory registration of services under a four-level URN; resolution with
zone-widening (exact zone first, then the whole organization); and
**per-organization accounting** — the Akademset principle that traffic is
attributed and rationed per organization.
"""

from __future__ import annotations

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

    # -- registration (mandatory, per OGAS) ------------------------------------
    def register(self, urn: str, capabilities: list[str] | None = None) -> Entry:
        addr = Address.parse(urn)
        if urn in self._entries:
            raise DuplicateName(urn)
        entry = Entry(urn, addr.org, addr.zone, addr.node, addr.service,
                      list(capabilities or []))
        self._entries[urn] = entry
        return entry

    def unregister(self, urn: str) -> None:
        self._entries.pop(urn, None)

    # -- resolution with zone-widening ------------------------------------------
    def resolve(self, urn: str) -> Entry:
        addr = Address.parse(urn)
        exact = self._entries.get(addr.to_urn())
        if exact is not None:
            return exact
        # zone-widening: any zone of the same org, same node+service
        for e in self._entries.values():
            if e.org == addr.org and e.node == addr.node and e.service == addr.service:
                return e
        raise UnknownService(addr.to_urn())

    def query(self, predicate) -> list[Entry]:
        """Query by attribute predicate (e.g. ``lambda e: 'time' in e.capabilities``)."""
        return [e for e in self._entries.values() if predicate(e)]

    # -- accounting (Akademset rateo) -------------------------------------------
    def account(self, org: str) -> int:
        """Charge one message to the organization, enforcing its quota."""
        n = self._counts.get(org, 0) + 1
        if n > self.org_quota:
            raise QuotaExceeded(
                f"organization '{org}' exceeded its quota of {self.org_quota}"
            )
        self._counts[org] = n
        return n

    def usage(self, org: str) -> int:
        return self._counts.get(org, 0)

    def reset_accounting(self) -> None:
        self._counts.clear()

    def all_entries(self) -> list[Entry]:
        return sorted(self._entries.values(), key=lambda e: e.urn)
