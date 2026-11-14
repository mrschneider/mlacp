"""MLACP layer 4 — hierarchical addressing (OGAS / Akademset heritage).

Every MLACP address is a URN of four fixed levels, mirroring the
organization → zone → center hierarchy of OGAS and the per-organization
addressing of Akademset:

    mlacp:<org>/<zone>/<node>/<service>

The organization is the accounting domain (quotas are per-org); the zone is
the routing domain; the node is a center; the service is the endpoint within
the center. Zones widen for resolution: an exact-zone match wins, then any
zone of the same organization.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .errors import BadAddress

URN_RE = re.compile(
    r"^mlacp:(?P<org>[a-z0-9_-]{1,32})/(?P<zone>[a-z0-9_-]{1,32})"
    r"/(?P<node>[a-z0-9_-]{1,32})/(?P<service>[a-z0-9_-]{1,64})$"
)

_LEVELS = ("org", "zone", "node", "service")

# Parsed-URN cache: the hot path (Envelope.from_value) parses the same sender /
# recipient URNs repeatedly — once per frame, per hop. Address is immutable and
# frozen, so memoising the regex result is safe and the single biggest win in
# the frame profile (Address.parse / regex match is ~40% of per-frame time).
# Bounded LRU so a long-lived node can't leak via an adversarial URN stream.
_ADDRESS_CACHE: dict[str, Address] = {}
_ADDRESS_CACHE_MAX = 4096
# Inverse cache: Address -> URN string.  to_urn() is called up to 6× per
# frame on the hot path; the f-string is cheap but the cache eliminates it
# entirely for repeat addresses (the common case in a long-lived node).
# Bounded to prevent unbounded growth from adversarial URN streams.
_URN_STR_CACHE: dict[Address, str] = {}
_URN_STR_CACHE_MAX = 4096


@dataclass(frozen=True)
class Address:
    org: str
    zone: str
    node: str
    service: str

    # -- construction --------------------------------------------------------
    @classmethod
    def parse(cls, urn: str) -> "Address":
        cached = _ADDRESS_CACHE.get(urn)
        if cached is not None:
            return cached
        m = URN_RE.match(urn)
        if not m:
            raise BadAddress(
                f"'{urn}' is not a mlacp URN "
                "(expected mlacp:<org>/<zone>/<node>/<service>)"
            )
        a = cls(**m.groupdict())
        if len(_ADDRESS_CACHE) < _ADDRESS_CACHE_MAX:
            _ADDRESS_CACHE[urn] = a
            _URN_STR_CACHE[a] = urn  # the input string IS the canonical URN
        return a

    # -- behavior ------------------------------------------------------------
    def to_urn(self) -> str:
        cached = _URN_STR_CACHE.get(self)
        if cached is not None:
            return cached
        s = f"mlacp:{self.org}/{self.zone}/{self.node}/{self.service}"
        if len(_URN_STR_CACHE) < _URN_STR_CACHE_MAX:
            _URN_STR_CACHE[self] = s
        return s

    def org_of(self) -> str:
        return self.org

    def zone_of(self) -> str:
        return self.zone

    def widen_zones(self) -> list[str]:
        """Resolution order per the directory: the exact zone first, then
        every other zone of the same organization (zone-widening)."""
        return [self.zone, "*"]

    def __str__(self) -> str:
        return self.to_urn()
