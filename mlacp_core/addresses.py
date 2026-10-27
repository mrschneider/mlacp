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


@dataclass(frozen=True)
class Address:
    org: str
    zone: str
    node: str
    service: str

    # -- construction --------------------------------------------------------
    @classmethod
    def parse(cls, urn: str) -> "Address":
        m = URN_RE.match(urn)
        if not m:
            raise BadAddress(
                f"'{urn}' is not a mlacp URN "
                "(expected mlacp:<org>/<zone>/<node>/<service>)"
            )
        return cls(**m.groupdict())

    # -- behavior ------------------------------------------------------------
    def to_urn(self) -> str:
        return f"mlacp:{self.org}/{self.zone}/{self.node}/{self.service}"

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
