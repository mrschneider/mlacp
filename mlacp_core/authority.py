"""MLACP layer 5 — capability chain of custody (АСУ authority pyramid).

The АСУ doctrine: authority flows DOWN through the chain, and a lower
echelon can never possess an authority its superior does not carry. Three
rules ported verbatim:

1. **delegation can only shrink** — a delegation carries a subset of the
   parent's capabilities (escalation is refused by name);
2. **every send is validated** against the sender's chain;
3. **revocation cascades** — revoking a parent silently kills every
   descendant's capability, recorded as chain-of-custody history.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from .errors import DelegationEscalation, NotPermitted


@dataclass
class Grant:
    grant_id: str
    parent_id: str | None
    holder: str            # holder URN
    capabilities: frozenset[str]
    revoked: bool = False


@dataclass
class CapabilityChain:
    """The authority pyramid. The root grant belongs to the operating
    authority (the node's own operator)."""

    _grants: dict[str, Grant] = field(default_factory=dict)
    _history: list[str] = field(default_factory=list)
    _counter = itertools.count(1)

    # -- issuing -----------------------------------------------------------------
    def issue_root(self, holder: str, capabilities: list[str]) -> str:
        gid = f"g{next(self._counter)}"
        self._grants[gid] = Grant(gid, None, holder, frozenset(capabilities))
        self._history.append(f"root {gid} -> {holder} {sorted(capabilities)}")
        return gid

    def delegate(self, parent_id: str, holder: str, capabilities: list[str]) -> str:
        parent = self._grants.get(parent_id)
        if parent is None:
            raise NotPermitted(f"unknown grant '{parent_id}'")
        if parent.revoked:
            raise NotPermitted(f"grant '{parent_id}' is revoked — the chain is silent")
        escalation = set(capabilities) - parent.capabilities
        if escalation:
            raise DelegationEscalation(
                f"delegation to '{holder}' escalates {sorted(escalation)} "
                f"beyond parent '{parent_id}'"
            )
        gid = f"g{next(self._counter)}"
        self._grants[gid] = Grant(gid, parent_id, holder, frozenset(capabilities))
        self._history.append(
            f"delegate {parent_id} -> {gid} -> {holder} {sorted(capabilities)}"
        )
        return gid

    # -- validation ----------------------------------------------------------------
    def authorize(self, holder: str, capability: str) -> Grant:
        """The holder may act with ``capability`` only through some live grant
        of its own chain. Returns the grant that authorizes."""
        for g in self._grants.values():
            if g.holder == holder and not g.revoked and capability in g.capabilities:
                return g
        raise NotPermitted(
            f"'{holder}' holds no live grant carrying '{capability}'"
        )

    def grants_of(self, holder: str) -> list[Grant]:
        return [g for g in self._grants.values() if g.holder == holder and not g.revoked]

    # -- revocation (cascade) ---------------------------------------------------------
    def revoke(self, grant_id: str) -> int:
        """Revoke a grant and every descendant. Returns how many grants died."""
        g = self._grants.get(grant_id)
        if g is None:
            raise NotPermitted(f"unknown grant '{grant_id}'")
        if g.revoked:
            return 0
        g.revoked = True
        n = 1
        for child in self._grants.values():
            if child.parent_id == grant_id and not child.revoked:
                n += self.revoke(child.grant_id)
        self._history.append(f"revoke {grant_id} (cascade={n})")
        return n

    def history(self) -> list[str]:
        return list(self._history)
