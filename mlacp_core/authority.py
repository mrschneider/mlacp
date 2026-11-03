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
import threading
from collections import deque
from ._locking import locked
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
    history_limit: int | None = 10_000
    _holders: dict = field(default_factory=dict, init=False, repr=False)
    _children: dict = field(default_factory=dict, init=False, repr=False)
    _lock: object = field(default_factory=threading.RLock, init=False, repr=False)
    _counter = itertools.count(1)

    def __post_init__(self):
        if self.history_limit is not None and self.history_limit < 0:
            raise ValueError("history_limit must be non-negative or None")
        self._history = deque(self._history, maxlen=self.history_limit)
        for grant in self._grants.values():
            if not grant.revoked:
                self._holders.setdefault(grant.holder, {})[grant.grant_id] = grant
            if grant.parent_id is not None:
                self._children.setdefault(grant.parent_id, {})[grant.grant_id] = None

    # -- issuing -----------------------------------------------------------------
    @locked
    def issue_root(self, holder: str, capabilities: list[str]) -> str:
        gid = f"g{next(self._counter)}"
        self._grants[gid] = Grant(gid, None, holder, frozenset(capabilities))
        self._holders.setdefault(holder, {})[gid] = self._grants[gid]
        self._history.append(f"root {gid} -> {holder} {sorted(capabilities)}")
        return gid

    @locked
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
        self._holders.setdefault(holder, {})[gid] = self._grants[gid]
        self._children.setdefault(parent_id, {})[gid] = None
        self._history.append(
            f"delegate {parent_id} -> {gid} -> {holder} {sorted(capabilities)}"
        )
        return gid

    # -- validation ----------------------------------------------------------------
    @locked
    def authorize(self, holder: str, capability: str) -> Grant:
        """The holder may act with ``capability`` only through some live grant
        of its own chain. Returns the grant that authorizes."""
        for g in self._holders.get(holder, {}).values():
            if g.holder == holder and not g.revoked and capability in g.capabilities:
                return g
        raise NotPermitted(
            f"'{holder}' holds no live grant carrying '{capability}'"
        )

    @locked
    def grants_of(self, holder: str) -> list[Grant]:
        return [g for g in self._holders.get(holder, {}).values() if not g.revoked]

    # -- revocation (cascade) ---------------------------------------------------------
    @locked
    def revoke(self, grant_id: str) -> int:
        """Revoke a grant and every descendant. Returns how many grants died."""
        g = self._grants.get(grant_id)
        if g is None:
            raise NotPermitted(f"unknown grant '{grant_id}'")
        if g.revoked:
            return 0
        counts = {}
        stack = [(grant_id, False)]
        while stack:
            gid, finishing = stack.pop()
            grant = self._grants[gid]
            if finishing:
                n = 1 + sum(counts.get(child, 0) for child in self._children.get(gid, ()))
                counts[gid] = n
                self._history.append(f"revoke {gid} (cascade={n})")
                continue
            if grant.revoked:
                continue
            grant.revoked = True
            holders = self._holders.get(grant.holder, {})
            holders.pop(gid, None)
            if not holders:
                self._holders.pop(grant.holder, None)
            stack.append((gid, True))
            for child in reversed(self._children.get(gid, ())):
                if not self._grants[child].revoked:
                    stack.append((child, False))
        return counts[grant_id]

    @locked
    def history(self) -> list[str]:
        return list(self._history)
