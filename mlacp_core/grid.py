"""MLACP layer 3 — the communications grid (PASS doctrine heritage).

A grid of communications centers connected by **arterial** trunks (the
primary paths between major centers) and **lateral** lines (cross-links that
bypass damaged arteries). Routing principles ported from the doctrine:

- route diversity: when an arterial fails, the lateral bypass is used;
- autonomy: the grid's management tick decays routes whose center has not
  been heard from — a silent center drops out without a manual deprovision;
- the management plane is separate from the data plane (route_update frames).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import BusinessRefusal


class NoRoute(BusinessRefusal):
    def __init__(self, center: str):
        super().__init__(f"no route to communications center '{center}'")


@dataclass
class Link:
    to_center: str
    kind: str            # "arterial" | "lateral"
    cost: int            # administrative weight; arterial < lateral
    freshness: int = 3   # management ticks of grace before decay


@dataclass
class CommunicationsGrid:
    """Routing between centers. ``heard`` marks a management tick in which
    the center proved alive (hello / route_update)."""

    decay_after: int = 3
    _links: dict[str, dict[str, Link]] = field(default_factory=dict)
    _heard: dict[str, int] = field(default_factory=dict)
    _tick: int = 0

    # -- building the grid -----------------------------------------------------
    def add_center(self, center: str) -> None:
        self._links.setdefault(center, {})

    def add_link(self, a: str, b: str, kind: str = "arterial", cost: int = 1) -> None:
        if kind not in ("arterial", "lateral"):
            raise BusinessRefusal(f"link kind must be arterial|lateral, got '{kind}'")
        self.add_center(a)
        self.add_center(b)
        self._links[a][b] = Link(b, kind, cost)
        self._links[b][a] = Link(a, kind, cost)

    def mark_heard(self, center: str) -> None:
        self._heard[center] = self._tick

    # -- the management tick (autonomy) ---------------------------------------
    def management_tick(self) -> list[str]:
        """One management tick: advance, decay freshness on every link to a
        center not heard from, and drop centers gone silent. Returns the
        centers removed (the caller journals them)."""
        self._tick += 1
        removed = []
        for center in list(self._links):
            last = self._heard.get(center, 0)  # never heard = silent since birth
            if self._tick - last > self.decay_after:
                removed.append(center)
        for center in removed:
            self._links.pop(center, None)
            for links in self._links.values():
                links.pop(center, None)
        return removed

    # -- routing ---------------------------------------------------------------
    def route(self, source: str, target: str) -> list[str]:
        """Dijkstra over the surviving links. Ties prefer arterials (lower
        cost). Returns the center path INCLUDING both endpoints; raises
        NoRoute when the target has fallen silent or was never connected."""
        if target not in self._links:
            raise NoRoute(target)
        if source not in self._links:
            raise NoRoute(source)
        dist = {source: 0}
        prev: dict[str, str | None] = {source: None}
        visited: set[str] = set()
        while True:
            pending = {c: d for c, d in dist.items() if c not in visited}
            if not pending:
                raise NoRoute(target)
            current = min(pending, key=lambda c: (pending[c], c))
            if current == target:
                break
            visited.add(current)
            for link in self._links.get(current, {}).values():
                if link.to_center in visited:
                    continue
                nd = dist[current] + link.cost
                if nd < dist.get(link.to_center, 1 << 30):
                    dist[link.to_center] = nd
                    prev[link.to_center] = current
        path, node = [], target
        while node is not None:
            path.append(node)
            node = prev[node]
        return list(reversed(path))

    def next_hop(self, source: str, target: str) -> str:
        path = self.route(source, target)
        return path[1] if len(path) > 1 else target

    def centers(self) -> list[str]:
        return sorted(self._links)

    def route_diversity(self, a: str, b: str) -> int:
        """How many edge-disjoint arterial routes survive between two centers
        (the doctrine's route-diversity metric, computed by max-flow)."""
        return self._max_flow(a, b, kind="arterial")

    def _max_flow(self, s: str, t: str, kind: str) -> int:
        cap = {
            a: {link.to_center: 1 for link in links.values() if link.kind == kind}
            for a, links in self._links.items()
        }
        flow = 0
        while True:
            # BFS in the residual graph
            parent: dict[str, str | None] = {s: None}
            queue = [s]
            while queue and t not in parent:
                u = queue.pop(0)
                for v, c in cap.get(u, {}).items():
                    if c > 0 and v not in parent:
                        parent[v] = u
                        queue.append(v)
            if t not in parent:
                return flow
            # augment by 1
            v: str | None = t
            while v is not None and parent[v] is not None:
                u = parent[v]
                assert u is not None
                cap[u][v] -= 1
                cap.setdefault(v, {}).setdefault(u, 0)
                cap[v][u] += 1
                v = u
            flow += 1
