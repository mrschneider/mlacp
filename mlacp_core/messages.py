"""MLACP wire vocabulary — closed, seven kinds, validated at one entrance.

The vocabulary is CLOSED on purpose (the same discipline the sibling
protocol uses): an unknown verb is refused *naming the word the peer sent
and listing the legal set*. A protocol that quietly accepts invented verbs
needs a translator for every pair of frameworks.

Wire kinds (the secondary-plane primitives):

- ``hello``         — bind to the node; carries the peer's version + URN
- ``envelope``      — a routed message between services (layer 4/5)
- ``custody``       — a bundle handed to a store-and-dump relay (layer 2)
- ``custody_ack``   — the relay/destination accepting or releasing custody
- ``route_update``  — grid management: arterial/lateral link state (layer 3)
- ``error``         — a typed refusal, in-protocol
- ``close``         — session teardown
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .addresses import Address
from .errors import BadAddress, UnknownKind, VersionMismatch, malformed

PROTOCOL = "mlacp"
MAJOR, MINOR = 1, 0

WIRE_KINDS = frozenset(
    {"hello", "envelope", "custody", "custody_ack", "route_update", "error", "close"}
)

MAX_TTL = 16  # hop budget, the field-grid hop discipline
REQUEST_ID_RE = re.compile(r"^req-[A-Za-z0-9_-]{1,64}$")

ENVELOPE_REQUIRED = ("sender", "recipient", "seq", "body")
CUSTODY_REQUIRED = ("bundle_id", "addressee", "ttl", "body")


@dataclass
class Envelope:
    """A routed message. ``sender``/``recipient`` are full URNs; ``seq`` is
    the sender's monotonic sequence; ``ttl`` counts down per hop."""

    sender: str
    recipient: str
    seq: int
    body: dict
    ttl: int = MAX_TTL
    request_id: str | None = None
    capabilities: list[str] = field(default_factory=list)

    def to_value(self) -> dict:
        v = {
            "sender": self.sender,
            "recipient": self.recipient,
            "seq": self.seq,
            "ttl": self.ttl,
            "body": self.body,
        }
        if self.request_id is not None:
            v["request_id"] = self.request_id
        if self.capabilities:
            v["capabilities"] = list(self.capabilities)
        return v

    @classmethod
    def from_value(cls, v: dict) -> "Envelope":
        _require(v, ENVELOPE_REQUIRED, "envelope")
        sender, recipient = _urn(v["sender"]), _urn(v["recipient"])
        seq = _int(v["seq"], "seq")
        if not isinstance(v["body"], dict):
            raise malformed("envelope body must be an object")
        ttl = v.get("ttl", MAX_TTL)
        if not isinstance(ttl, int) or not (1 <= ttl <= MAX_TTL):
            raise malformed(f"envelope ttl must be an int in [1,{MAX_TTL}]")
        rid = v.get("request_id")
        if rid is not None and not REQUEST_ID_RE.match(str(rid)):
            raise malformed("request_id must match req-[A-Za-z0-9_-]{1,64}")
        caps = v.get("capabilities", [])
        if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
            raise malformed("capabilities must be a list of strings")
        return cls(sender.to_urn() if isinstance(sender, Address) else sender,
                   recipient.to_urn() if isinstance(recipient, Address) else recipient,
                   seq, v["body"], ttl, rid, caps)


@dataclass
class Bundle:
    """A custody unit (layer 2). The relay NEVER inspects ``body`` —
    retention is by addressee, not by content."""

    bundle_id: str
    addressee: str
    ttl: int          # remaining contact windows
    body: dict
    origin: str
    seq: int          # origin sequence, for in-order drain

    def to_value(self) -> dict:
        return {
            "bundle_id": self.bundle_id,
            "addressee": self.addressee,
            "ttl": self.ttl,
            "origin": self.origin,
            "seq": self.seq,
            "body": self.body,
        }

    @classmethod
    def from_value(cls, v: dict) -> "Bundle":
        _require(v, CUSTODY_REQUIRED + ("origin", "seq"), "custody")
        addressee, origin = _urn(v["addressee"]), _urn(v["origin"])
        ttl = _int(v["ttl"], "ttl")
        if not (1 <= ttl <= MAX_TTL):
            raise malformed(f"bundle ttl must be an int in [1,{MAX_TTL}]")
        if not isinstance(v["body"], dict):
            raise malformed("bundle body must be an object")
        if not isinstance(v["bundle_id"], str) or not v["bundle_id"]:
            raise malformed("bundle_id must be a non-empty string")
        return cls(v["bundle_id"], addressee.to_urn(), ttl, v["body"],
                   origin.to_urn(), _int(v["seq"], "seq"))


def frame(kind: str, **fields) -> dict:
    """Build an outgoing wire frame."""
    if kind not in WIRE_KINDS:
        raise UnknownKind(kind, sorted(WIRE_KINDS))
    return {"kind": kind, "v": f"{MAJOR}.{MINOR}", **fields}


def parse_frame(v: dict) -> tuple[str, dict]:
    """The ONE validation entrance. Returns (kind, frame) or raises a typed
    refusal: structural violations -> InfrastructureFailure(malformed);
    vocabulary/version violations -> BusinessRefusal."""
    if not isinstance(v, dict):
        raise malformed("frame must be a JSON object")
    kind = v.get("kind")
    if kind not in WIRE_KINDS:
        raise UnknownKind(str(kind), sorted(WIRE_KINDS))
    ver = v.get("v", f"{MAJOR}.{MINOR}")
    if not isinstance(ver, str) or "." not in ver:
        raise malformed("frame version must be 'major.minor'")
    vmaj, _, vminor = ver.partition(".")
    if not (vmaj.isdigit() and vminor.isdigit()):
        raise malformed("frame version must be 'major.minor'")
    if int(vmaj) != MAJOR:
        raise VersionMismatch(
            f"peer speaks {ver}, this node speaks {MAJOR}.{MINOR} — majors are incompatible"
        )
    return kind, v


# -- helpers -----------------------------------------------------------------

def _require(v: dict, names: tuple[str, ...], what: str) -> None:
    missing = [n for n in names if n not in v]
    if missing:
        raise malformed(f"{what} missing required fields: {missing}")


def _urn(value) -> Address:
    if isinstance(value, Address):
        return value
    if not isinstance(value, str):
        raise BadAddress(f"address must be a URN string, got {type(value).__name__}")
    return Address.parse(value)


def _int(value, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise malformed(f"{name} must be an integer")
    return value
