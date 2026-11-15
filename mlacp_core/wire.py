"""MLACP wire serialization — orjson fast-path with stdlib fallback.

The hot path (``_chan_send`` / ``_recv_frame``) calls :func:`dumps` and
:func:`loads` per frame.  When ``orjson`` is installed the calls are 5-15×
faster than ``json``; the fallback keeps the protocol importable on
minimal environments (tests, CI without C extensions).

API contract (identical for both backends):

- ``dumps(obj) -> bytes``          — JSON object, **no** trailing newline
- ``dumps_sorted(obj) -> bytes``   — JSON object with sorted keys
- ``loads(data) -> object``        — ``data`` is ``bytes`` or ``str``
"""

from __future__ import annotations

try:
    import orjson as _fast

    def dumps(obj) -> bytes:
        return _fast.dumps(obj)

    def dumps_sorted(obj) -> bytes:
        return _fast.dumps(obj, option=_fast.OPT_SORT_KEYS)

    def loads(data) -> object:
        return _fast.loads(data)

    BACKEND = "orjson"

except ImportError:
    import json as _slow

    # COMPACT separators: the stdlib default writes ", " and ": " between
    # items — every frame carried the padding over the wire and the peer
    # parsed it back. The compact form is the same JSON (any parser
    # accepts it) with ~10-15 % fewer bytes on the wire.
    def dumps(obj) -> bytes:
        return _slow.dumps(obj, separators=(",", ":")).encode()

    def dumps_sorted(obj) -> bytes:
        return _slow.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

    def loads(data) -> object:
        return _slow.loads(data)

    BACKEND = "json"
