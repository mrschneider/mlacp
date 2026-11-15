"""The wire serializer: one contract, two backends.

The stdlib fallback must produce the SAME JSON as orjson (any parser
accepts both), and the canonical (``dumps_sorted``) form must stay
byte-stable — it is the MGM plaintext, so a different byte order would
change the ciphertext.
"""
import json

from mlacp_core import wire


def test_round_trip():
    value = {"kind": "envelope", "v": "1.0", "sender": "mlacp:o/z/n1/a",
             "body": {"x": 1, "text": "привет", "n": [1, 2, 3]}}
    raw = wire.dumps(value)
    assert isinstance(raw, bytes)
    assert wire.loads(raw) == value
    assert wire.loads(raw.decode()) == value


def test_the_wire_form_is_compact():
    """No padding between items: the stdlib default writes ", " and ": ",
    which put ~10-15 % of every frame's bytes on the wire."""
    raw = wire.dumps({"kind": "envelope", "body": {"a": 1, "b": 2}})
    assert b", " not in raw
    assert b": " not in raw
    assert raw == b'{"kind":"envelope","body":{"a":1,"b":2}}'


def test_the_canonical_form_is_sorted_and_stable():
    """``dumps_sorted`` is the MGM plaintext: the same value must always
    produce the same bytes, whatever the insertion order."""
    a = wire.dumps_sorted({"b": 1, "a": 2, "c": {"z": 1, "y": 2}})
    b = wire.dumps_sorted({"c": {"y": 2, "z": 1}, "a": 2, "b": 1})
    assert a == b
    assert a == b'{"a":2,"b":1,"c":{"y":2,"z":1}}'
    assert wire.loads(a) == {"a": 2, "b": 1, "c": {"y": 2, "z": 1}}


def test_both_backends_agree():
    """The stdlib fallback and orjson must produce the same JSON value
    (the compact separators are a formatting choice, not a schema)."""
    value = {"kind": "hello", "urn": "mlacp:o/z/n1/worker", "caps": ["a", "b"],
             "n": 42, "flag": True, "none": None}
    assert json.loads(wire.dumps(value).decode()) == value
    assert wire.BACKEND in ("orjson", "json")
