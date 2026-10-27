import pytest

from mlacp_core.errors import InfrastructureFailure, UnknownKind, VersionMismatch, malformed
from mlacp_core.messages import MAX_TTL, Bundle, Envelope, frame, parse_frame


def test_frame_unknown_verb_refused_by_name():
    with pytest.raises(UnknownKind) as e:
        frame("agent_step")
    assert "agent_step" in str(e.value)
    assert "envelope" in str(e.value)  # the legal set is listed


def test_parse_frame_major_version_refused():
    f = frame("envelope", sender="mlacp:a/z/n/s", recipient="mlacp:a/z/n/t",
              seq=1, body={})
    f["v"] = "2.0"
    with pytest.raises(VersionMismatch):
        parse_frame(f)


def test_parse_frame_minor_version_accepted():
    f = frame("envelope", sender="mlacp:a/z/n/s", recipient="mlacp:a/z/n/t",
              seq=1, body={})
    f["v"] = "1.7"
    kind, _ = parse_frame(f)
    assert kind == "envelope"


def test_envelope_missing_fields_all_listed():
    with pytest.raises(InfrastructureFailure) as e:
        Envelope.from_value({"sender": "mlacp:a/z/n/s"})
    assert "recipient" in str(e.value)
    assert "seq" in str(e.value)
    assert "body" in str(e.value)


def test_envelope_ttl_bounds():
    with pytest.raises(InfrastructureFailure):
        Envelope.from_value({"sender": "mlacp:a/z/n/s", "recipient": "mlacp:a/z/n/t",
                             "seq": 1, "body": {}, "ttl": MAX_TTL + 1})


def test_bundle_roundtrip():
    b = Bundle("b1", "mlacp:a/z/n/svc", 3, {"k": 1}, "mlacp:a/z/n/origin", 7)
    assert Bundle.from_value(b.to_value()) == b


def test_bundle_rejects_bad_ttl():
    with pytest.raises(InfrastructureFailure):
        Bundle.from_value({"bundle_id": "b", "addressee": "mlacp:a/z/n/s",
                           "ttl": 0, "body": {}, "origin": "mlacp:a/z/n/o",
                           "seq": 1})
