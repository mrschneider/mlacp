import pytest

from mlacp_core.addresses import Address
from mlacp_core.errors import BadAddress


def test_parse_and_roundtrip():
    a = Address.parse("mlacp:ministry/transport/rail-ct/dispatch")
    assert (a.org, a.zone, a.node, a.service) == ("ministry", "transport", "rail-ct", "dispatch")
    assert a.to_urn() == "mlacp:ministry/transport/rail-ct/dispatch"


def test_rejects_wrong_scheme():
    with pytest.raises(BadAddress):
        Address.parse("acnl:foo/bar/baz/qux")


def test_rejects_wrong_level_count():
    with pytest.raises(BadAddress):
        Address.parse("mlacp:org/zone/node")


def test_rejects_uppercase():
    with pytest.raises(BadAddress):
        Address.parse("mlacp:ORG/zone/node/svc")


def test_zone_widening_order():
    a = Address.parse("mlacp:ministry/transport/rail-ct/dispatch")
    assert a.widen_zones() == ["transport", "*"]


def test_parse_is_cached_identity():
    # The hot path parses the same URNs repeatedly; the cache must return the
    # exact same frozen instance (identity, not just equality) for repeated
    # parses of the same URN.
    a1 = Address.parse("mlacp:ministry/transport/rail-ct/dispatch")
    a2 = Address.parse("mlacp:ministry/transport/rail-ct/dispatch")
    assert a1 is a2


def test_parse_cache_does_not_break_validation():
    # A malformed URN must still raise even though it never enters the cache.
    with pytest.raises(BadAddress):
        Address.parse("mlacp:ORG/zone/node/svc")
