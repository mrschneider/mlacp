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
