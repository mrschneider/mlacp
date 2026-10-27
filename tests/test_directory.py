import pytest

from mlacp_core.directory import HierarchicalDirectory
from mlacp_core.errors import DuplicateName, QuotaExceeded, UnknownService


def test_register_and_resolve():
    d = HierarchicalDirectory()
    d.register("mlacp:ministry/north/ct-1/time")
    e = d.resolve("mlacp:ministry/north/ct-1/time")
    assert e.org == "ministry"


def test_zone_widening_resolves_across_zones():
    d = HierarchicalDirectory()
    d.register("mlacp:ministry/north/ct-1/time")
    # the service moved to the south zone: same org/node/service
    assert d.resolve("mlacp:ministry/south/ct-1/time").zone == "north"


def test_unknown_service_refused_by_name():
    d = HierarchicalDirectory()
    with pytest.raises(UnknownService) as e:
        d.resolve("mlacp:ministry/north/ct-1/time")
    assert "mlacp:ministry/north/ct-1/time" in str(e.value)


def test_duplicate_registration_refused():
    d = HierarchicalDirectory()
    d.register("mlacp:ministry/north/ct-1/time")
    with pytest.raises(DuplicateName):
        d.register("mlacp:ministry/north/ct-1/time")


def test_query_by_capability():
    d = HierarchicalDirectory()
    d.register("mlacp:ministry/north/ct-1/time", ["time"])
    d.register("mlacp:ministry/north/ct-1/relay", ["relay"])
    assert [e.urn for e in d.query(lambda e: "time" in e.capabilities)] == [
        "mlacp:ministry/north/ct-1/time"]


def test_per_org_accounting_and_quota():
    d = HierarchicalDirectory(org_quota=3)
    d.register("mlacp:ministry/north/ct-1/time")
    for i in range(3):
        d.account("ministry")
    with pytest.raises(QuotaExceeded) as e:
        d.account("ministry")
    assert "ministry" in str(e.value)
    # a different organization has its own accounting window
    assert d.account("academy") == 1
