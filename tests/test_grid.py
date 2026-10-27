import pytest

from mlacp_core.errors import BusinessRefusal
from mlacp_core.grid import CommunicationsGrid, NoRoute


def grid():
    g = CommunicationsGrid()
    # arterial spine moskva -> omsk -> vladivostok; lateral omsk-taishet bypass
    g.add_link("moskva", "omsk", "arterial", cost=1)
    g.add_link("omsk", "vladivostok", "arterial", cost=1)
    g.add_link("omsk", "taishet", "lateral", cost=2)
    g.add_link("taishet", "vladivostok", "lateral", cost=2)
    return g


def test_arterial_route_preferred():
    g = grid()
    assert g.route("moskva", "vladivostok") == ["moskva", "omsk", "vladivostok"]


def test_route_diversity_counts_arterials():
    g = grid()
    assert g.route_diversity("moskva", "vladivostok") == 1  # one arterial spine


def test_route_diversity_zero_without_links():
    g = CommunicationsGrid()
    g.add_center("a")
    g.add_center("b")
    assert g.route_diversity("a", "b") == 0


def test_no_route_names_the_center():
    g = grid()
    with pytest.raises(NoRoute) as e:
        g.route("moskva", "petropavlovsk")
    assert "petropavlovsk" in str(e.value)


def test_link_kind_validated():
    g = CommunicationsGrid()
    with pytest.raises(BusinessRefusal):
        g.add_link("a", "b", "pipe")


def test_autonomous_decay_drops_silent_center():
    g = grid()
    g.mark_heard("omsk")
    g.mark_heard("vladivostok")
    # moskva never heard from again
    removed: list[str] = []
    for _ in range(g.decay_after + 2):
        removed += g.management_tick()
        g.mark_heard("omsk")
        g.mark_heard("vladivostok")
    assert "moskva" in removed
    assert "moskva" not in g.centers()
    with pytest.raises(NoRoute):
        g.route("omsk", "moskva")


def test_heard_center_survives_decay():
    g = grid()
    for _ in range(10):
        g.management_tick()
        g.mark_heard("omsk")   # omsk keeps answering the management plane
    assert "omsk" in g.centers()
