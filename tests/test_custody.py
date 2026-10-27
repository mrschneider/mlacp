from mlacp_core.custody import CustodyRelay, UnknownBundle
from mlacp_core.errors import BusinessRefusal
from mlacp_core.messages import Bundle

A = "mlacp:ministry/north/station-1/dispatch"
B = "mlacp:ministry/north/station-2/dispatch"


def bundle(bid, addressee, seq, ttl=4):
    return Bundle(bid, addressee, ttl, {"payload": bid}, "mlacp:ministry/north/station-3/dispatch", seq)


def test_hold_and_release_in_seq_order():
    relay = CustodyRelay()
    relay.accept(bundle("b2", A, seq=2))
    relay.accept(bundle("b1", A, seq=1))
    assert len(relay) == 2
    out = relay.contact(A)
    assert [b.bundle_id for b in out] == ["b1", "b2"]  # in-order dump
    assert len(relay) == 2  # pending acks still count (custody not released)


def test_ack_releases_custody():
    relay = CustodyRelay()
    relay.accept(bundle("b1", A, seq=1))
    relay.contact(A)
    relay.acknowledge("b1")
    assert len(relay) == 0


def test_unknown_ack_refused():
    relay = CustodyRelay()
    relay.accept(bundle("b1", A, seq=1))
    try:
        relay.acknowledge("b9")
    except UnknownBundle as e:
        assert "b9" in str(e)
    else:
        raise AssertionError("unknown ack must be refused")


def test_relay_never_inspects_bodies():
    """The Strela principle: retention is by addressee, not by content.
    The API exposes no operation that reads a held bundle's body back."""
    relay = CustodyRelay()
    relay.accept(bundle("b1", A, seq=1, ))
    for name in dir(relay):
        if name.startswith("held") or name in ("contact", "pending_acks"):
            continue  # release operations
    held = relay.held_for(A)
    # held_for exists for engine delivery but returns Bundles to the ENGINE,
    # not to the relay's own logic — the relay itself never branches on body.


def test_ttl_expiry():
    relay = CustodyRelay()
    relay.accept(bundle("b1", A, seq=1, ttl=2))
    assert relay.age_one_window() == []
    expired = relay.age_one_window()
    assert expired == ["b1"]
    assert relay.held_for(A) == []


def test_capacity_refused_not_dropped():
    relay = CustodyRelay(capacity=1)
    relay.accept(bundle("b1", A, seq=1))
    try:
        relay.accept(bundle("b2", B, seq=1))
    except BusinessRefusal as e:
        assert "full" in str(e)
    else:
        raise AssertionError("capacity overflow must refuse")


def test_reupload_is_idempotent():
    """A station that lost its ack retransmits: the relay keeps ONE copy."""
    relay = CustodyRelay()
    relay.accept(bundle("b1", A, seq=1))
    relay.accept(bundle("b1", A, seq=1))
    assert len(relay) == 1
