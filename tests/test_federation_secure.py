"""Inter-center encrypted envelopes over the wire (layer 6 over layer 1)."""
import socket
import threading
import time

import pytest

from mlacp_core.grid import CommunicationsGrid
from mlacp_core.messages import frame
from mlacp_engine.channels import TcpListener
from mlacp_engine.node import CenterNode, _chan_send, _recv_frame, serve

C1 = "mlacp:ministry/north/ct-1/center"
C2 = "mlacp:ministry/south/ct-2/center"
A = "mlacp:ministry/north/ct-1/dispatch"
B = "mlacp:ministry/south/ct-2/relay"
LINK_KEY = bytes(range(32))


def _wait_port(port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("port never opened")


def _two_centers(link_key):
    grid = CommunicationsGrid()
    grid.add_center("ct-1")
    grid.add_center("ct-2")
    grid.add_link("ct-1", "ct-2", "arterial", cost=1)
    n1 = CenterNode(C1, grid=grid, link_key=link_key)
    n2 = CenterNode(C2, grid=grid, link_key=link_key)
    l1, l2 = TcpListener("127.0.0.1", 0), TcpListener("127.0.0.1", 0)
    n1.peers["ct-2"] = ("127.0.0.1", l2.port)
    n2.peers["ct-1"] = ("127.0.0.1", l1.port)
    flag = threading.Event()
    serve(n1, l1, flag)
    serve(n2, l2, flag)
    _wait_port(l1.port)
    _wait_port(l2.port)
    return n1, n2, l1, l2, flag


@pytest.mark.parametrize("key", [LINK_KEY, None],
                         ids=["secure", "plaintext"])
def test_inter_center_envelope_delivery(key):
    """An envelope for a peer-homed service is forwarded, delivered, and
    acknowledged hop-by-hop — encrypted when a link key binds the centers."""
    n1, n2, l1, l2, flag = _two_centers(key)
    try:
        n2.handle_frame(frame("hello", urn=B, capabilities=["relay"]), conn=None)
        reply = n1.handle_frame(frame("envelope", sender=A, recipient=B,
                                      seq=1, body={"order": "zima-plan"}),
                                conn=None)
        assert reply["kind"] == "custody_ack"
        # the addressee is offline at ct-2 -> hop custody TAKEN (Strela rule)
        assert reply["status"] == "held"
        held = n2.relay.held_for(B)
        if key is not None:
            # the wire body was opened in transit, but AT REST custody is
            # encrypted again with ct-2's link key
            assert held[0].body.get("__secure__") is True
            assert n2._unsecure_body(held[0].body) == {"order": "zima-plan"}
        else:
            assert held[0].body["order"] == "zima-plan"
    finally:
        flag.set()
        l1.close()
        l2.close()


def test_wire_body_is_encrypted_in_flight():
    """Sniffing the actual wire frame: with a shared link key the forwarded
    body is an MGM secure frame, never the plaintext."""
    n1, n2, l1, l2, flag = _two_centers(LINK_KEY)
    try:
        n2.handle_frame(frame("hello", urn=B, capabilities=["relay"]), conn=None)
        # a capturing proxy: connect, send the forwarded frame manually by
        # calling the handler path but intercepting at the wire level
        import json
        seen = {}

        orig_forward = n1._forward_to_center

        def spy_forward(center, forwarded):
            seen["wire"] = forwarded
            return orig_forward(center, forwarded)

        n1._forward_to_center = spy_forward
        n1.handle_frame(frame("envelope", sender=A, recipient=B, seq=1,
                              body={"order": "zima-plan"}), conn=None)
        wire_body = seen["wire"]["body"]
        assert wire_body.get("__secure__") is True
        assert "zima-plan" not in json.dumps(seen["wire"])
        # and ct-2 still TAKES custody — encrypted at rest, plaintext inside
        held = n2.relay.held_for(B)
        assert held and n2._unsecure_body(held[0].body) == {"order": "zima-plan"}
    finally:
        flag.set()
        l1.close()
        l2.close()


def test_secure_without_key_is_refused():
    """A node WITHOUT the link key cannot open a secure body."""
    n1, n2, l1, l2, flag = _two_centers(LINK_KEY)
    try:
        n2b = CenterNode(C2, grid=n2.grid, link_key=None)  # keyless impostor
        from mlacp_core.gost import secure_encrypt
        payload = secure_encrypt(LINK_KEY, b"\x01" + bytes(15),
                                 b'{"order": "zima-plan"}')
        reply = n2b.handle_frame(frame(
            "envelope", sender=A, recipient=B, seq=1, via="center",
            body={"__secure__": True,
                  "payload": __import__("base64").b64encode(payload).decode()}),
            conn=None)
        assert reply["kind"] == "error"
        assert reply["code"] == "notpermitted"
    finally:
        flag.set()
        l1.close()
        l2.close()
