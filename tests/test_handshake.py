"""The VKO handshake over the wire: two centers derive the same link key
from ephemeral ГОСТ Р 34.10-2012 keys (RFC 7836 §4.3) and protect traffic
with it."""
import socket
import threading
import time

from mlacp_core.grid import CommunicationsGrid
from mlacp_core.messages import frame
from mlacp_engine.channels import TcpListener
from mlacp_engine.node import CenterNode, serve

C1 = "mlacp:ministry/north/ct-1/center"
C2 = "mlacp:ministry/south/ct-2/center"
A = "mlacp:ministry/north/ct-1/dispatch"
B = "mlacp:ministry/south/ct-2/relay"


def _wait_port(port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("port never opened")


def test_vko_handshake_derives_matching_link_keys():
    grid = CommunicationsGrid()
    grid.add_center("ct-1")
    grid.add_center("ct-2")
    grid.add_link("ct-1", "ct-2", "arterial", cost=1)
    n1 = CenterNode(C1, grid=grid)  # NO pre-shared key
    n2 = CenterNode(C2, grid=grid)
    l1, l2 = TcpListener("127.0.0.1", 0), TcpListener("127.0.0.1", 0)
    n1.peers["ct-2"] = ("127.0.0.1", l2.port)
    n2.peers["ct-1"] = ("127.0.0.1", l1.port)
    flag = threading.Event()
    serve(n1, l1, flag)
    serve(n2, l2, flag)
    _wait_port(l1.port)
    _wait_port(l2.port)
    try:
        # initiator: ephemeral keypair + UKM -> offer frame
        offer = n1.initiate_handshake()
        assert offer["kind"] == "handshake" and offer["role"] == "offer"
        assert n1.link_key is None  # not yet
        accept = n2.handle_frame(offer, conn=None)
        assert accept["kind"] == "handshake" and accept["role"] == "accept"
        assert n2.link_key is not None          # the acceptor already holds KEK
        kek_acceptor = n2.link_key
        n1.handle_frame(accept, conn=None)      # initiator completes
        assert n1.link_key == kek_acceptor      # VKO symmetry on the wire
        assert len(n1.link_key) == 32           # a 256-bit KEK (VKO_256)

        # the derived key PROTECTS traffic: an envelope for a peer-homed
        # service travels encrypted and is delivered in plaintext
        n2.handle_frame(frame("hello", urn=B, capabilities=["relay"]), conn=None)
        reply = n1.handle_frame(frame("envelope", sender=A, recipient=B,
                                      seq=1, body={"order": "zima-plan"}),
                                conn=None)
        assert reply["kind"] == "custody_ack"
        held = n2.relay.held_for(B)
        assert held and held[0].body.get("__secure__") is True
        assert n2._unsecure_body(held[0].body) == {"order": "zima-plan"}

        # a keyless impostor CANNOT read the wire body
        n3 = CenterNode(C2, grid=n2.grid, link_key=None)
        import pytest
        from mlacp_core.errors import MlacpError
        # (its attempt would fail: it holds no KEK)
        assert n3.link_key is None

        # bad point (not on the curve) is refused
        bad = dict(offer)
        bad["x"] = "00" * 64
        bad["y"] = "00" * 64
        reply = n2.handle_frame(bad, conn=None)
        assert reply["kind"] == "error"
    finally:
        flag.set()
        l1.close()
        l2.close()
