"""Epoch re-keying: fresh ephemerals on an ESTABLISHED link — forward
secrecy (the old key never protects new traffic) with an in-flight window
that tolerates the previous epoch during the transition."""
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


def _two_centers():
    grid = CommunicationsGrid()
    grid.add_center("ct-1")
    grid.add_center("ct-2")
    grid.add_link("ct-1", "ct-2", "arterial", cost=1)
    n1, n2 = CenterNode(C1, grid=grid), CenterNode(C2, grid=grid)
    l1, l2 = TcpListener("127.0.0.1", 0), TcpListener("127.0.0.1", 0)
    n1.peers["ct-2"] = ("127.0.0.1", l2.port)
    n2.peers["ct-1"] = ("127.0.0.1", l1.port)
    flag = threading.Event()
    serve(n1, l1, flag)
    serve(n2, l2, flag)
    _wait_port(l1.port)
    _wait_port(l2.port)
    return n1, n2, l1, l2, flag


def _handshake(n1, n2):
    n1.handle_frame(n2.handle_frame(n1.initiate_handshake(), conn=None),
                    conn=None)


def test_rekey_rotates_the_link_key_with_forward_secrecy():
    n1, n2, l1, l2, flag = _two_centers()
    try:
        _handshake(n1, n2)
        kek1 = n1.link_key
        assert kek1 == n2.link_key and n1._epoch == 1

        # epoch 2: fresh ephemerals, fresh KEK on both sides
        offer2 = n1.rekey()
        accept2 = n2.handle_frame(offer2, conn=None)
        n1.handle_frame(accept2, conn=None)
        kek2 = n1.link_key
        assert kek2 == n2.link_key          # still symmetric
        assert kek2 != kek1                 # fresh ephemerals -> fresh key
        assert n1._epoch == 2 and n2._epoch == 2
        assert kek1 in n1.link_keys         # in-flight window keeps the old one

        # FORWARD SECRECY: NEW traffic (post-re-key) is NOT decryptable
        # under the OLD key — a captor holding only kek1 learns nothing
        from mlacp_core.gost import secure_decrypt
        body = n2._secure_body(type(
            "E", (), {"body": {"order": "epoch-2 secret"}})())
        payload = __import__("base64").b64decode(body["payload"])
        with __import__("pytest").raises(ValueError):
            secure_decrypt(kek1, payload)     # the old key is USELESS here
        assert n2._unsecure_body(body) == {"order": "epoch-2 secret"}  # new key opens it

        # IN-FLIGHT WINDOW: a body encrypted with the OLD epoch (captured
        # before the re-key) still opens after the rotation
        old_body = {"__secure__": True, "payload": __import__("base64")
                    .b64encode(__import__("mlacp_core.gost", fromlist=[
                        "secure_encrypt"]).secure_encrypt(
                        kek1, b"\x01" + bytes(15),
                        b'{"order": "pre-rekey"}')).decode()}
        assert n2._unsecure_body(old_body) == {"order": "pre-rekey"}

        # REPLAY: re-submitting the SAME accept frame is a no-op — the
        # retransmission guard keeps no duplicate keys in the window
        keys_before = list(n2.link_keys)
        n2.handle_frame(accept2, conn=None)
        assert n2.link_keys == keys_before
    finally:
        flag.set()
        l1.close()
        l2.close()


def test_rekey_before_handshake_is_refused():
    n = CenterNode(C1)
    import pytest
    from mlacp_core.errors import BusinessRefusal
    with pytest.raises(BusinessRefusal):
        n.rekey()
