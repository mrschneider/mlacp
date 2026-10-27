import base64

from mlacp_core.authority import CapabilityChain
from mlacp_core.grid import CommunicationsGrid
from mlacp_core.messages import MAX_TTL, frame
from mlacp_engine.channels import LoopbackChannel
from mlacp_engine.node import CenterNode, _recv_frame, _chan_send

C1 = "mlacp:ministry/north/ct-1/center"
A = "mlacp:ministry/north/ct-1/dispatch"
B = "mlacp:ministry/north/ct-1/relay"


def node(**kw):
    return CenterNode(C1, **kw)


def bind(n, urn=A, conn=None, caps=None):
    return n.handle_frame(frame("hello", urn=urn, capabilities=caps or []), conn)


def test_hello_registers_and_replies():
    n = node()
    reply = bind(n, caps=["time"])
    assert reply["kind"] == "hello"
    assert A in reply["directory"]


def test_envelope_delivered_to_connected_service():
    n = node()
    a_ch, b_ch = LoopbackChannel().ends()
    bind(n, A, conn=a_ch)
    bind(n, B, conn=b_ch)
    # a sends to b: the node pushes the envelope into b's channel
    n.handle_frame(frame("envelope", sender=A, recipient=B, seq=1,
                         body={"text": "ping"}), conn=a_ch)
    got = _recv_frame(b_ch, timeout=2)
    assert got is not None and got["kind"] == "envelope"
    assert got["body"] == {"text": "ping"}
    assert any(j["event"] == "delivered" for j in n.journal)


def test_envelope_to_unknown_service_refused_in_protocol():
    n = node()
    reply = n.handle_frame(frame("envelope", sender=A,
                                 recipient="mlacp:ministry/south/ct-9/ghost",
                                 seq=1, body={}))
    assert reply["kind"] == "error"
    assert reply["code"] == "unknown_service"


def test_offline_recipient_takes_custody_and_dumps_on_recontact():
    n = node()
    a_ch, _ = LoopbackChannel().ends()
    bind(n, A, conn=a_ch)
    bind(n, B)  # b IS registered (known to the directory) but offline
    # b is NOT connected: custody
    reply = n.handle_frame(frame("envelope", sender=A, recipient=B, seq=1,
                                 body={"text": "hold this"}), conn=a_ch)
    assert reply == frame("custody_ack", bundle_id=f"bndl-{A}-1", status="held")

    # b re-registers: hello itself dumps the held envelope (in order), then
    # acknowledges — the recontact trigger lives on the bind path
    b_ch, _ = LoopbackChannel().ends()
    bind(n, B, conn=b_ch)
    got = _recv_frame(b_ch, timeout=2)
    assert got is not None and got["kind"] == "envelope"
    assert got["body"] == {"text": "hold this"}
    assert n.relay.pending_acks() == []  # ack releases custody
    assert any(j["event"] == "custody_dump" for j in n.journal)


def test_capability_guard_blocks_unauthorized_send():
    auth = CapabilityChain()
    auth.issue_root(A, ["send"])
    n = node(authority=auth)
    a_ch, _ = LoopbackChannel().ends()
    b_ch, _ = LoopbackChannel().ends()
    bind(n, A, conn=a_ch)
    bind(n, B, conn=b_ch)
    # sender B has no grant: sending with require_capability is refused
    reply = n.handle_frame(frame("envelope", sender=B, recipient=A, seq=1,
                                 body={}, require_capability="send"), conn=b_ch)
    assert reply["kind"] == "error"
    assert reply["code"] == "notpermitted"
    # and nothing was delivered
    assert _recv_frame(a_ch, timeout=0.2) is None


def test_secured_body_roundtrip_through_custody():
    key = bytes(range(32))
    n = node(link_key=key)
    a_ch, _ = LoopbackChannel().ends()
    bind(n, A, conn=a_ch)
    bind(n, B)  # registered but offline
    n.handle_frame(frame("envelope", sender=A, recipient=B, seq=1,
                         body={"secret": "zima-plan"}), conn=a_ch)
    held = n.relay.held_for(B)
    assert held and held[0].body["__secure__"] is True
    assert "zima-plan" not in str(held[0].body)  # body is ciphertext on the relay
    b_ch, _ = LoopbackChannel().ends()
    bind(n, B, conn=b_ch)
    n.on_recontact(B, conn=b_ch)
    got = _recv_frame(b_ch, timeout=2)
    assert got["body"] == {"secret": "zima-plan"}


def test_unknown_verb_answered_in_protocol():
    n = node()
    reply = n.handle_frame({"kind": "agent_step", "v": "1.0"})
    assert reply["kind"] == "error"
    assert reply["code"] == "unknownkind"
    assert "agent_step" in reply["message"]


def test_route_update_extends_grid():
    n = node()
    reply = n.handle_frame(frame("route_update", a="ct-1", b="ct-2",
                                 link="arterial", cost=1))
    assert reply["state"] == "acked"
    assert "ct-2" in n.grid.centers()
