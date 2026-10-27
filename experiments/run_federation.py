#!/usr/bin/env python3
"""MLACP federation E2E: TWO communications centers (ct-1 in Moscow, ct-2 in
Vladivostok) linked by an arterial route (layer 3), each serving its own
services. A NODE.JS client binds to ct-1 and sends an envelope addressed to a
service homed on ct-2; ct-1 forwards it over the primary network, ct-2
delivers it locally and answers the hop-by-hop custody_ack (the Strela rule).

Also exercised: UDS as the primary network for ct-2's own clients (layer 1
media heterogeneity).

Run: python experiments/run_federation.py  (requires Node.js >= 18)
"""

import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mlacp_core.grid import CommunicationsGrid  # noqa: E402
from mlacp_engine.channels import TcpListener, UnixListener, unix_client  # noqa: E402
from mlacp_engine.node import CenterNode, serve  # noqa: E402

HERE = Path(__file__).parent
C1 = "mlacp:ministry/north/ct-1/center"
C2 = "mlacp:ministry/south/ct-2/center"
A = "mlacp:ministry/north/ct-1/dispatch"
B = "mlacp:ministry/south/ct-2/relay"
UDS_PATH = "/tmp/mlacp_fed_ct2.sock"


def wait_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("node did not open the port")


def run_client(scenario: str, *args: str) -> tuple[int, str]:
    cmd = ["node", str(HERE / "client.js"), str(PORT1), scenario, *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="")
    return proc.returncode, proc.stdout


PORT1 = 0


def main() -> int:
    global PORT1
    failed = 0

    grid = CommunicationsGrid()
    grid.add_center("ct-1")
    grid.add_center("ct-2")
    grid.add_link("ct-1", "ct-2", "arterial", cost=1)

    node1 = CenterNode(C1, grid=grid)
    node2 = CenterNode(C2, grid=grid)

    listener1 = TcpListener("127.0.0.1", 0)
    PORT1 = listener1.port
    listener2 = TcpListener("127.0.0.1", 0)
    node1.peers["ct-2"] = ("127.0.0.1", listener2.port)
    node2.peers["ct-1"] = ("127.0.0.1", PORT1)

    flag = threading.Event()
    serve(node1, listener1, flag)
    serve(node2, listener2, flag)
    wait_port(PORT1)
    wait_port(listener2.port)
    print(f"[mlacp] ct-1 up on :{PORT1}, ct-2 up on :{listener2.port}")

    # the relay service registers at ct-2 (its home center)
    conn2 = unix_client(UDS_PATH) if False else None
    # ct-2 also serves a UDS channel (layer 1: heterogeneous media)
    uds_listener = UnixListener(UDS_PATH)
    serve(node2, uds_listener, flag)

    # scenario: register the relay service AT ct-2 through the UDS channel
    uds_ch = unix_client(UDS_PATH)
    uds_ch.send(b'{"kind": "hello", "v": "1.0", "urn": "%s", "capabilities": ["relay"]}\n'
                % B.encode())
    buf = b""
    while b"\n" not in buf:
        buf += uds_ch.recv(2) or b""
    hello_reply = buf.partition(b"\n")[0]
    if B.encode() in hello_reply:
        print("PASS: federation: relay service registered at ct-2 over UDS")
    else:
        print(f"FAIL: registration reply: {hello_reply[:120]}")
        failed += 1

    # the Node client binds at ct-1 and sends an envelope for ct-2's service:
    # ct-1 must forward it through the arterial route and relay the custody_ack
    code, out = run_client("federate", C1, B)
    failed += code != 0

    # the journal must show the delivery happened at ct-2 (not ct-1)
    if any(j["event"] == "delivered" and "ct-2" in j["recipient"] for j in node2.journal):
        print("PASS: ct-2 journal shows the local delivery")
    else:
        print("FAIL: ct-2 never delivered the forwarded envelope")
        failed += 1

    flag.set()
    listener1.close()
    listener2.close()
    uds_listener.close()
    print(f"\nEXPERIMENT_MLACP_FEDERATION: {'PASS' if failed == 0 else 'FAIL'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
