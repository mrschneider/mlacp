#!/usr/bin/env python3
"""MLACP end-to-end proof: a NODE.JS client (experiments/client.js) drives the
PYTHON reference center over TCP through every secondary plane:

1. register + directory (layer 4)
2. envelope ping-pong across the node (layers 1+4)
3. custody for a registered-offline service, dumped on return (layer 2)
4. typed refusals — unknown verb named and listed (closed vocabulary)

Run: python experiments/run_e2e.py
"""

import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mlacp_core.grid import CommunicationsGrid  # noqa: E402
from mlacp_engine.channels import TcpListener  # noqa: E402
from mlacp_engine.node import CenterNode, serve  # noqa: E402

C1 = "mlacp:ministry/north/ct-1/center"
NODE_URN = "mlacp:ministry/north/ct-1/center"
HERE = Path(__file__).parent


def wait_port(port: int, timeout: float = 5.0) -> None:
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("node did not open the port")


def run_client(scenario: str, *args: str) -> tuple[int, str]:
    cmd = ["node", str(HERE / "client.js"), str(PORT), scenario, *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="")
    return proc.returncode, proc.stdout


def main() -> int:
    global PORT
    listener = TcpListener("127.0.0.1", 0)
    PORT = listener.port
    grid = CommunicationsGrid()
    grid.add_center("ct-1")
    node = CenterNode(C1, grid=grid)
    run_flag = __import__("threading").Event()
    serve(node, listener, run_flag)
    wait_port(PORT)
    print(f"[mlacp] node up on 127.0.0.1:{PORT} as {C1}")

    failed = 0

    # scenario 0: register the relay service so it is known-but-offline
    code, _ = run_client("register", NODE_URN)
    failed += code != 0
    assert any(e["event"] == "hello" for e in node.journal)

    # scenario 1: envelope ping-pong
    code, _ = run_client("ping")
    failed += code != 0

    # scenario 2: custody for the offline relay
    code, _ = run_client("custody")
    failed += code != 0
    held = [j for j in node.journal if j["event"] == "custody_dump"]
    if not held or held[0]["count"] != 1:
        print("FAIL: the node did not journal the custody dump")
        failed += 1
    else:
        print("PASS: node journal shows the custody dump (1 bundle)")

    # scenario 3: refusals
    code, _ = run_client("refusals")
    failed += code != 0

    # in-protocol ledger check: every refusal is a typed error frame
    errors = [j for j in node.journal if j["event"] == "error"]
    if len(errors) >= 2:
        print(f"PASS: {len(errors)} refusals journaled with typed codes: "
              + ", ".join(sorted({e['code'] for e in errors})))
    else:
        print("FAIL: expected typed refusals in the journal")
        failed += 1

    run_flag.set()
    listener.close()
    print(f"\nEXPERIMENT_MLACP_E2E: {'PASS' if failed == 0 else 'FAIL'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
