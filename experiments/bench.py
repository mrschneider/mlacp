#!/usr/bin/env python3
"""Micro-benchmarks for the MLACP hot paths: GOST crypto + node frame throughput.

Run: python experiments/bench.py
"""
import sys, time, os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mlacp_core import gost
from mlacp_core.gost import (secure_encrypt, secure_decrypt, ctr_encrypt,
                             streebog_256, streebog_512, mgm_encrypt)
from mlacp_core.gost_ec import CURVE_512A, generate_keypair, vko
from mlacp_core.grid import CommunicationsGrid
from mlacp_engine.node import CenterNode

NATIVE = gost.NATIVE_BACKEND
KEY = bytes(range(32))
IV = bytes(range(16))
MSG = os.urandom(2048)

def bench(label, fn, n=200):
    t = time.perf_counter(); fn(); dt = time.perf_counter() - t
    print(f"  {label:42s} {dt/n*1e6:8.2f} us/call  (native={NATIVE})")

print(f"=== GOST crypto (native backend: {NATIVE}) ===")
bench("secure_encrypt 2KB", lambda: secure_encrypt(KEY, IV, MSG))
bench("secure_decrypt 2KB", lambda: secure_decrypt(KEY, secure_encrypt(KEY, IV, MSG)))
bench("ctr_encrypt 2KB", lambda: ctr_encrypt(KEY, IV, MSG))
bench("streebog_256 64KB", lambda: streebog_256(os.urandom(65536)))
bench("streebog_512 64KB", lambda: streebog_512(os.urandom(65536)))
print("=== GOST EC (VKO handshake) ===")
def do_vko():
    d, pub = generate_keypair(CURVE_512A)
    peer = (pub[0] ^ 1, pub[1])
    vko(CURVE_512A, d, peer, 1, bits=512)
bench("VKO_512 full handshake", do_vko, n=50)

print("=== Node frame throughput (envelope, no crypto) ===")
def node_bench():
    grid = CommunicationsGrid()
    grid.add_center("n1")
    node = CenterNode("mlacp:o/n/n1/center", grid=grid)
    node.directory.register("mlacp:o/n/svc/center", [])
    env = {"kind": "envelope", "v": "1.0",
           "sender": "mlacp:o/n/a/center", "recipient": "mlacp:o/n/svc/center",
           "seq": 1, "body": {"x": 1}}
    n = 2000
    t = time.perf_counter()
    for _ in range(n):
        node.handle_frame(env)
    dt = time.perf_counter() - t
    print(f"  node.handle_frame envelope: {dt/n*1e6:8.2f} us/call  ({n/dt:.0f} fr/s)")

node_bench()
