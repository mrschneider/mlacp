#!/usr/bin/env python3
"""Repeatable crypto timings and VERIFIED successful local delivery.

python experiments/bench.py --iterations 50 --node-frames 2000
Set MLACP_PURE=1 to measure the pure Python reference (use fewer iterations).
"""
import argparse
import itertools
import json
import os
from pathlib import Path
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mlacp_core import gost
from mlacp_core.gost_ec import CURVE_512A, generate_keypair, vko
from mlacp_core.grid import CommunicationsGrid
from mlacp_core.directory import HierarchicalDirectory
from mlacp_engine.node import CenterNode


def bench(label, fn, n, repeats=3):
    fn()  # exclude one-time table initialization from steady-state timings
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        for _ in range(n):
            fn()
        samples.append((time.perf_counter() - start) / n * 1e6)
    print(f"  {label:38s} {statistics.median(samples):10.2f} us/call ({n} calls/run)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=20)
    parser.add_argument('--node-frames', type=int, default=2000)
    args = parser.parse_args()
    if args.iterations < 1 or args.node_frames < 1:
        parser.error('iteration and frame counts must be positive')
    key, message = bytes(range(32)), os.urandom(2048)
    nonces = itertools.count(1)
    def iv():
        return next(nonces).to_bytes(16, 'big')  # fresh valid MGM ICN per encryption
    ciphertext = gost.secure_encrypt(key, iv(), message)
    context = gost.SecureContext(key)
    assert bytes(context.decrypt(ciphertext)) == message
    data64k = os.urandom(65536)
    print(f'=== Crypto (native backend: {gost.NATIVE_BACKEND}) ===')
    bench('secure_encrypt 2KB', lambda: gost.secure_encrypt(key, iv(), message), args.iterations)
    bench('context.encrypt 2KB', lambda: context.encrypt(iv(), message), args.iterations)
    bench('secure_decrypt 2KB', lambda: gost.secure_decrypt(key, ciphertext), args.iterations)
    bench('context.decrypt 2KB', lambda: context.decrypt(ciphertext), args.iterations)
    bench('ctr_encrypt 2KB', lambda: gost.ctr_encrypt(key, iv(), message), args.iterations)
    bench('streebog_256 64KB', lambda: gost.streebog_256(data64k), args.iterations)
    bench('streebog_512 64KB', lambda: gost.streebog_512(data64k), args.iterations)
    def handshake():
        private, public = generate_keypair(CURVE_512A)
        peer_private, peer_public = generate_keypair(CURVE_512A)
        first = vko(CURVE_512A, private, peer_public, 1, bits=512)
        second = vko(CURVE_512A, peer_private, public, 1, bits=512)
        assert first == second
    bench('VKO_512 symmetric agreement', handshake, args.iterations)

    class Sink:
        delivered = 0
        def send(self, data):
            value = json.loads(data)
            assert value['kind'] == 'envelope'
            assert value['body'] == {'x': 1}
            self.delivered += 1
    grid = CommunicationsGrid()
    grid.add_center('n1')
    node = CenterNode('mlacp:o/z/n1/center', grid=grid,
                      directory=HierarchicalDirectory(org_quota=args.node_frames+1))
    sink = Sink()
    recipient = 'mlacp:o/z/n1/worker'
    assert node.handle_frame({'kind': 'hello', 'urn': recipient}, conn=sink)['kind'] == 'hello'
    start = time.perf_counter()
    for seq in range(args.node_frames):
        result = node.handle_frame({'kind': 'envelope',
            'sender': 'mlacp:o/z/n1/source', 'recipient': recipient,
            'seq': seq, 'body': {'x': 1}, 'ttl': 10})
        assert result is None, f'frame refused: {result}'
    elapsed = time.perf_counter()-start
    assert sink.delivered == args.node_frames
    node.close()
    print(f'  successful deliveries: {sink.delivered}/{args.node_frames}; '
          f'{elapsed/args.node_frames*1e6:.2f} us/frame; {args.node_frames/elapsed:.0f} frames/s')


if __name__ == '__main__':
    main()
