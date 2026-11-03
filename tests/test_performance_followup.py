"""Regression coverage for indexed state, persistent peers and crypto contexts."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from unittest.mock import patch

import pytest
from mlacp_core.authority import CapabilityChain
from mlacp_core.custody import CustodyRelay
from mlacp_core.directory import HierarchicalDirectory
from mlacp_core.errors import BusinessRefusal, InfrastructureFailure, NotPermitted, UnknownService
from mlacp_core.grid import CommunicationsGrid, NoRoute
from mlacp_core.messages import Bundle, frame
from mlacp_core import gost
from mlacp_engine.channels import TcpListener, PeerConnectionPool
from mlacp_engine.node import CenterNode, serve, _recv_frame


def test_deep_revocation_is_iterative_and_does_not_kill_unrelated_grants():
    chain = CapabilityChain(history_limit=5)
    root = chain.issue_root('root', ['send'])
    parent = root
    for i in range(2000):
        parent = chain.delegate(parent, f'holder{i}', ['send'])
    other = chain.issue_root('other', ['send'])
    assert chain.revoke(root) == 2001
    assert chain.revoke(root) == 0
    with pytest.raises(NotPermitted):
        chain.authorize('holder1999', 'send')
    assert chain.authorize('other', 'send').grant_id == other
    assert len(chain.history()) == 5


def test_authority_preserves_first_live_grant_and_cascade_history():
    chain = CapabilityChain()
    root = chain.issue_root('same', ['send'])
    second = chain.issue_root('same', ['send'])
    child = chain.delegate(root, 'child', ['send'])
    assert chain.authorize('same', 'send').grant_id == root
    assert chain.revoke(root) == 2
    assert chain.authorize('same', 'send').grant_id == second
    assert chain.history()[-2:] == [f'revoke {child} (cascade=1)', f'revoke {root} (cascade=2)']


def test_directory_precedence_removal_and_reregistration():
    directory = HierarchicalDirectory()
    north = 'mlacp:o/north/n/s'
    south = 'mlacp:o/south/n/s'
    directory.register(north)
    directory.register(south)
    assert directory.resolve(south).urn == south
    assert directory.resolve('mlacp:o/other/n/s').urn == north
    directory.unregister(north)
    assert directory.resolve('mlacp:o/other/n/s').urn == south
    directory.register(north)
    assert directory.resolve('mlacp:o/other/n/s').urn == south
    directory.unregister(north)
    directory.unregister(south)
    with pytest.raises(UnknownService):
        directory.resolve(north)


def test_weighted_next_hop_zero_cost_and_topology_changes():
    grid = CommunicationsGrid()
    grid.add_link('a', 'c', cost=100)
    grid.add_link('a', 'b', cost=1)
    grid.add_link('b', 'c', cost=1)
    assert grid.route('a', 'c') == ['a', 'b', 'c']
    assert grid.next_hop('a', 'c') == 'b'
    grid.add_link('a', 'c', cost=0)
    assert grid.next_hop('a', 'c') == 'c'
    assert grid.route('a', 'a') == ['a']
    grid.management_tick(); grid.management_tick(); grid.management_tick()
    grid.mark_heard('a')
    assert set(grid.management_tick()) == {'b', 'c'}
    with pytest.raises(NoRoute):
        grid.next_hop('a', 'c')
    with pytest.raises(BusinessRefusal):
        grid.add_link('a', 'c', cost=-1)


def test_routing_ties_are_deterministic():
    grid = CommunicationsGrid()
    for a, b in [('a', 'c'), ('c', 'd'), ('a', 'b'), ('b', 'd')]:
        grid.add_link(a, b)
    assert grid.route('a', 'd') == ['a', 'b', 'd']
    assert grid.route_diversity('a', 'd') == 2


def bundle(bid, addressee='a', ttl=3, seq=0):
    return Bundle(bid, addressee, ttl, {}, 'source', seq)


def test_custody_order_ack_capacity_idempotency_and_expiry():
    relay = CustodyRelay(capacity=3)
    relay.accept(bundle('first', seq=2))
    relay.accept(bundle('second', seq=1))
    relay.accept(bundle('other', addressee='other', ttl=1))
    assert relay.accept(bundle('first')) == 'first'  # even at capacity
    assert [b.bundle_id for b in relay.contact('a')] == ['second', 'first']
    assert len(relay) == 3
    assert relay.pending_acks() == ['first', 'second']
    relay.acknowledge('first')
    assert relay.age_one_window() == ['other']
    assert relay.held_for('other') == []
    relay.acknowledge('second')
    assert len(relay) == 0
    assert not relay._by_addressee


def test_custody_contact_expires_admitted_zero_ttl_elsewhere():
    relay = CustodyRelay()
    relay.accept(bundle('expired', addressee='elsewhere', ttl=0))
    assert relay.contact('absent') == []
    assert len(relay) == 0
    assert not relay._expired_ids


def test_journal_and_history_retention_do_not_remove_authority():
    node = CenterNode('mlacp:o/z/n/s', journal_limit=2)
    for i in range(100):
        node._jour('delivery', seq=i)
    assert [entry['seq'] for entry in node.journal] == [98, 99]
    chain = CapabilityChain(history_limit=0)
    root = chain.issue_root('holder', ['send'])
    assert chain.history() == []
    assert chain.authorize('holder', 'send').grant_id == root
    chain.revoke(root)
    with pytest.raises(NotPermitted):
        chain.authorize('holder', 'send')
    node.close()


@pytest.mark.parametrize('size', [0, 1, 16, 33, 2048])
def test_context_matches_reference_and_refuses_tampering(size):
    key, iv = bytes(range(32)), bytes(range(16))
    data = b'x' * size
    context = gost.SecureContext(key)
    encrypted = bytes(context.encrypt(iv, data))
    assert encrypted == bytes(gost._pure_secure_encrypt(key, iv, data))
    assert bytes(context.decrypt(encrypted)) == data
    altered = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
    with pytest.raises(ValueError):
        context.decrypt(altered)
    with pytest.raises(ValueError):
        context.encrypt(b'\xff'*16, data)
    with pytest.raises(ValueError):
        context.decrypt(b'truncated')


def test_node_contexts_are_bounded_and_use_fresh_ivs():
    from mlacp_core.messages import Envelope
    node = CenterNode('mlacp:o/z/n/s', link_key=bytes(32))
    env = Envelope('mlacp:o/z/n/a', 'mlacp:o/z/n/b', 1, {'x': 1})
    first, second = node._secure_body(env), node._secure_body(env)
    assert first != second
    assert node._unsecure_body(first) == {'x': 1}
    for i in range(1, 6):
        key = bytes([i])*32
        node._adopt_link_key(key, i+1, 'offer', 'test', 1)
        node._secure_body(env)
    assert len(node._crypto_contexts) == 3
    assert len(node.link_keys) == 3
    assert set(node._crypto_contexts) <= set(node.link_keys)
    node.close()


class CountingListener(TcpListener):
    accepted = 0
    def accept(self, timeout=None):
        chan = super().accept(timeout)
        if chan is not None:
            self.accepted += 1
        return chan


@contextmanager
def running_center(max_connections=64):
    node = CenterNode('mlacp:o/z/peer/s')
    node._handlers['hello'] = lambda f, conn: frame('hello', n=f.get('n'))
    listener = CountingListener()
    stop = threading.Event()
    worker = serve(node, listener, stop, max_connections=max_connections)
    try:
        yield node, listener
    finally:
        stop.set(); listener.close(); worker.join(timeout=3)
        assert not worker.is_alive()


def test_peer_reuse_serializes_concurrent_exchanges_and_closes_resources():
    with running_center() as (_, listener):
        node = CenterNode('mlacp:o/z/local/s')
        node.peers['peer'] = ('127.0.0.1', listener.port)
        try:
            with ThreadPoolExecutor(max_workers=8) as workers:
                replies = list(workers.map(lambda n: node._forward_to_center('peer', frame('hello', n=n)), range(20)))
            assert [reply['n'] for reply in replies] == list(range(20))
            assert listener.accepted == 1
        finally:
            node.close()
        assert not node._peer_pool._entries


def test_peer_idle_eviction_and_capacity():
    with running_center() as (_, listener):
        node = CenterNode('mlacp:o/z/local/s', peer_capacity=1)
        address = ('127.0.0.1', listener.port)
        node.peers['peer'] = address
        try:
            node._forward_to_center('peer', frame('hello'))
            now = node._peer_pool._clock()
            with patch.object(node._peer_pool, '_clock', return_value=now+20):
                node._peer_pool.close_idle()
            assert not node._peer_pool._entries
            node._forward_to_center('peer', frame('hello'))
            assert listener.accepted == 2
            with node._peer_pool.connection('peer', address):
                with pytest.raises(InfrastructureFailure):
                    with node._peer_pool.connection('other', address):
                        pass
        finally:
            node.close()


def test_failed_exchange_is_not_retried_but_next_call_reconnects():
    with running_center() as (peer, listener):
        calls = []
        def fail_after_receive(f, conn):
            calls.append(f)
            raise OSError('ambiguous delivery')
        peer._handlers['hello'] = fail_after_receive
        node = CenterNode('mlacp:o/z/local/s')
        node.peers['peer'] = ('127.0.0.1', listener.port)
        try:
            with pytest.raises(InfrastructureFailure):
                node._forward_to_center('peer', frame('hello'))
            assert len(calls) == 1
            peer._handlers['hello'] = lambda f, conn: frame('hello')
            assert node._forward_to_center('peer', frame('hello'))['kind'] == 'hello'
            assert listener.accepted == 2
        finally:
            node.close()


def test_server_connection_limit_rejects_extra_connection():
    with running_center(max_connections=1) as (_, listener):
        node = CenterNode('mlacp:o/z/local/s')
        address = ('127.0.0.1', listener.port)
        node.peers['one'] = address; node.peers['two'] = address
        try:
            node._forward_to_center('one', frame('hello'))
            with pytest.raises(InfrastructureFailure):
                node._forward_to_center('two', frame('hello'))
        finally:
            node.close()


def test_partial_json_frame_survives_receive_timeout():
    class Channel:
        chunks = iter([b'{"kind":', None, b'"hello"}\n'])
        def recv(self, timeout):
            return next(self.chunks)
    channel = Channel()
    assert _recv_frame(channel, .1) is None
    assert _recv_frame(channel, .1) == {'kind': 'hello'}


def test_benchmark_counts_successful_frames_and_real_iterations():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root/'experiments/bench.py'),
                             '--iterations', '1', '--node-frames', '10'],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert 'successful deliveries: 10/10' in result.stdout
    assert '(1 calls/run)' in result.stdout
