"""MLACP layer 1 — the primary network: channels.

The ЕАСС doctrine: a primary network of generic channels carrying NO service
semantics, with secondary planes layered on top. A Channel moves bytes and
knows nothing about messages; the same secondary plane (node.py) rides any
channel. Three adapters with deliberately different capabilities:

- ``TcpChannel``   — real network, many clients (durable across processes)
- ``LoopbackChannel`` — in-process pair, zero infrastructure (tests)
- the UDS variant is exercised through TcpChannel on localhost in the E2E
"""

from __future__ import annotations

import socket
import threading
from collections import deque
from dataclasses import dataclass, field


@dataclass
class LoopbackChannel:
    """A connection stub inside one process with MAILBOX semantics: bytes
    sent on an end are read back on that same end. This matches how the
    node uses a connection object — the node holds one end per peer and
    'sends on it' meaning 'transmits to that peer'; the test (or the peer
    thread) reads the same mailbox. Ends are independent mailboxes."""

    _a: deque = field(default_factory=deque)
    _b: deque = field(default_factory=deque)
    _cv: threading.Condition = field(default_factory=threading.Condition)

    def ends(self):
        return _LoopEnd(self, "a"), _LoopEnd(self, "b")

    def _send(self, side: str, data: bytes) -> None:
        q = self._a if side == "a" else self._b
        with self._cv:
            q.append(data)
            self._cv.notify_all()

    def _recv(self, side: str, timeout: float | None) -> bytes | None:
        q = self._a if side == "a" else self._b
        with self._cv:
            if not q and timeout is not None:
                self._cv.wait(timeout)
            return q.popleft() if q else None


class _LoopEnd:
    def __init__(self, channel: LoopbackChannel, side: str):
        self._channel = channel
        self._side = side

    def send(self, data: bytes) -> None:
        self._channel._send(self._side, data)

    def recv(self, timeout: float | None = None) -> bytes | None:
        return self._channel._recv(self._side, timeout)

    def close(self) -> None:  # parity with the socket API
        pass


class TcpChannel:
    """A TCP connection wrapped in the Channel interface (non-blocking-friendly
    with a recv timeout)."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.eof = False
        self._send_lock = threading.Lock()

    def send(self, data: bytes) -> None:
        with self._send_lock:
            self.sock.sendall(data)

    def recv(self, timeout: float | None = None) -> bytes | None:
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(65536)
        except (socket.timeout, TimeoutError):
            return None
        if not data:
            self.eof = True
        return data or None

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class UnixChannel:
    """A UDS connection wrapped in the Channel interface."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.eof = False
        self._send_lock = threading.Lock()

    def send(self, data: bytes) -> None:
        with self._send_lock:
            self.sock.sendall(data)

    def recv(self, timeout: float | None = None) -> bytes | None:
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(65536)
        except (socket.timeout, TimeoutError):
            return None
        if not data:
            self.eof = True
        return data or None

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class UnixListener:
    """Binds a unix socket path and yields UnixChannel connections."""

    def __init__(self, path: str, backlog: int = 16):
        import os
        self.path = path
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(backlog)

    def accept(self, timeout: float | None = None) -> UnixChannel | None:
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            conn, _ = self.sock.accept()
        except (socket.timeout, TimeoutError):
            return None
        return UnixChannel(conn)

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def unix_client(path: str) -> UnixChannel:
    """Connect to a UDS listening center."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    return UnixChannel(sock)


class TcpListener:
    """Binds a port and yields TcpChannel connections (the center's access
    point on the primary network)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]

    def accept(self, timeout: float | None = None) -> TcpChannel | None:
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            conn, _ = self.sock.accept()
        except (socket.timeout, TimeoutError):
            return None
        return TcpChannel(conn)

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class PeerConnectionPool:
    """Bounded persistent peer transports. Exchanges are leased exclusively.

    A failed/ambiguous exchange invalidates its connection and is never retried
    automatically: the peer may already have accepted custody.
    """

    def __init__(self, capacity=32, idle_timeout=10.0, timeout=5.0):
        import time
        if capacity < 1 or idle_timeout <= 0 or timeout <= 0:
            raise ValueError("pool capacity and timeouts must be positive")
        self.capacity, self.idle_timeout, self.timeout = capacity, idle_timeout, timeout
        self._clock = time.monotonic
        self._lock = threading.Lock()
        self._entries = {}
        self._closed = False

    def _prune(self):
        now = self._clock()
        for key, entry in list(self._entries.items()):
            if entry['users'] == 0 and now - entry['used'] >= self.idle_timeout:
                if entry['channel'] is not None:
                    entry['channel'].close()
                del self._entries[key]

    def close_idle(self):
        with self._lock:
            self._prune()

    def connection(self, center, address):
        from contextlib import contextmanager
        from mlacp_core.errors import InfrastructureFailure

        @contextmanager
        def lease():
            key = (center, tuple(address))
            with self._lock:
                if self._closed:
                    raise InfrastructureFailure('unavailable', 'peer pool is closed', True)
                self._prune()
                entry = self._entries.get(key)
                if entry is None:
                    if len(self._entries) >= self.capacity:
                        idle = [(e['used'], k) for k, e in self._entries.items() if e['users'] == 0]
                        if not idle:
                            raise InfrastructureFailure('unavailable', 'peer connection capacity exhausted', True)
                        old = self._entries.pop(min(idle)[1])
                        if old['channel'] is not None:
                            old['channel'].close()
                    entry = dict(lock=threading.Lock(), channel=None, used=self._clock(), users=0)
                    self._entries[key] = entry
                entry['users'] += 1
            acquired = False
            try:
                acquired = entry['lock'].acquire(timeout=self.timeout)
                if not acquired:
                    raise InfrastructureFailure('timeout', 'peer exchange is busy', True)
                with self._lock:
                    if self._closed:
                        raise InfrastructureFailure('unavailable', 'peer pool is closed', True)
                if entry['channel'] is None:
                    sock = socket.create_connection(address, timeout=self.timeout)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    channel = TcpChannel(sock)
                    with self._lock:
                        if self._closed:
                            channel.close()
                            raise InfrastructureFailure('unavailable', 'peer pool is closed', True)
                        entry['channel'] = channel
                try:
                    yield entry['channel']
                except BaseException:
                    entry['channel'].close()
                    entry['channel'] = None
                    raise
            finally:
                if acquired:
                    entry['lock'].release()
                with self._lock:
                    entry['users'] -= 1
                    entry['used'] = self._clock()
        return lease()

    def close(self):
        with self._lock:
            self._closed = True
            for entry in self._entries.values():
                if entry['channel'] is not None:
                    entry['channel'].close()
            self._entries.clear()
