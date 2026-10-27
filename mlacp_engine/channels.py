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

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv(self, timeout: float | None = None) -> bytes | None:
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(65536)
        except (socket.timeout, TimeoutError):
            return None
        return data or None

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


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
            self.sock.close()
        except OSError:
            pass
