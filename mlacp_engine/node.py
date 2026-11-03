"""MLACP reference center — one node wiring all six layers together.

The node is a communications center on the primary network (layer 1): it
receives wire frames (closed vocabulary, validated at ONE entrance), and
routes envelopes through the grid (layer 3) and the directory (layer 4),
enforces the capability chain (layer 5), holds offline traffic in the
store-and-dump relay (layer 2), and protects bodies with the GOST layer
(layer 6) when a secure binding exists.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from collections import OrderedDict, deque

from mlacp_core.addresses import Address
from mlacp_core.authority import CapabilityChain
from mlacp_core.custody import CustodyRelay
from mlacp_core.directory import HierarchicalDirectory
from mlacp_core.errors import (
    BusinessRefusal,
    InfrastructureFailure,
    MlacpError,
    NotPermitted,
    UnknownService,
)
from mlacp_core.grid import CommunicationsGrid
from mlacp_core.messages import (
    MAX_TTL,
    WIRE_KINDS,
    Bundle,
    Envelope,
    frame,
    parse_frame,
)
from mlacp_engine.channels import TcpChannel


class CenterNode:
    """A communications center. ``urn`` is its own address
    (mlacp:<org>/<zone>/<node>/center)."""

    def __init__(self, urn: str, grid: CommunicationsGrid | None = None,
                 directory: HierarchicalDirectory | None = None,
                 relay: CustodyRelay | None = None,
                 authority: CapabilityChain | None = None,
                 link_key: bytes | None = None, *, journal_limit: int | None = 10_000,
                 peer_capacity: int = 32, peer_idle_timeout: float = 10.0):
        self.urn = Address.parse(urn)
        self.grid = grid or CommunicationsGrid()
        self.directory = directory or HierarchicalDirectory()
        self.relay = relay if relay is not None else CustodyRelay()
        self.authority = authority or CapabilityChain()
        # the link keys, NEWEST FIRST is not the order: list[-1] is the
        # CURRENT epoch key; older epochs stay decryptable during the
        # re-key window (in-flight traffic), forward secrecy means the OLD
        # key never protects NEW traffic (encrypt always uses list[-1])
        self.link_keys: list[bytes] = [link_key] if link_key else []
        self._epoch = 1 if link_key else 0
        if journal_limit is not None and journal_limit < 0:
            raise ValueError("journal_limit must be non-negative or None")
        self.journal = deque(maxlen=journal_limit)
        self._crypto_contexts = OrderedDict()
        from .channels import PeerConnectionPool
        self._peer_pool = PeerConnectionPool(peer_capacity, peer_idle_timeout)
        self._lock = threading.Lock()
        self._conns: dict[str, object] = {}       # service urn -> channel-like
        self._contact_fn = None                   # grid hook: (center)->node|None
        self.peers: dict[str, tuple[str, int]] = {}   # center -> (host, port)
        self._pending_handshake: tuple | None = None
        # dispatch table built once — no getattr() reflection per frame
        self._handlers = {k: getattr(self, f"_on_{k}") for k in WIRE_KINDS}

    @property
    def link_key(self) -> bytes | None:
        """The CURRENT-epoch link key (None before any handshake)."""
        return self.link_keys[-1] if self.link_keys else None

    # -- journaling -----------------------------------------------------------
    def _jour(self, event: str, **fields) -> None:
        with self._lock:
            self.journal.append({"event": event, **fields})

    # -- the ONE entrance ------------------------------------------------------
    def handle_frame(self, raw: dict, conn=None) -> dict | None:
        """Validate and dispatch one wire frame. Returns the reply frame (or
        None). Every refusal is answered IN-PROTOCOL with an error frame."""
        try:
            kind, f = parse_frame(raw)
            handler = self._handlers[kind]
            return handler(f, conn)
        except UnknownService as e:
            return self._error("unknown_service", str(e), retryable=False)
        except BusinessRefusal as e:
            return self._error(e.__class__.__name__.lower(), str(e), retryable=False)
        except InfrastructureFailure as e:
            return self._error(e.code, e.message, retryable=e.retryable)

    def _error(self, code: str, message: str, retryable: bool) -> dict:
        self._jour("error", code=code, message=message)
        return frame("error", code=code, message=message, retryable=retryable)

    # -- hello: bind + register --------------------------------------------------
    def _on_hello(self, f, conn) -> dict:
        urn = f.get("urn")
        addr = Address.parse(urn) if isinstance(urn, str) else None
        caps = f.get("capabilities", [])
        if urn:
            # hello BINDS: rebinding a registered URN is a reconnect, not a
            # duplicate — update the entry in place (capabilities refresh)
            try:
                self.directory.register(urn, caps)
            except Exception as e:
                from mlacp_core.errors import DuplicateName
                if not isinstance(e, DuplicateName):
                    raise
                old = self.directory.resolve(urn)
                old.capabilities = list(caps)
        if conn is not None and urn:
            self._conns[urn] = conn
        if addr is not None:
            self.grid.mark_heard(addr.node)
        self._jour("hello", urn=urn, capabilities=caps)
        # the addressee is back on the air: dump its held custody (layer 2)
        if urn and len(self.relay.held_for(urn)):
            self.on_recontact(urn, conn)
        return frame("hello", urn=self.urn.to_urn(),
                     directory=[e.urn for e in self.directory.all_entries()])

    # -- envelope: the routed message ---------------------------------------------
    def _on_envelope(self, f, conn) -> dict | None:
        env = Envelope.from_value(f)
        # layer 6: a wire envelope arriving over an inter-center link is
        # encrypted with the shared link key — open it BEFORE anything else
        # (delivery, custody, routing all see the plaintext body)
        if env.body.get("__secure__"):
            env = Envelope(sender=env.sender, recipient=env.recipient,
                           seq=env.seq, ttl=env.ttl,
                           body=self._unsecure_body(env.body))
        sender = Address.parse(env.sender)
        recipient = Address.parse(env.recipient)

        # layer 5: the capability chain authorizes the send (if a capability
        # is demanded, the sender must carry it)
        required = f.get("require_capability")
        if required:
            self.authorize_or_refuse(env.sender, required)

        # layer 4: mandatory registration + per-org accounting
        self.directory.account(sender.org)

        # layer 4: mandatory registration — an unregistered LOCAL addressee is
        # refused BY NAME (the OGAS rule: no service outside the directory).
        # Each center's directory covers its OWN services; a service homed on
        # another center is that center's responsibility (§grid doctrine).
        if recipient.node == self.urn.node:
            self.directory.resolve(recipient.to_urn())
        elif not self.grid.has_center(recipient.node):
            # nobody on this grid has ever heard of the recipient's center:
            # refusing by name beats forwarding into the void
            raise UnknownService(recipient.to_urn())

        # layer 3: route through the grid toward the recipient's center.
        # next_hop only — the full route() list is built and reversed for a
        # value we never use past the first element.
        hop = self._route_toward(recipient)

        if recipient.to_urn() in self._conns:
            # deliver locally: push the envelope to the connected service
            chan = self._conns[recipient.to_urn()]
            out = frame("envelope", **env.to_value())
            _chan_send(chan, out)
            self._jour("delivered", sender=env.sender, recipient=env.recipient,
                       seq=env.seq)
            if f.get("via") == "center":
                # hop-by-hop custody transfer: the forwarding center owns the
                # bundle until THIS center acknowledges
                return frame("custody_ack", bundle_id=f"hop-{env.sender}-{env.seq}",
                             status="delivered")
            return None
        if hop is None:
            # the recipient's center is unreachable NOW -> layer 2: custody
            bundle = Bundle(
                bundle_id=f"bndl-{env.sender}-{env.seq}",
                addressee=recipient.to_urn(),
                ttl=min(env.ttl, MAX_TTL),
                body=self._secure_body(env),
                origin=env.sender,
                seq=env.seq,
            )
            self.relay.accept(bundle)
            self._jour("custody_taken", bundle_id=bundle.bundle_id,
                       addressee=env.recipient)
            return frame("custody_ack", bundle_id=bundle.bundle_id,
                         status="held")
        # multi-hop: hand the envelope to the next center's node over the
        # primary network (layer 1). The peer answers custody_ack (status
        # held|delivered) — hop-by-hop custody transfer, the Strela rule:
        # every relay owns the bundle until the next hop acknowledges.
        if env.ttl - 1 <= 0:
            raise BusinessRefusal(f"hops exhausted before reaching {recipient}")
        # layer 6: with a shared link key the inter-center body travels
        # ENCRYPTED over the primary network (MGM secure frame)
        forwarded = frame("envelope", via="center",
                          **{**env.to_value(),
                             "ttl": env.ttl - 1,
                             "body": self._secure_body(env)})
        reply = self._forward_to_center(hop, forwarded)
        return reply

    def _forward_to_center(self, center: str, forwarded: dict) -> dict:
        if center not in self.peers:
            raise InfrastructureFailure("unavailable", f"no link to center '{center}'", True)
        try:
            with self._peer_pool.connection(center, self.peers[center]) as chan:
                _chan_send(chan, forwarded)
                reply = _recv_frame(chan, timeout=5)
                if reply is None:
                    raise InfrastructureFailure("timeout", f"center '{center}' did not answer", True)
                return reply
        except (OSError, ValueError) as error:
            raise InfrastructureFailure("unavailable", f"center '{center}' exchange failed: {error}", True) from error

    def close(self):
        """Release pooled outbound transports when this center is stopped."""
        self._peer_pool.close()

    def _crypto_context(self, key):
        from mlacp_core.gost import SecureContext
        with self._lock:
            context = self._crypto_contexts.get(key)
            if context is None:
                context = SecureContext(key)
                if key not in self.link_keys:
                    return context  # an in-flight old epoch is not retained again
                self._crypto_contexts[key] = context
                while len(self._crypto_contexts) > 3:
                    self._crypto_contexts.popitem(last=False)
            else:
                self._crypto_contexts.move_to_end(key)
            return context

    def _route_toward(self, recipient: Address) -> str | None:
        """Next grid hop toward the recipient's node, or None when this node
        hosts the recipient's node itself."""
        if recipient.node == self.urn.node:
            return None
        try:
            return self.grid.next_hop(self.urn.node, recipient.node)
        except Exception:
            return recipient.node  # autonomous fallback: aim straight at it

    def _contact(self, center: str):
        return self._contact_fn(center) if self._contact_fn else None

    # -- custody plane ---------------------------------------------------------
    def _on_custody(self, f, conn) -> dict:
        bundle = Bundle.from_value(f)
        bid = self.relay.accept(bundle)
        self._jour("custody_accept", bundle_id=bid, addressee=bundle.addressee)
        return frame("custody_ack", bundle_id=bid, status="held")

    def _on_custody_ack(self, f, conn) -> dict | None:
        self.relay.acknowledge(f["bundle_id"])
        self._jour("custody_release", bundle_id=f["bundle_id"])
        return None

    def on_recontact(self, service_urn: str, conn) -> int:
        """The addressee came back on the air: dump its bundles (in seq
        order) and deliver. Returns how many bundles were released."""
        released = self.relay.contact(service_urn)
        for b in released:
            env = Envelope(sender=b.origin, recipient=b.addressee, seq=b.seq,
                           body=self._unsecure_body(b.body), ttl=MAX_TTL)
            out = frame("envelope", **env.to_value())
            chan = self._conns.get(service_urn, conn)
            if chan is not None:
                _chan_send(chan, out)
            self.relay.acknowledge(b.bundle_id)
        if released:
            self._jour("custody_dump", addressee=service_urn, count=len(released))
        return len(released)

    # -- grid management plane -----------------------------------------------------
    def _on_route_update(self, f, conn) -> dict:
        a, b, link_kind = f.get("a"), f.get("b"), f.get("link", "arterial")
        if f.get("state") == "down":
            self._jour("route_down", a=a, b=b)
            return frame("route_update", state="acked")
        self.grid.add_link(a, b, link_kind, int(f.get("cost", 1)))
        self.grid.mark_heard(self.urn.node)
        return frame("route_update", state="acked")

    def _on_error(self, f, conn) -> None:
        self._jour("peer_error", code=f.get("code"), message=f.get("message"))
        return None

    def _on_close(self, f, conn) -> None:
        for urn, c in list(self._conns.items()):
            if c is conn:
                del self._conns[urn]
        return None

    # -- secure bodies (layer 6) -----------------------------------------------------
    def _secure_body(self, env: Envelope) -> dict:
        if not self.link_keys:
            return dict(env.body)
        raw = json.dumps(env.body, sort_keys=True).encode()
        iv = bytearray(os.urandom(16))
        iv[0] &= 0x7F  # MGM reserves the top bit of the ICN
        # ALWAYS the current-epoch key: the old key never protects new traffic
        payload = self._crypto_context(self.link_keys[-1]).encrypt(bytes(iv), raw)
        return {"__secure__": True,
                "payload": base64.b64encode(payload).decode()}

    def _unsecure_body(self, secure_body: dict) -> dict:
        if not secure_body.get("__secure__"):
            return dict(secure_body)
        if not self.link_keys:
            raise NotPermitted("secure bundle received but this node has no key")
        payload = base64.b64decode(secure_body["payload"])
        # the re-key window: try the newest epoch first, then the older ones
        # (in-flight traffic encrypted before a re-key still opens here —
        # but a key the node never held NEVER will)
        last_err: Exception | None = None
        for key in reversed(self.link_keys):
            try:
                return json.loads(self._crypto_context(key).decrypt(payload))
            except ValueError as e:
                last_err = e
        raise BusinessRefusal(
            f"body encrypted under an unknown key epoch: {last_err}")

    # -- VKO handshake (layer 6 over layer 1) ---------------------------------
    def initiate_handshake(self, curve=None, epoch: int | None = None) -> dict:
        """Produce the `handshake` OFFER frame: this center generates an
        ephemeral VKO keypair (ГОСТ Р 34.10-2012) and a random UKM. The peer
        answers `accept`, and both sides derive the SAME KEK (the agreement
        is symmetric — proven against RFC 7836 §B), which becomes the link
        key protecting all subsequent envelope/custody traffic. Calling this
        again on an ESTABLISHED link starts a NEW EPOCH (epoch = previous+1):
        fresh ephemerals, a fresh KEK — forward secrecy, the old key never
        encrypts new traffic."""
        from mlacp_core.gost_ec import CURVE_512A, generate_keypair, \
            point_to_wire
        import os
        curve = curve or CURVE_512A
        d, pub = generate_keypair(curve)
        ukm = int.from_bytes(os.urandom(8), "little")
        epoch = self._epoch + 1 if epoch is None else epoch
        self._pending_handshake = (curve, d, ukm, epoch)
        return frame("handshake", role="offer", curve=curve.name,
                     ukm=ukm, epoch=epoch, **point_to_wire(curve, pub))

    def rekey(self) -> dict:
        """Start the next key epoch on an established link."""
        if not self.link_keys:
            raise BusinessRefusal("rekey before any handshake")
        return self.initiate_handshake()

    def _adopt_link_key(self, kek: bytes, epoch: int, role: str,
                        curve_name: str, ukm: int) -> None:
        with self._lock:
            if epoch <= self._epoch and kek in self.link_keys:
                return
            self.link_keys.append(kek)
            self.link_keys = self.link_keys[-3:]
            self._epoch = max(self._epoch, epoch)
            for key in list(self._crypto_contexts):
                if key not in self.link_keys:
                    del self._crypto_contexts[key]
        self._jour("handshake_complete", role=role, epoch=epoch,
                   curve=curve_name, ukm=ukm)

    def _on_handshake(self, f, conn) -> dict | None:
        from mlacp_core.gost_ec import (CURVE_512A, CURVE_256A, generate_keypair,
                                        point_to_wire, vko)
        curves = {c.name: c for c in (CURVE_512A, CURVE_256A)}
        role = f.get("role")
        if role not in ("offer", "accept"):
            raise BusinessRefusal("handshake role must be 'offer' or 'accept'")
        if role == "accept" and not self._pending_handshake:
            raise BusinessRefusal("handshake accept without a pending offer")
        if role == "offer":
            curve = curves.get(f.get("curve"), CURVE_512A)
            peer_pub = self._peer_point(curve, f)
            ukm = int(f.get("ukm", 1))
            epoch = int(f.get("epoch", 1))
            d, pub = generate_keypair(curve)
            # KEK from OUR ephemeral private key and THEIR public point
            kek = vko(curve, d, peer_pub, ukm, bits=256)
            self._adopt_link_key(kek, epoch, "acceptor", curve.name, ukm)
            return frame("handshake", role="accept", curve=curve.name,
                         epoch=epoch, **point_to_wire(curve, pub))
        if role == "accept":
            curve, d, ukm, epoch = self._pending_handshake
            peer_pub = self._peer_point(curve, f)
            kek = vko(curve, d, peer_pub, ukm, bits=256)
            self._adopt_link_key(kek, epoch, "initiator", curve.name, ukm)
            self._pending_handshake = None
            return None
        raise BusinessRefusal("handshake role must be 'offer' or 'accept'")

    @staticmethod
    def _peer_point(curve, f) -> tuple:
        from mlacp_core.gost_ec import point_from_wire
        try:
            return point_from_wire(curve, f)
        except ValueError as e:
            raise BusinessRefusal(str(e)) from e

    # -- capability guard ------------------------------------------------------------
    def authorize_or_refuse(self, sender_urn: str, capability: str) -> None:
        self.authority.authorize(sender_urn, capability)  # raises NotPermitted


# -- channel plumbing -----------------------------------------------------------

def _chan_send(chan, wire_frame: dict) -> None:
    data = (json.dumps(wire_frame) + "\n").encode()
    chan.send(data)


def _recv_frame(chan, timeout: float | None = None) -> dict | None:
    """Read one JSON-line frame from a channel (buffers across recv calls)."""
    buf = bytearray(getattr(chan, "_mlacp_buf", b""))
    deadline = None if timeout is None else time.monotonic() + timeout
    while b"\n" not in buf:
        remaining = None if deadline is None else max(0, deadline - time.monotonic())
        if remaining == 0:
            chan._mlacp_buf = bytes(buf)
            return None
        chunk = chan.recv(remaining)
        if chunk is None:
            chan._mlacp_buf = bytes(buf)
            return None
        buf.extend(chunk)
        if len(buf) > 4 * 1024 * 1024:
            raise ValueError("MLACP JSON frame exceeds 4 MiB")
    line, _, rest = buf.partition(b"\n")
    chan._mlacp_buf = bytes(rest)
    return json.loads(line)


def serve(node: CenterNode, listener, run_flag: threading.Event, *,
          max_connections: int = 64, idle_timeout: float = 30.0) -> threading.Thread:
    """Bound connection workers; stop closes accepted and outbound channels."""
    if max_connections < 1 or idle_timeout <= 0:
        raise ValueError("connection limit and idle timeout must be positive")
    gate = threading.BoundedSemaphore(max_connections)
    lock = threading.Lock()
    workers = {}

    def run_connection(chan):
        try:
            _serve_conn(node, chan, run_flag, idle_timeout)
        finally:
            with lock:
                workers.pop(threading.current_thread(), None)
            gate.release()

    def loop():
        try:
            while not run_flag.is_set():
                node._peer_pool.close_idle()
                try:
                    chan = listener.accept(timeout=0.2)
                except OSError:
                    break
                if chan is None:
                    continue
                if not gate.acquire(blocking=False):
                    chan.close()
                    continue
                worker = threading.Thread(target=run_connection, args=(chan,), daemon=True)
                with lock:
                    workers[worker] = chan
                worker.start()
        finally:
            with lock:
                active = list(workers.items())
            for _, chan in active:
                chan.close()
            node.close()
            for worker, _ in active:
                worker.join(timeout=1)

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    return th


def _serve_conn(node: CenterNode, chan, run_flag=None, idle_timeout=30.0) -> None:
    last_used = time.monotonic()
    try:
        while run_flag is None or not run_flag.is_set():
            f = _recv_frame(chan, timeout=0.2)
            if f is None:
                if getattr(chan, 'eof', False) or time.monotonic() - last_used >= idle_timeout:
                    break
                continue
            last_used = time.monotonic()
            reply = node.handle_frame(f, conn=chan)
            if reply is not None:
                _chan_send(chan, reply)
    except (OSError, ValueError):
        pass
    finally:
        node.handle_frame(frame("close"), conn=chan)
        chan.close()
