"""Bounded thread-based chat service without Qt dependencies."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import logging
from pathlib import Path
from queue import Empty, Full, Queue
import select
import socket
import tempfile
import threading
import time
from typing import Any
from uuid import uuid4

from core.addressbook import AddressBook, AddressEntry
from core.directory_sync import merge_page as merge_directory_page
from core.directory_sync import serve_query as serve_directory_query
from core.scope import is_internet_host
from core.discovery import (
    DiscoveryTransport, Hello, encode_hello, local_ipv4_addresses,
    local_ipv6_addresses,
)
from core.diagnostics import DiagnosticsService
from core.feed import merge_page, serve_query
from core.message_journal import MessageJournal
from core.services import LocalServiceDirectory, RemoteDirectoryCache
from core.peer_repository import (
    PeerRepository, PeerRepositoryEvent, TrustState,
)
from core.post_signatures import sign_post
from core.protocol import (
    ProtocolError, envelope, recv_message, send_message, validate_envelope,
)
from core.roster import Peer, PeerRoster, candidate_ips
from core.secure_transport import (
    PairingCandidate, SecureTransport, SecureTransportError,
)
from core.storage import PostStore
from core.transfer import TransferService

MAX_SYNC_PAGES = 20
_DIAL_CACHE_TTL = 120.0
MAX_PENDING_DIALS = 8


@dataclass(frozen=True, kw_only=True)
class _DialedPeer(Peer):
    entry: AddressEntry


@dataclass
class _DialRequest:
    entry: AddressEntry
    peer: Peer | None = None
    error: str | None = None
    done: bool = False


class ChatService:
    """Run bounded chat workers and publish events to a UI-owned queue."""

    def __init__(self, hello: Hello, discovery_port: int = 50000,
                 broadcast: str = "255.255.255.255",
                 reuse_address: bool = False,
                 post_store: PostStore | None = None,
                 message_journal: MessageJournal | None = None,
                 secure_transport: SecureTransport | None = None,
                 discovery_source_addresses: tuple[str, ...] | None = None,
                 discovery_include_fallback: bool = True,
                 directory: LocalServiceDirectory | None = None,
                 address_book: AddressBook | Path | str | None = None,
                 remote_catalog: RemoteDirectoryCache | None = None) -> None:
        self.hello = hello
        encode_hello(hello)
        if (secure_transport is not None
                and secure_transport.local_hello != hello):
            raise ValueError("secure transport does not correspond to HELLO")
        if type(discovery_include_fallback) is not bool:
            raise ValueError("discovery_include_fallback must be bool")
        resolved_sources = _validate_discovery_sources(discovery_source_addresses)
        self.discovery_options = (hello.session_id, discovery_port,
                                  broadcast, reuse_address, resolved_sources,
                                  discovery_include_fallback)
        self._discovery_config_lock = threading.Lock()
        self._discovery_sources = resolved_sources
        self._discovery_fallback = discovery_include_fallback
        self._discovery_revision = 0
        self.events: Queue[tuple[str, Any]] = Queue(maxsize=512)
        self._incoming: Queue[socket.socket] = Queue(maxsize=16)
        self._secure_incoming: Queue[socket.socket] = Queue(maxsize=16)
        self._outgoing: Queue[tuple[Peer, dict[str, Any]]] = Queue(maxsize=128)
        self._pairing: Queue[Peer] = Queue(maxsize=8)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._active: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._repository_event_lock = threading.Lock()
        self._pending_repository_event: PeerRepositoryEvent | None = None
        self._seen: OrderedDict[tuple[str, str], None] = OrderedDict()
        self.secure_transport = secure_transport
        if self.secure_transport is not None:
            self.secure_transport.observe_socket = self._track
        self.peer_repository = PeerRepository(
            trust_resolver=self._resolve_trust)
        self.post_store = post_store
        self.directory = directory or LocalServiceDirectory(hello)
        if self.directory.owner is not hello:
            raise ValueError("directory must belong to the local session")
        self.remote_catalog = remote_catalog or RemoteDirectoryCache()
        self._directory_cursors: dict[str, dict[str, Any] | None] = {}
        self._dial_cache: OrderedDict[
            str, tuple[AddressEntry, str, str, float]] = OrderedDict()
        self._dial_lock = threading.Lock()
        self._dial_generation = 0
        self._dial_requests: dict[str, _DialRequest] = {}
        self._dial_queue: Queue[str] = Queue(maxsize=MAX_PENDING_DIALS)
        self._dial_thread: threading.Thread | None = None
        self._rv_config: tuple[str, int, str, int, int] | None = None
        self._rv_config_lock = threading.Lock()
        self._rv_thread: threading.Thread | None = None
        if isinstance(address_book, AddressBook):
            self.address_book = address_book
            self._book_dir: tempfile.TemporaryDirectory[str] | None = None
        else:
            if address_book is None:
                self._book_dir = tempfile.TemporaryDirectory(
                    prefix="lan-atlas-book-")
                holder: Path | str = (
                    Path(self._book_dir.name) / "addressbook.json")
            else:
                self._book_dir = None
                holder = address_book
            self.address_book = AddressBook(Path(holder))
        self.message_journal = message_journal or MessageJournal()
        if self.secure_transport is not None:
            self.secure_transport.emit = self._event
        self._sync_cursors: dict[str, dict[str, Any] | None] = {}
        self.transfers = TransferService(
            hello, self._event, self._connect_peer, self._track)
        self.diagnostics = DiagnosticsService(
            self._event, hello.peer_id, hello.session_id)

    def start(self) -> None:
        """Start a single service lifecycle; networking initialization is asynchronous."""
        if self._threads:
            raise RuntimeError("service already started")
        self.diagnostics.start()
        targets = [self._presence, self._listen, self._receive_worker,
                   self._receive_worker, self._send_worker, self._send_worker]
        if self.secure_transport is not None:
            targets.extend((self._listen_secure, self._secure_receive_worker,
                            self._secure_receive_worker, self._pair_worker))
        for target in targets:
            thread = threading.Thread(target=target, daemon=True)
            self._threads.append(thread)
            thread.start()

    def _event(self, kind: str, data: Any) -> bool:
        try:
            self.events.put_nowait((kind, data))
            return True
        except Full:
            logging.warning("Chat UI queue full; %s event not delivered", kind)
            return False

    def flush_repository_events(self) -> None:
        """Retry the latest repository revision after UI queue saturation."""
        with self._repository_event_lock:
            pending = self._pending_repository_event
        if pending is None or not self._event("peer_repository", pending):
            return
        with self._repository_event_lock:
            if self._pending_repository_event is pending:
                self._pending_repository_event = None

    def _queue_repository_event(self, event: PeerRepositoryEvent) -> None:
        with self._repository_event_lock:
            pending = self._pending_repository_event
            if pending is None or event.revision > pending.revision:
                self._pending_repository_event = event
        self.flush_repository_events()

    def send(self, text: str, recipients: tuple[Peer, ...],
             direct: bool = False) -> str:
        """Queue bounded per-peer sends and return the request ID."""
        if self._stop.is_set():
            raise RuntimeError("service is stopping")
        if not recipients or (direct and len(recipients) != 1):
            raise ValueError("select one DM recipient or discover room peers")
        body = {"scope": "dm" if direct else "room", "text": text}
        if direct:
            body["to_session"] = recipients[0].hello.session_id
        message = envelope("CHAT", self.hello.peer_id, self.hello.session_id, body)
        self.message_journal.record_outgoing(message, self.hello, recipients)
        for peer in recipients:
            try:
                self._outgoing.put_nowait((peer, message))
            except Full:
                self.message_journal.update_delivery(
                    message["message_id"], peer.hello.session_id, "failed",
                    "outbound queue full")
                self._event("status", f"Failed {message['message_id']} to "
                            f"{peer.hello.name}: outbound queue full")
        return message["message_id"]

    def send_guest_room(self, display_name: str, text: str) -> str:
        """Relay one open LAN guest message to nearby room peers as host."""
        if self._stop.is_set():
            raise RuntimeError("service is stopping")
        name = display_name.strip() if isinstance(display_name, str) else ""
        if not name or any(ord(char) < 32 or char == "\x7f" for char in name):
            raise ValueError("display name must be visible text")
        message_text = text.strip() if isinstance(text, str) else ""
        if not message_text:
            raise ValueError("chat text must not be empty")
        recipients = tuple(
            record.as_peer() for record in self.peer_repository.supporting("chat_v1"))
        body = {"scope": "room", "text": f"Guest {name}: {message_text}"}
        message = envelope("CHAT", self.hello.peer_id, self.hello.session_id, body)
        self.message_journal.record_outgoing(message, self.hello, recipients)
        for peer in recipients:
            try:
                self._outgoing.put_nowait((peer, message))
            except Full:
                self.message_journal.update_delivery(
                    message["message_id"], peer.hello.session_id, "failed",
                    "outbound queue full")
                self._event("status", f"Failed {message['message_id']} to "
                            f"{peer.hello.name}: outbound queue full")
        return message["message_id"]

    def publish_post(self, text: str, refs: list[dict[str, Any]] | None = None) -> str:
        """Persist an immutable local post and notify the UI."""
        if self.post_store is None:
            raise RuntimeError("post store is not configured")
        post = {"post_id": str(uuid4()), "author_id": self.hello.peer_id,
                "text": text, "created_ms": time.time_ns() // 1_000_000,
                "refs": refs or []}
        if self.secure_transport is not None:
            post = sign_post(post, self.secure_transport.identity)
        if not self.post_store.add(post):
            raise RuntimeError("generated duplicate post ID")
        self._event("post_published", {"post_id": post["post_id"]})
        return post["post_id"]

    def sync_posts(self, peer: Peer) -> str:
        """Queue a bounded page sync from one peer without blocking the UI."""
        if self.post_store is None:
            raise RuntimeError("post store is not configured")
        if "posts_v1" not in peer.hello.capabilities:
            raise ValueError("peer does not advertise posts_v1")
        message = envelope("POST_QUERY", self.hello.peer_id, self.hello.session_id,
                           {"cursor": self._sync_cursors.get(peer.hello.session_id),
                            "limit": 50, "author_id": None})
        try:
            self._outgoing.put_nowait((peer, message))
        except Full as error:
            raise RuntimeError("outbound queue full") from error
        return message["message_id"]

    def sync_directory(self, peer: Peer) -> str:
        """Queue a bounded catalog sync from one peer without blocking the UI."""
        if "directory_v1" not in peer.hello.capabilities:
            raise ValueError("peer does not advertise directory_v1")
        message = envelope("DIR_QUERY", self.hello.peer_id, self.hello.session_id,
                           {"cursor": self._directory_cursors.get(peer.hello.session_id),
                            "limit": 50, "kind": None})
        try:
            self._outgoing.put_nowait((peer, message))
        except Full as error:
            raise RuntimeError("outbound queue full") from error
        return message["message_id"]

    def dial_peer(self, peer_id: str) -> Peer:
        """Resolve one address book entry to a live Peer via TLS probe."""
        entry = self._dial_entry(peer_id)
        return self._probe_dial_entry(entry)

    def _dial_entry(self, peer_id: str) -> AddressEntry:
        if self._stop.is_set():
            raise RuntimeError("service is stopping")
        if self.secure_transport is None:
            raise RuntimeError("secure transport is not configured")
        entry = self.address_book.get(peer_id)
        if entry is None:
            raise ValueError("no address book entry for peer")
        trust = self.secure_transport.trust_store
        record = trust.get(entry.peer_id)
        if record is None:
            raise ValueError("entry peer is not paired; pair on LAN first")
        if record.fingerprint != entry.fingerprint:
            raise ValueError("entry certificate differs from paired key")
        return entry

    def _validate_dial_entry(self, entry: AddressEntry) -> None:
        if self._dial_entry(entry.peer_id) != entry:
            raise ValueError("address book entry changed while resolving")

    def _probe_dial_entry(self, entry: AddressEntry) -> Peer:
        self._validate_dial_entry(entry)
        with self._dial_lock:
            cached = self._dial_cache.get(entry.peer_id)
            generation = self._dial_generation
        if (cached is not None and cached[0] == entry
                and time.monotonic() - cached[3] < _DIAL_CACHE_TTL):
            session_id, address = cached[1], cached[2]
        else:
            try:
                assert self.secure_transport is not None
                session_id, address = self.secure_transport.probe_session(
                    entry.host, entry.port, entry.peer_id, cancel=self._stop)
            except (OSError, SecureTransportError, ValueError) as error:
                raise ValueError(f"dial failed: {error}") from error
            self._validate_dial_entry(entry)
            with self._dial_lock:
                if self._stop.is_set():
                    raise RuntimeError("service is stopping")
                if generation == self._dial_generation:
                    self._dial_cache[entry.peer_id] = (
                        entry, session_id, address, time.monotonic())
                    self._dial_cache.move_to_end(entry.peer_id)
                    while len(self._dial_cache) > 128:
                        self._dial_cache.popitem(last=False)
        self._validate_dial_entry(entry)
        hello = Hello(entry.peer_id, session_id, entry.label, entry.port,
                      entry.capabilities, entry.port, entry.fingerprint)
        return _DialedPeer(hello, address, time.monotonic(), entry=entry)

    def validate_dial_peer(self, peer: Peer) -> None:
        """Recheck direct-dial provenance before a deferred action uses a peer."""
        if isinstance(peer, _DialedPeer):
            self._validate_dial_entry(peer.entry)

    def _drop_dial_cache(self, peer_id: str) -> None:
        """Forget one probed session so the next dial re-resolves it."""
        with self._dial_lock:
            self._dial_cache.pop(peer_id, None)
            self._dial_generation += 1

    def dial_peer_async(self, peer_id: str) -> str:
        """Queue a bounded session probe and return its single-use result token."""
        entry = self._dial_entry(peer_id)
        with self._dial_lock:
            if self._stop.is_set():
                raise RuntimeError("service is stopping")
            if len(self._dial_requests) >= MAX_PENDING_DIALS:
                raise RuntimeError("Internet dial queue full")
            if self._dial_thread is None:
                worker = threading.Thread(
                    target=self._resolve_worker, name="internet-dial", daemon=True)
                worker.start()
                self._dial_thread = worker
            token = str(uuid4())
            self._dial_requests[token] = _DialRequest(entry)
            self._dial_queue.put_nowait(token)
        return token

    def take_dial_result(self, token: str) -> Peer | None:
        """Consume a validated result, raise its error, or return None if pending."""
        with self._dial_lock:
            if self._stop.is_set():
                raise RuntimeError("service is stopping")
            request = self._dial_requests.get(token)
            if request is None:
                raise ValueError("unknown Internet dial token")
            if not request.done:
                return None
            del self._dial_requests[token]
        if request.error is not None:
            raise ValueError(request.error)
        self._validate_dial_entry(request.entry)
        assert request.peer is not None
        return request.peer

    def _resolve_worker(self) -> None:
        while not self._stop.is_set():
            try:
                token = self._dial_queue.get(timeout=0.1)
            except Empty:
                continue
            with self._dial_lock:
                request = self._dial_requests.get(token)
            if request is None or self._stop.is_set():
                continue
            peer, failure = None, None
            try:
                peer = self._probe_dial_entry(request.entry)
            except (OSError, ValueError, RuntimeError) as error:
                failure = str(error)
                logging.info("Internet dial failed: %s", error)
            except Exception as error:
                logging.exception("Unexpected Internet dial failure")
                failure = f"Internet dial failed: {error}"
            with self._dial_lock:
                if self._stop.is_set():
                    continue
                request.peer, request.error, request.done = peer, failure, True

    def relay_reserve(self, host: str, port: int) -> str:
        """Hold one relay allocation and serve a single inbound DM."""
        if self.secure_transport is None:
            raise RuntimeError("secure transport is not configured")
        from core.relay import reserve
        try:
            sock, token = reserve(host, port, self.hello.peer_id,
                                  self.hello.session_id)
        except (OSError, ProtocolError, ValueError) as error:
            raise RuntimeError(f"relay reservation failed: {error}") from error
        worker = threading.Thread(
            target=self._relay_host_worker, args=(sock, token), daemon=True)
        worker.start()
        return token

    def _relay_host_worker(self, sock: socket.socket, token: str) -> None:
        """Wait for one join, then accept a single authenticated DM."""
        del token
        deadline = time.monotonic() + 150.0
        try:
            while not self._stop.is_set() and time.monotonic() < deadline:
                try:
                    message = recv_message(sock, timeout=5.0)
                except TimeoutError:
                    continue
                if message is None:
                    return
                validate_envelope(message)
                if message["type"] != "RELAY_READY":
                    raise ProtocolError("expected relay ready before traffic")
                break
            else:
                return
            transport = self.secure_transport
            if transport is None or self._stop.is_set():
                return
            try:
                channel = transport.accept(sock, allow_pairing=False)
            except (OSError, SecureTransportError, ValueError) as error:
                self._event("status", f"Relay handshake failed: {error}")
                return
            if channel is None:
                self._event("status", "Relay pairing refused over relay")
                return
            try:
                self._dispatch_inbound(channel.socket, True,
                                       channel.peer_id, channel.session_id)
            except (OSError, ValueError) as error:
                self._event("status", f"Relay inbound ended: {error}")
            finally:
                try:
                    channel.socket.close()
                except OSError as error:
                    logging.debug("Relay close raced worker: %s", error)
        except (OSError, ProtocolError, ValueError) as error:
            self._event("status", f"Relay reservation ended: {error}")
        finally:
            try:
                sock.close()
            except OSError as error:
                logging.debug("Relay socket close raced worker: %s", error)

    def relay_send(self, peer_id: str, relay_host: str, relay_port: int,
                   token: str, text: str) -> str:
        """Send one DM through a relay without touching direct routes."""
        if self.secure_transport is None:
            raise RuntimeError("secure transport is not configured")
        entry = self.address_book.get(peer_id)
        if entry is None:
            raise ValueError("no address book entry for peer")
        trust = self.secure_transport.trust_store
        record = trust.get(entry.peer_id)
        if record is None:
            raise ValueError("entry peer is not paired; pair on LAN first")
        if record.fingerprint != entry.fingerprint:
            raise ValueError("entry certificate differs from paired key")
        from core.relay import join as relay_join
        from core.protocol import recv_message as _recv
        try:
            sock = relay_join(relay_host, relay_port, self.hello.peer_id,
                              self.hello.session_id, token)
        except (OSError, ProtocolError, ValueError) as error:
            raise RuntimeError(f"relay join failed: {error}") from error
        placeholder = Hello(entry.peer_id, str(uuid4()), entry.label,
                            entry.port, entry.capabilities, entry.port,
                            entry.fingerprint)
        try:
            channel = self.secure_transport.connect_over(
                sock, Peer(placeholder, entry.host, time.monotonic()),
                expect_session=False)
        except (OSError, SecureTransportError, ValueError) as error:
            raise RuntimeError(f"relay handshake failed: {error}") from error
        body = {"scope": "dm", "text": text, "to_session": channel.session_id}
        message = envelope("CHAT", self.hello.peer_id, self.hello.session_id,
                           body)
        channel_hello = Hello(channel.peer_id, channel.session_id,
                              entry.label, entry.port, entry.capabilities,
                              entry.port, channel.fingerprint)
        self.message_journal.record_outgoing(
            message, self.hello,
            (Peer(channel_hello, entry.host, time.monotonic()),))
        try:
            with channel.socket:
                send_message(channel.socket, message)
                reply = _recv(channel.socket)
                if reply is None:
                    raise ProtocolError("no acknowledgement")
                validate_envelope(reply)
                if (reply["type"] != "ACK"
                        or reply["reply_to"] != message["message_id"]
                        or reply["session_id"] != channel.session_id
                        or reply["peer_id"] != channel.peer_id
                        or reply["body"].get("status") != "accepted"):
                    raise ProtocolError("invalid acknowledgement")
        except (OSError, SecureTransportError, ValueError) as error:
            self.message_journal.update_delivery(
                message["message_id"], channel.session_id, "uncertain",
                str(error))
            self._event("status", f"Failed {message['message_id']} via relay: "
                        f"{error}")
            raise RuntimeError(f"relay send failed: {error}") from error
        self.message_journal.update_delivery(
            message["message_id"], channel.session_id, "accepted",
            "accepted by receiving application via relay", True)
        self._event("status", f"Accepted {message['message_id']} via relay")
        return message["message_id"]

    def rendezvous_register(self, server_host: str, server_port: int,
                            ext_host: str, ext_tcp_port: int,
                            ext_secure_port: int) -> bool:
        """Publish this session to a rendezvous server every two minutes."""
        if self.secure_transport is None:
            raise RuntimeError("secure transport is not configured")
        if self._stop.is_set():
            raise RuntimeError("service is stopping")
        from core.rendezvous import sign_announcement
        try:
            sign_announcement(
                self.secure_transport.identity, self.hello.session_id,
                self.hello.name, ext_host, ext_tcp_port, ext_secure_port,
                list(self.hello.capabilities))
        except ValueError as error:
            raise ValueError(f"announced endpoint invalid: {error}") from error
        with self._rv_config_lock:
            self._rv_config = (server_host, server_port, ext_host,
                               ext_tcp_port, ext_secure_port)
            if self._rv_thread is not None and not self._rv_thread.is_alive():
                self._threads = [thread for thread in self._threads
                                 if thread is not self._rv_thread]
                self._rv_thread = None
            live = self._rv_thread is not None and self._rv_thread.is_alive()
            if not live:
                self._rv_thread = threading.Thread(
                    target=self._rendezvous_worker, daemon=True)
                self._threads.append(self._rv_thread)
                self._rv_thread.start()
            return True

    def rendezvous_stop(self) -> None:
        """Withdraw from rendezvous announcements without joining."""
        with self._rv_config_lock:
            self._rv_config = None

    def rendezvous_lookup(self, server_host: str, server_port: int
                          ) -> list[tuple[dict[str, Any], bool]]:
        """Fetch bounded rendezvous pages with trust verification per entry."""
        from core.rendezvous import query_all, verify_announcement
        from core.identity import validate_certificate
        import base64
        if self.secure_transport is None:
            raise RuntimeError("secure transport is not configured")
        trust = self.secure_transport.trust_store
        try:
            entries = query_all(server_host, server_port,
                                self.hello.peer_id, self.hello.session_id)
        except (OSError, ProtocolError, ValueError) as error:
            raise RuntimeError(f"lookup failed: {error}") from error
        results = []
        for raw in entries:
            if not isinstance(raw, dict):
                continue
            try:
                valid, _reason = verify_announcement(raw, None)
            except (ValueError, TypeError, AttributeError):
                continue
            if not valid:
                continue
            try:
                actual = validate_certificate(
                    base64.b64decode(raw["certificate"]),
                    raw["peer_id"])
            except (ValueError, TypeError, AttributeError):
                continue
            record = trust.get(raw["peer_id"])
            trusted = (record is not None
                       and record.fingerprint == actual)
            results.append((raw, trusted))
        return results

    def _rendezvous_worker(self) -> None:
        from core.rendezvous import announce_once, sign_announcement
        while not self._stop.is_set():
            with self._rv_config_lock:
                config = self._rv_config
            if config is None:
                break
            server_host, server_port, ext_host, ext_tcp, ext_secure = config
            transport = self.secure_transport
            try:
                if transport is None:
                    raise RuntimeError("secure transport is not configured")
                entry = sign_announcement(
                    transport.identity, self.hello.session_id,
                    self.hello.name, ext_host, ext_tcp, ext_secure,
                    list(self.hello.capabilities))
                announce_once(server_host, server_port, entry,
                              self.hello.peer_id, self.hello.session_id)
            except (OSError, ProtocolError, ValueError,
                    RuntimeError) as error:
                self._event("status", f"Rendezvous announce failed: {error}")
            for _ in range(240):
                if self._stop.is_set():
                    break
                with self._rv_config_lock:
                    if self._rv_config is None:
                        break
                self._stop.wait(0.5)

    def request_pair(self, peer: Peer) -> bool:
        """Queue one pairing request without blocking the caller."""
        if self.secure_transport is None:
            raise RuntimeError("secure transport is not configured")
        if self._stop.is_set():
            raise RuntimeError("service is stopping")
        for address in candidate_ips(peer):
            try:
                scoped = is_internet_host(address)
            except ValueError as error:
                raise ValueError(f"pair peer address invalid: {error}") from error
            if scoped:
                raise ValueError("pair over Internet refused; pair on LAN first")
        try:
            self._pairing.put_nowait(peer)
            return True
        except Full:
            self._event("status", "Pairing request queue full")
            return False

    def accept_pair(self, request_id: str) -> PairingCandidate:
        """Accept one pending inbound pairing request."""
        if self.secure_transport is None:
            raise RuntimeError("secure transport is not configured")
        candidate = self.secure_transport.accept_pair(request_id)
        self._publish_trust_refresh()
        return candidate

    def decline_pair(self, request_id: str) -> PairingCandidate:
        """Decline one pending inbound pairing request."""
        if self.secure_transport is None:
            raise RuntimeError("secure transport is not configured")
        return self.secure_transport.decline_pair(request_id)

    def accept_outbound_pair(self, request_id: str) -> PairingCandidate:
        """Approve and pin one certificate requested by this device."""
        if self.secure_transport is None:
            raise RuntimeError("secure transport is not configured")
        candidate = self.secure_transport.accept_outbound_pair(request_id)
        self._publish_trust_refresh()
        return candidate

    def decline_outbound_pair(self, request_id: str) -> PairingCandidate:
        """Discard one outbound pairing candidate without pinning it."""
        if self.secure_transport is None:
            raise RuntimeError("secure transport is not configured")
        return self.secure_transport.decline_outbound_pair(request_id)

    def pending_pairs(self) -> tuple[PairingCandidate, ...]:
        """Return unexpired inbound pairing requests."""
        if self.secure_transport is None:
            return ()
        return self.secure_transport.pending()

    def forget_pair(self, peer_id: str) -> bool:
        """Forget one pinned peer certificate and refresh visible trust evidence."""
        if self.secure_transport is None:
            raise RuntimeError("secure transport is not configured")
        forgotten = self.secure_transport.trust_store.forget(peer_id)
        if forgotten:
            self._publish_trust_refresh()
        return forgotten

    def stop(self) -> None:
        """Request cancellation and interrupt established sockets without blocking UI."""
        self._stop.set()
        with self._dial_lock:
            self._dial_requests.clear()
            self._dial_cache.clear()
            while True:
                try:
                    self._dial_queue.get_nowait()
                except Empty:
                    break
        self.transfers.stop()
        self.diagnostics.stop()
        with self._lock:
            conns = tuple(self._active)
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError as error:
                logging.debug("Shutdown raced connection close: %s", error)
            try:
                conn.close()
            except OSError as error:
                logging.debug("Close raced worker: %s", error)

    def join(self, timeout: float = 6.0) -> bool:
        """Wait outside the UI event loop for workers to release resources."""
        deadline = time.monotonic() + timeout
        for thread in self._threads:
            thread.join(max(0, deadline - time.monotonic()))
        with self._dial_lock:
            dial_thread = self._dial_thread
        if dial_thread is not None:
            dial_thread.join(max(0, deadline - time.monotonic()))
        transfers_done = self.transfers.join(max(0, deadline - time.monotonic()))
        diagnostics_done = self.diagnostics.join(max(0, deadline - time.monotonic()))
        return (transfers_done and diagnostics_done
                and (dial_thread is None or not dial_thread.is_alive())
                and not any(thread.is_alive() for thread in self._threads))

    def set_discovery_source_addresses(
            self, addresses: tuple[str, ...] | None,
            include_fallback: bool | None = None) -> None:
        """Select announcement egress without touching sockets from the caller."""
        resolved = _validate_discovery_sources(addresses)
        with self._discovery_config_lock:
            if include_fallback is None:
                fallback = self._discovery_fallback
            elif type(include_fallback) is not bool:
                raise ValueError("include_fallback must be bool")
            else:
                fallback = include_fallback
            if resolved == self._discovery_sources and fallback == self._discovery_fallback:
                return
            self._discovery_sources = resolved
            self._discovery_fallback = fallback
            self._discovery_revision += 1

    def discovery_selection(self) -> tuple[tuple[str, ...] | None, bool, int]:
        """Return selected sources, fallback mode, and config revision."""
        with self._discovery_config_lock:
            return (self._discovery_sources, self._discovery_fallback,
                    self._discovery_revision)

    def _presence(self) -> None:
        transport = None
        roster = PeerRoster(self.hello.session_id)
        try:
            transport = DiscoveryTransport(*self.discovery_options)
            due = time.monotonic()
            applied_revision = 0
            last_auto_check = 0.0
            last_auto_snapshot: tuple[str, ...] | None = None
            while not self._stop.is_set():
                now = time.monotonic()
                sources, fallback, revision = self.discovery_selection()
                if sources is None and now - last_auto_check >= 5.0:
                    last_auto_check = now
                    snapshot = (local_ipv4_addresses()
                                + local_ipv6_addresses())
                    if snapshot != last_auto_snapshot:
                        last_auto_snapshot = snapshot
                        try:
                            transport.refresh_senders(snapshot, fallback)
                        except (OSError, ValueError) as error:
                            self._event("status", f"Discovery refresh failed: {error}")
                if revision != applied_revision:
                    applied_revision = revision
                    resolved = (local_ipv4_addresses() + local_ipv6_addresses()
                                if sources is None else sources)
                    if sources is None:
                        last_auto_snapshot = resolved
                        last_auto_check = now
                    try:
                        transport.refresh_senders(resolved, fallback)
                    except (OSError, ValueError) as error:
                        self._event("status", f"Discovery refresh failed: {error}")
                roster.expire(now)
                if now >= due:
                    try:
                        transport.announce(self.hello)
                    except OSError as error:
                        self._event("status", f"Discovery send failed: {error}")
                    due = now + 2
                ready, _, _ = select.select(transport.receivers, [], [], 0.2)
                for sock in ready:
                    if sock is transport.receiver:
                        result = transport.receive()
                    else:
                        result = transport.receive_v6()
                    if result is not None:
                        hello, address = result
                        roster.update(hello, address[0], time.monotonic())
                peers = roster.snapshot()
                event = self.peer_repository.reconcile_presence(peers, now)
                if event is not None:
                    self._queue_repository_event(event)
                    keep = {record.hello.peer_id for record in
                            self.peer_repository.snapshot()}
                    self.remote_catalog.evict_owners(keep)
                self.flush_repository_events()
        except OSError as error:
            self._event("status", f"Discovery stopped: {error}")
        finally:
            if transport is not None:
                transport.close()

    def _listen(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                option = (socket.SO_EXCLUSIVEADDRUSE
                          if hasattr(socket, "SO_EXCLUSIVEADDRUSE") else socket.SO_REUSEADDR)
                listener.setsockopt(socket.SOL_SOCKET, option, 1)
                listener.bind(("0.0.0.0", self.hello.tcp_port))
                listener.listen(16)
                listener.settimeout(0.2)
                while not self._stop.is_set():
                    try:
                        conn, _ = listener.accept()
                    except TimeoutError:
                        continue
                    try:
                        self._incoming.put_nowait(conn)
                    except Full:
                        conn.close()
                        logging.warning("Inbound connection limit reached")
        except OSError as error:
            self._event("status", f"TCP listener stopped: {error}")
            self.stop()
        finally:
            while True:
                try:
                    self._incoming.get_nowait().close()
                except Empty:
                    break

    def _listen_secure(self) -> None:
        secure_port = self.hello.secure_port
        if secure_port is None:
            self._event("status", "Secure TCP listener stopped: secure port missing")
            self.stop()
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                option = (socket.SO_EXCLUSIVEADDRUSE
                          if hasattr(socket, "SO_EXCLUSIVEADDRUSE") else socket.SO_REUSEADDR)
                listener.setsockopt(socket.SOL_SOCKET, option, 1)
                listener.bind(("0.0.0.0", secure_port))
                listener.listen(16)
                listener.settimeout(0.2)
                while not self._stop.is_set():
                    try:
                        conn, _ = listener.accept()
                    except TimeoutError:
                        continue
                    self._track(conn, True)
                    try:
                        self._secure_incoming.put_nowait(conn)
                    except Full:
                        self._track(conn, False)
                        conn.close()
                        logging.warning("Secure inbound connection limit reached")
        except OSError as error:
            self._event("status", f"Secure TCP listener stopped: {error}")
            self.stop()
        finally:
            while True:
                try:
                    conn = self._secure_incoming.get_nowait()
                except Empty:
                    break
                self._track(conn, False)
                conn.close()

    def _receive_worker(self) -> None:
        while not self._stop.is_set():
            try:
                conn = self._incoming.get(timeout=0.2)
            except Empty:
                continue
            self._track(conn, True)
            try:
                with conn:
                    self._dispatch_inbound(conn, False)
            except (OSError, ValueError) as error:
                self._event("status", f"Inbound connection ended: {error}")
            finally:
                self._track(conn, False)

    def _secure_receive_worker(self) -> None:
        transport = self.secure_transport
        if transport is None:
            return
        while not self._stop.is_set():
            try:
                raw = self._secure_incoming.get(timeout=0.2)
            except Empty:
                continue
            conn = None
            transferred = False
            try:
                try:
                    channel = transport.accept(
                        raw, allow_pairing=self._pairing_allowed(raw))
                except (OSError, SecureTransportError, ValueError) as error:
                    self._event("status", f"Secure handshake failed: {error}")
                    continue
                finally:
                    self._track(raw, False)
                if channel is None:
                    continue
                conn = channel.socket
                self._track(conn, True)
                transferred = self._dispatch_inbound(
                    conn, True, channel.peer_id, channel.session_id)
            except (OSError, ValueError) as error:
                self._event("status", f"Secure inbound connection ended: {error}")
            finally:
                self._track(raw, False)
                if conn is None:
                    try:
                        raw.close()
                    except OSError as error:
                        logging.debug("Secure raw close raced worker: %s", error)
                else:
                    if not transferred:
                        self._track(conn, False)
                        try:
                            conn.close()
                        except OSError as error:
                            logging.debug("Secure TLS close raced worker: %s", error)

    def _dispatch_inbound(self, conn: socket.socket, authenticated: bool,
                          channel_peer_id: str | None = None,
                          channel_session_id: str | None = None) -> bool:
        message = recv_message(conn)
        if message is None:
            return False
        validate_envelope(message)
        if authenticated:
            if (message["peer_id"] != channel_peer_id
                    or message["session_id"] != channel_session_id):
                raise ProtocolError("secure envelope identity mismatch")
        elif (self.secure_transport is not None
              and self.secure_transport.trust_store.get(message["peer_id"])
              is not None):
            raise ProtocolError("plaintext downgrade rejected for paired peer")
        if message["type"] == "FILE_OFFER":
            if authenticated:
                self.transfers.receive(conn, message, authenticated=True)
                return True
            dedicated = conn.dup()
            try:
                self.transfers.receive(dedicated, message)
            except (OSError, ProtocolError):
                dedicated.close()
                raise
            return False
        if message["type"] == "POST_QUERY":
            if self.post_store is None:
                raise ProtocolError("post store is not configured")
            body = serve_query(self.post_store, message["body"])
            send_message(conn, envelope("POST_PAGE", self.hello.peer_id,
                                        self.hello.session_id, body,
                                        message["message_id"]))
            return False
        if message["type"] == "DIR_QUERY":
            body = serve_directory_query(self.directory, message["body"])
            send_message(conn, envelope("DIR_PAGE", self.hello.peer_id,
                                        self.hello.session_id, body,
                                        message["message_id"]))
            return False
        if message["type"] != "CHAT":
            raise ProtocolError("listener does not accept this message type")
        body = message["body"]
        if body["scope"] == "dm" and body["to_session"] != self.hello.session_id:
            raise ProtocolError("DM addressed to a different session")
        key = (message["session_id"], message["message_id"])
        with self._lock:
            duplicate = key in self._seen
            if not duplicate:
                self._seen[key] = None
                if len(self._seen) > 1024:
                    self._seen.popitem(last=False)
        if not duplicate:
            record = self.peer_repository.get(message["session_id"])
            sender_name = (
                record.hello.name if record is not None
                and record.hello.peer_id == message["peer_id"]
                else f"Peer {message['peer_id'][:8]}")
            self.message_journal.record_incoming(
                message, sender_name, self.hello, authenticated)
        send_message(conn, envelope("ACK", self.hello.peer_id,
                                    self.hello.session_id,
                                    {"status": "accepted"},
                                    message["message_id"]))
        return False

    def _pairing_allowed(self, raw: socket.socket) -> bool:
        """Refuse inbound pairing from Internet scope; auth stays allowed."""
        try:
            source = raw.getpeername()[0]
        except OSError:
            return False
        try:
            return not is_internet_host(source)
        except ValueError:
            return False

    def _track(self, conn: socket.socket, add: bool) -> None:
        close_now = False
        with self._lock:
            if add:
                if self._stop.is_set():
                    close_now = True
                else:
                    self._active.add(conn)
            else:
                self._active.discard(conn)
        if close_now:
            try:
                conn.close()
            except OSError as error:
                logging.debug("Close raced stopped service: %s", error)

    def _connect_peer(self, peer: Peer) -> tuple[socket.socket, bool]:
        self.validate_dial_peer(peer)
        addresses = candidate_ips(peer)
        paired = (self.secure_transport is not None
                  and self.secure_transport.trust_store.get(peer.hello.peer_id)
                  is not None)
        try:
            internet = any(is_internet_host(address) for address in addresses)
        except ValueError as error:
            raise ValueError(f"peer address invalid: {error}") from error
        if (internet or isinstance(peer, _DialedPeer)) and not paired:
            raise ValueError("unpaired Internet dial refused; pair on LAN first")
        if paired:
            assert self.secure_transport is not None
            error: Exception | None = None
            for address in addresses:
                attempt = Peer(peer.hello, address, peer.last_seen,
                               peer.endpoint_candidates)
                try:
                    channel = self.secure_transport.connect(attempt)
                    return channel.socket, True
                except (OSError, SecureTransportError, ValueError) as exc:
                    error = exc
                    continue
            assert error is not None
            raise error
        connect_error: OSError | None = None
        for address in addresses:
            try:
                return (socket.create_connection(
                    (address, peer.hello.tcp_port), timeout=3), False)
            except OSError as exc:
                connect_error = exc
                continue
        assert connect_error is not None
        raise connect_error

    def _resolve_trust(self, hello: Hello) -> TrustState:
        transport = self.secure_transport
        if transport is None:
            return TrustState.UNVERIFIED
        record = transport.trust_store.get(hello.peer_id)
        if record is None:
            return TrustState.UNVERIFIED
        if (hello.certificate_sha256 is not None
                and hello.certificate_sha256 != record.fingerprint):
            return TrustState.KEY_CHANGED
        return TrustState.PAIRED

    def _publish_trust_refresh(self) -> None:
        event = self.peer_repository.refresh_trust()
        if event is not None:
            self._queue_repository_event(event)

    def _pair_worker(self) -> None:
        transport = self.secure_transport
        if transport is None:
            return
        while not self._stop.is_set():
            try:
                peer = self._pairing.get(timeout=0.2)
            except Empty:
                continue
            try:
                candidate = transport.request_pair(peer)
                self._event("pair_outbound", candidate)
            except (OSError, SecureTransportError, ValueError) as error:
                self._event("status", f"Pairing request failed: {error}")

    def _send_worker(self) -> None:
        while not self._stop.is_set():
            try:
                peer, message = self._outgoing.get(timeout=0.2)
            except Empty:
                continue
            conn = None
            authenticated = False
            transmission_started = False
            try:
                if message["type"] == "POST_QUERY":
                    self._sync_peer(peer, message)
                    continue
                if message["type"] == "DIR_QUERY":
                    self._sync_directory_peer(peer, message)
                    continue
                conn, authenticated = self._connect_peer(peer)
                self._track(conn, True)
                with conn:
                    transmission_started = True
                    send_message(conn, message)
                    reply = recv_message(conn)
                    if reply is None:
                        raise ProtocolError("no acknowledgement")
                    validate_envelope(reply)
                    if (reply["type"] != "ACK" or reply["reply_to"] != message["message_id"]
                            or reply["session_id"] != peer.hello.session_id
                            or reply["peer_id"] != peer.hello.peer_id
                            or reply["body"].get("status") != "accepted"):
                        raise ProtocolError("invalid acknowledgement")
                self.message_journal.update_delivery(
                    message["message_id"], peer.hello.session_id, "accepted",
                    "accepted by receiving application", authenticated)
                self._event("status", f"Accepted {message['message_id']} by {peer.hello.name}")
            except (OSError, SecureTransportError, ValueError) as error:
                state = "uncertain" if transmission_started else "failed"
                self._drop_dial_cache(peer.hello.peer_id)
                self.message_journal.update_delivery(
                    message["message_id"], peer.hello.session_id, state,
                    str(error))
                self._event("status", f"Failed {message['message_id']} to "
                            f"{peer.hello.name}: {error}")
            finally:
                if conn is not None:
                    conn.close()
                    self._track(conn, False)

    def _sync_peer(self, peer: Peer, query: dict[str, Any]) -> None:
        """Fetch bounded pages, retaining a continuation cursor if capped."""
        if self.post_store is None:
            raise RuntimeError("post store is not configured")
        added = duplicates = 0
        current = query
        for _ in range(MAX_SYNC_PAGES):
            conn, _ = self._connect_peer(peer)
            self._track(conn, True)
            try:
                with conn:
                    send_message(conn, current)
                    reply = recv_message(conn)
            finally:
                self._track(conn, False)
            if reply is None:
                raise ProtocolError("no post page response")
            validate_envelope(reply)
            if (reply["type"] != "POST_PAGE"
                    or reply["reply_to"] != current["message_id"]
                    or reply["peer_id"] != peer.hello.peer_id
                    or reply["session_id"] != peer.hello.session_id):
                raise ProtocolError("invalid post page response")
            page_added, page_duplicates = merge_page(self.post_store,
                                                      reply["body"]["posts"])
            added += page_added
            duplicates += page_duplicates
            cursor = reply["body"]["next_cursor"]
            if reply["body"]["complete"]:
                self._sync_cursors.pop(peer.hello.session_id, None)
                self._event("feed_updated", {"added": added,
                                              "duplicates": duplicates})
                return
            self._sync_cursors[peer.hello.session_id] = cursor
            current = envelope("POST_QUERY", self.hello.peer_id,
                               self.hello.session_id,
                               {"cursor": cursor, "limit": 50,
                                "author_id": None})
        self._event("feed_updated", {"added": added, "duplicates": duplicates,
                                     "partial": True})

    def _sync_directory_peer(self, peer: Peer, query: dict[str, Any]) -> None:
        """Fetch bounded catalog pages, retaining a continuation cursor if capped."""
        added = duplicates = 0
        authenticated = False
        current = query
        for _ in range(MAX_SYNC_PAGES):
            conn, authenticated = self._connect_peer(peer)
            self._track(conn, True)
            try:
                with conn:
                    send_message(conn, current)
                    reply = recv_message(conn)
            finally:
                self._track(conn, False)
            if reply is None:
                raise ProtocolError("no directory page response")
            validate_envelope(reply)
            if (reply["type"] != "DIR_PAGE"
                    or reply["reply_to"] != current["message_id"]
                    or reply["peer_id"] != peer.hello.peer_id
                    or reply["session_id"] != peer.hello.session_id):
                raise ProtocolError("invalid directory page response")
            for raw in reply["body"]["entries"]:
                if (not isinstance(raw, dict)
                        or raw.get("owner_peer_id") != peer.hello.peer_id
                        or raw.get("owner_session_id") != peer.hello.session_id):
                    raise ProtocolError("directory entry owner differs from sender")
            page_added, page_duplicates = merge_directory_page(
                self.remote_catalog, reply["body"]["entries"])
            added += page_added
            duplicates += page_duplicates
            cursor = reply["body"]["next_cursor"]
            if reply["body"]["complete"]:
                self._directory_cursors.pop(peer.hello.session_id, None)
                self._event("directory_updated", {"added": added,
                                                  "duplicates": duplicates,
                                                  "authenticated": authenticated})
                return
            self._store_directory_cursor(peer.hello.session_id, cursor)
            current = envelope("DIR_QUERY", self.hello.peer_id,
                               self.hello.session_id,
                               {"cursor": cursor, "limit": 50, "kind": None})
        self._event("directory_updated", {"added": added, "duplicates": duplicates,
                                          "partial": True,
                                          "authenticated": authenticated})

    def _store_directory_cursor(self, session_id: str,
                                cursor: dict[str, Any] | None) -> None:
        """Retain one continuation cursor with a bounded session table."""
        if len(self._directory_cursors) >= 64 and session_id not in self._directory_cursors:
            oldest = next(iter(self._directory_cursors))
            del self._directory_cursors[oldest]
        self._directory_cursors[session_id] = cursor


def _validate_discovery_sources(
        value: tuple[str, ...] | list[str] | None) -> tuple[str, ...] | None:
    """Validate announcement egress selection without probing the network."""
    if value is None:
        return None
    if not isinstance(value, (tuple, list)):
        raise ValueError("discovery sources must be a tuple or None")
    from ipaddress import ip_address as _ip_address
    resolved = tuple(value)
    for item in resolved:
        if not isinstance(item, str) or not item or len(item) > 255:
            raise ValueError("discovery source must be a bounded string")
        try:
            _ip_address(item.partition("%")[0])
        except ValueError as error:
            raise ValueError(f"invalid IP discovery source: {item}") from error
    return resolved
