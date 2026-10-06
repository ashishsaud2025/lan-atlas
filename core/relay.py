"""Dumb byte relay pairing two strangers by single-use tokens."""

from __future__ import annotations

import logging
import select
import socket
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from core.protocol import (
    ProtocolError, envelope, recv_message, send_message, validate_envelope,
)

logger = logging.getLogger(__name__)

RELAY_TTL = 120.0
MAX_PENDING = 64
MAX_RELAYS = 8
MAX_HANDLERS = 32
ACTIVE_TTL = 300.0
CHUNK_SIZE = 64 * 1024
IO_TIMEOUT = 60.0
ACCEPT_TIMEOUT = 0.5
PIPE_POLL = 0.5


@dataclass(frozen=True)
class RelayState:
    """Immutable lifecycle snapshot of one relay server."""

    phase: str = "stopped"
    host: str | None = None
    port: int | None = None
    pending: int = 0
    active: int = 0
    error: str | None = None


@dataclass
class _Allocation:
    holder: socket.socket
    deadline: float


class RelayServer:
    """Splice paired strangers without ever reading their bytes."""

    def __init__(self, allocation_ttl: float = RELAY_TTL,
                 max_pending: int = MAX_PENDING,
                 max_relays: int = MAX_RELAYS,
                 allow_loopback: bool = False) -> None:
        if not allocation_ttl > 0:
            raise ValueError("allocation TTL must be positive")
        if type(max_pending) is not int or max_pending <= 0:
            raise ValueError("max pending must be a positive integer")
        if type(max_relays) is not int or max_relays <= 0:
            raise ValueError("max relays must be a positive integer")
        self.allocation_ttl = allocation_ttl
        self.max_pending = max_pending
        self.max_relays = max_relays
        self.allow_loopback = allow_loopback
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._handlers: list[threading.Thread] = []
        self._splices: set[socket.socket] = set()
        self._pending: OrderedDict[str, _Allocation] = OrderedDict()
        self._active = 0
        self._state = RelayState()

    def start(self, host: str, port: int) -> RelayState:
        """Bind synchronously, then serve from one owned daemon worker."""
        from ipaddress import ip_address as _ip_address
        if not isinstance(host, str) or not host.strip():
            raise ValueError("server requires a concrete address")
        cleaned = host.strip().strip("[]")
        if cleaned in {"0.0.0.0", "::"}:
            raise ValueError("bind one concrete address, not a wildcard")
        try:
            loopback = _ip_address(cleaned).is_loopback
        except ValueError as error:
            raise ValueError(f"server address invalid: {error}") from error
        if loopback and not self.allow_loopback:
            raise ValueError("loopback servers need explicit opt in")
        family = socket.AF_INET6 if ":" in cleaned else socket.AF_INET
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("server is already running or stopping")
            self._stop.clear()
            listener = socket.socket(family, socket.SOCK_STREAM)
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((cleaned, port))
                listener.listen(self.max_relays)
                listener.settimeout(ACCEPT_TIMEOUT)
                actual = listener.getsockname()
            except (OSError, ValueError) as error:
                listener.close()
                raise ValueError(f"server bind failed: {error}") from error
            self._listener = listener
            self._state = RelayState("running", str(actual[0]),
                                     int(actual[1]), 0, 0)
            thread = threading.Thread(
                target=self._accept, name="lan-atlas-relay", daemon=True)
            self._thread = thread
            thread.start()
            return self._state

    def stop(self) -> None:
        """Request shutdown and unblock accept plus live sockets promptly."""
        with self._lock:
            thread = self._thread
            listener = self._listener
            held = [item.holder for item in self._pending.values()]
            spliced = tuple(self._splices)
            if thread is None or not thread.is_alive():
                if self._state.phase != "failed":
                    self._state = RelayState()
                return
            self._state = RelayState(
                "stopping", self._state.host, self._state.port,
                len(self._pending), self._active)
            self._stop.set()
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    logger.debug("Could not close relay listener", exc_info=True)
        for sock in held + list(spliced):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                logger.debug("Could not interrupt relay socket", exc_info=True)

    def join(self, timeout: float = 3.0) -> bool:
        """Wait a finite interval for accept and handler workers to finish."""
        if timeout < 0:
            raise ValueError("timeout must not be negative")
        with self._lock:
            thread = self._thread
            handlers = tuple(self._handlers)
        deadline = time.monotonic() + timeout
        if thread is not None:
            thread.join(max(0.0, deadline - time.monotonic()))
        for handler in handlers:
            handler.join(max(0.0, deadline - time.monotonic()))
        with self._lock:
            self._handlers = [item for item in self._handlers if item.is_alive()]
            handlers_done = not self._handlers
        return (thread is None or not thread.is_alive()) and handlers_done

    def state(self) -> RelayState:
        """Return one immutable lifecycle snapshot."""
        with self._lock:
            return self._state

    def _accept(self) -> None:
        with self._lock:
            listener = self._listener
        if listener is None:
            return
        failed: str | None = None
        try:
            while not self._stop.is_set():
                try:
                    client, _address = listener.accept()
                except TimeoutError:
                    continue
                except OSError as error:
                    if not self._stop.is_set():
                        failed = str(error)
                        logger.exception("Relay listener failed: %s", error)
                    break
                with self._lock:
                    self._handlers = [item for item in self._handlers
                                      if item.is_alive()]
                    if len(self._handlers) >= MAX_HANDLERS:
                        full_conn = True
                    else:
                        full_conn = False
                if full_conn:
                    try:
                        client.close()
                    except OSError:
                        logger.debug("Could not close excess client", exc_info=True)
                    continue
                worker = threading.Thread(
                    target=self._handle, args=(client,),
                    name="lan-atlas-relay-conn", daemon=True)
                with self._lock:
                    self._handlers.append(worker)
                worker.start()
        finally:
            try:
                listener.close()
            except OSError:
                logger.debug("Could not close listener", exc_info=True)
            with self._lock:
                self._listener = None
                if failed is None:
                    self._state = RelayState()
                    self._pending.clear()
                else:
                    self._state = RelayState(
                        "failed", self._state.host, self._state.port,
                        len(self._pending), self._active, failed)

    def _handle(self, conn: socket.socket) -> None:
        owned = True
        try:
            conn.settimeout(5.0)
            message = recv_message(conn)
            if message is None:
                return
            validate_envelope(message)
            if message["type"] == "RELAY_ALLOC":
                token = self._allocate(conn)
                send_message(conn, envelope(
                    "ACK", message["peer_id"], message["session_id"],
                    {"status": "accepted", "token": token},
                    message["message_id"]))
                owned = not self._hold(conn, token)
            elif message["type"] == "RELAY_JOIN":
                self._join(conn, message)
            else:
                raise ProtocolError("relay accepts RELAY frames only")
        except (OSError, ProtocolError, ValueError) as error:
            logger.debug("Relay connection ended: %s", error)
        finally:
            if owned:
                try:
                    conn.close()
                except OSError:
                    logger.debug("Could not close relay socket", exc_info=True)

    def _hold(self, holder: socket.socket, token: str) -> bool:
        """Keep one allocation open; True when a join consumed it."""
        while not self._stop.is_set():
            with self._lock:
                item = self._pending.get(token)
                if item is None or item.holder is not holder:
                    return True
                if time.monotonic() >= item.deadline:
                    del self._pending[token]
                    return False
            self._stop.wait(1.0)
        return False

    def _allocate(self, holder: socket.socket) -> str:
        now = time.monotonic()
        with self._lock:
            expired = [key for key, item in self._pending.items()
                       if now >= item.deadline]
            for key in expired:
                stale = self._pending.pop(key)
                try:
                    stale.holder.close()
                except OSError:
                    logger.debug("Could not close expired holder", exc_info=True)
            if len(self._pending) >= self.max_pending:
                raise ProtocolError("relay allocation table full")
            token = uuid4().hex
            self._pending[token] = _Allocation(
                holder, now + self.allocation_ttl)
            return token

    def _join(self, joiner: socket.socket, message: dict[str, Any]) -> None:
        token = message["body"].get("token")
        if (not isinstance(token, str) or len(token) != 32
                or any(c not in "0123456789abcdef" for c in token)):
            raise ProtocolError("relay join requires a 32 hex token")
        with self._lock:
            item = self._pending.pop(token, None)
            if item is None:
                raise ProtocolError("unknown or expired relay token")
            if self._active >= self.max_relays:
                self._pending[token] = item
                raise ProtocolError("relay is at connection capacity")
            holder = item.holder
            self._active += 1
        try:
            send_message(holder, envelope(
                "RELAY_READY", message["peer_id"], message["session_id"], {},
                message["message_id"]))
        except (OSError, ProtocolError, ValueError):
            with self._lock:
                self._active = max(0, self._active - 1)
            raise ProtocolError("allocation holder is gone")
        send_message(joiner, envelope(
            "ACK", message["peer_id"], message["session_id"],
            {"status": "accepted"}, message["message_id"]))
        first = threading.Thread(
            target=_pipe, args=(joiner, holder, self._stop), daemon=True)
        second = threading.Thread(
            target=_pipe, args=(holder, joiner, self._stop), daemon=True)
        with self._lock:
            self._splices.add(joiner)
            self._splices.add(holder)
        first.start()
        second.start()
        try:
            deadline = time.monotonic() + ACTIVE_TTL
            for pipe in (first, second):
                pipe.join(max(0.0, deadline - time.monotonic()))
        finally:
            for sock in (joiner, holder):
                try:
                    sock.close()
                except OSError:
                    logger.debug("Could not close spliced socket", exc_info=True)
            with self._lock:
                self._splices.discard(joiner)
                self._splices.discard(holder)
        with self._lock:
            self._active = max(0, self._active - 1)


def _pipe(source: socket.socket, dest: socket.socket,
          stop: threading.Event) -> None:
    """Copy raw bytes one way with prompt stop wakeups and half-close."""
    try:
        while not stop.is_set():
            try:
                ready, _, _ = select.select([source], [], [], PIPE_POLL)
            except (OSError, ValueError):
                break
            if not ready:
                continue
            try:
                chunk = source.recv(CHUNK_SIZE)
            except TimeoutError:
                continue
            except OSError:
                break
            if not chunk:
                break
            try:
                dest.sendall(chunk)
            except (OSError, TimeoutError):
                break
    finally:
        try:
            dest.shutdown(socket.SHUT_WR)
        except OSError:
            logger.debug("Half close raced socket teardown", exc_info=True)


def reserve(host: str, port: int, peer_id: str, session_id: str,
            timeout: float = 5.0) -> tuple[socket.socket, str]:
    """Hold one relay allocation open and return its single-use token."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        send_message(sock, envelope("RELAY_ALLOC", peer_id, session_id, {}))
        reply = recv_message(sock)
        if reply is None:
            raise ProtocolError("no allocation response")
        validate_envelope(reply)
        if (reply["type"] != "ACK"
                or reply["body"].get("status") != "accepted"
                or not isinstance(reply["body"].get("token"), str)):
            raise ProtocolError("allocation not accepted")
        return sock, str(reply["body"]["token"])
    except (OSError, ProtocolError, ValueError):
        sock.close()
        raise


def join(host: str, port: int, peer_id: str, session_id: str, token: str,
         timeout: float = 5.0) -> socket.socket:
    """Join one allocation and return the raw pipe to the holder."""
    if (not isinstance(token, str) or len(token) != 32
            or any(c not in "0123456789abcdef" for c in token)):
        raise ValueError("relay join requires a 32 hex token")
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        send_message(sock, envelope("RELAY_JOIN", peer_id, session_id,
                                    {"token": token}))
        reply = recv_message(sock)
        if reply is None:
            raise ProtocolError("no join response")
        validate_envelope(reply)
        if (reply["type"] != "ACK"
                or reply["body"].get("status") != "accepted"):
            raise ProtocolError("join not accepted")
        return sock
    except (OSError, ProtocolError, ValueError):
        sock.close()
        raise
