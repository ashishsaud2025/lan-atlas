"""Self-hosted rendezvous directory with signed untrusted announcements.

The server checks shape only: one client can evict others with fresh UUIDs
within the bounded entry cap, so clients treat listings as hints and verify
every entry before display or dialing."""

from __future__ import annotations

import base64
import json
import logging
import socket
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from uuid import UUID

from core.identity import DeviceIdentity, IdentityError, validate_certificate
from core.protocol import (
    ProtocolError, envelope, recv_message, send_message, validate_envelope,
)

logger = logging.getLogger(__name__)

ANNOUNCE_DOMAIN = b"LAN-MANAGER-ANNOUNCE-V1\x00"
RV_ANNOUNCE_INTERVAL = 120.0
RV_ENTRY_TTL = 300.0
RV_PAGE_LIMIT_MAX = 50
RV_MAX_ENTRIES = 1024
RV_MAX_CONNECTIONS = 16


@dataclass(frozen=True)
class RendezvousState:
    """Immutable lifecycle snapshot of one rendezvous server."""

    phase: str = "stopped"
    host: str | None = None
    port: int | None = None
    entries: int = 0
    error: str | None = None


@dataclass
class _Record:
    data: dict[str, Any]
    last_seen: float


def _canonical_id(value: object, label: str) -> str:
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError("noncanonical UUID")
    except ValueError as error:
        raise ValueError(f"invalid {label}") from error
    assert isinstance(value, str)
    return value


def _checked_port(value: object, label: str) -> int:
    if type(value) is not int or isinstance(value, bool) or not 1 <= value <= 65535:
        raise ValueError(f"{label} must be from 1 through 65535")
    return value


def _checked_host(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 255:
        raise ValueError("announcement host must be a bounded string")
    return value.strip()


def _checked_capabilities(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > 16:
        raise ValueError("capabilities must be a bounded list")
    for item in value:
        if (not isinstance(item, str) or not item or len(item) > 64
                or not item.isascii()
                or not all(c.isalnum() or c in "_-" for c in item)):
            raise ValueError("invalid capability")
    return value


def _payload(data: dict[str, Any]) -> bytes:
    """Return the exact bytes covered by an announcement signature."""
    fields = {
        "peer_id": data["peer_id"],
        "session_id": data["session_id"],
        "host": data["host"],
        "tcp_port": data["tcp_port"],
        "secure_port": data["secure_port"],
        "capabilities": sorted(data["capabilities"]),
        "timestamp_ms": data["timestamp_ms"],
    }
    try:
        encoded = json.dumps(
            fields, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("announcement fields must be JSON compatible") from error
    return ANNOUNCE_DOMAIN + encoded


def check_announcement(value: object) -> dict[str, Any]:
    """Validate announcement shape without trusting any of its claims."""
    if not isinstance(value, dict):
        raise ValueError("announcement must be an object")
    expected = {"peer_id", "session_id", "name", "host", "tcp_port",
                "secure_port", "capabilities", "certificate", "timestamp_ms",
                "signature"}
    if set(value) != expected:
        raise ValueError("announcement has invalid fields")
    _canonical_id(value["peer_id"], "peer_id")
    _canonical_id(value["session_id"], "session_id")
    name = value["name"]
    if not isinstance(name, str) or not name.strip() or len(name) > 80:
        raise ValueError("announcement name must contain 1 to 80 characters")
    _checked_host(value["host"])
    _checked_port(value["tcp_port"], "tcp_port")
    _checked_port(value["secure_port"], "secure_port")
    _checked_capabilities(value["capabilities"])
    timestamp = value["timestamp_ms"]
    if type(timestamp) is not int or not 0 <= timestamp <= 2 ** 63 - 1:
        raise ValueError("timestamp_ms must be a nonnegative integer")
    for label in ("certificate", "signature"):
        raw = value[label]
        if not isinstance(raw, str) or not raw or not raw.isascii():
            raise ValueError(f"announcement {label} must be base64 text")
        try:
            base64.b64decode(raw, validate=True)
        except ValueError as error:
            raise ValueError(f"announcement {label} is not base64") from error
    return value  # type: ignore[return-value]


def sign_announcement(identity: DeviceIdentity, session_id: str, name: str,
                      host: str, tcp_port: int, secure_port: int,
                      capabilities: list[str]) -> dict[str, Any]:
    """Sign one directory announcement with the device identity."""
    data: dict[str, Any] = {
        "peer_id": _canonical_id(identity.peer_id, "peer_id"),
        "session_id": _canonical_id(session_id, "session_id"),
        "name": name.strip(),
        "host": _checked_host(host),
        "tcp_port": _checked_port(tcp_port, "tcp_port"),
        "secure_port": _checked_port(secure_port, "secure_port"),
        "capabilities": _checked_capabilities(capabilities),
        "certificate": base64.b64encode(identity.certificate_der).decode("ascii"),
        "timestamp_ms": time.time_ns() // 1_000_000,
        "signature": "",
    }
    if not data["name"] or len(data["name"]) > 80:
        raise ValueError("announcement name must contain 1 to 80 characters")
    signature = identity.sign(_payload(data))
    data["signature"] = base64.b64encode(bytes(signature)).decode("ascii")
    return check_announcement(data)


def verify_announcement(data: dict[str, Any],
                        fingerprint: str | None) -> tuple[bool, str]:
    """Verify shape, certificate binding, signature, and freshness."""
    from core.identity import verify_signature
    try:
        checked = check_announcement(dict(data))
        certificate_der = base64.b64decode(checked["certificate"])
        actual = validate_certificate(certificate_der, checked["peer_id"])
        signature = base64.b64decode(checked["signature"])
        if not verify_signature(certificate_der, _payload(checked), signature):
            return False, "signature does not match"
        now_ms = time.time_ns() // 1_000_000
        age = now_ms - checked["timestamp_ms"]
        if age > 600_000 or age < -300_000:
            return False, "announcement is stale or from the future"
        if fingerprint is not None and actual != fingerprint:
            return False, "certificate differs from pinned key"
    except (ValueError, IdentityError) as error:
        return False, str(error)
    return True, ""


class RendezvousServer:
    """Hold signed peer announcements without ever trusting them."""

    def __init__(self, entry_ttl: float = RV_ENTRY_TTL,
                 max_entries: int = RV_MAX_ENTRIES) -> None:
        if not entry_ttl > 0:
            raise ValueError("entry TTL must be positive")
        if type(max_entries) is not int or max_entries <= 0:
            raise ValueError("max entries must be a positive integer")
        self.entry_ttl = entry_ttl
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._handlers: list[threading.Thread] = []
        self._active = 0
        self._records: OrderedDict[str, _Record] = OrderedDict()
        self._state = RendezvousState()

    def start(self, host: str, port: int,
              allow_loopback: bool = False) -> RendezvousState:
        """Bind synchronously, then serve from one owned daemon worker."""
        if not isinstance(host, str) or not host.strip():
            raise ValueError("server requires a concrete address")
        cleaned = host.strip().strip("[]")
        if cleaned in {"0.0.0.0", "::"}:
            raise ValueError("bind one concrete address, not a wildcard")
        try:
            loopback = ip_address(cleaned).is_loopback
        except ValueError as error:
            raise ValueError(f"server address invalid: {error}") from error
        if loopback and not allow_loopback:
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
                listener.listen(RV_MAX_CONNECTIONS)
                listener.settimeout(0.5)
                actual = listener.getsockname()
            except (OSError, ValueError) as error:
                listener.close()
                raise ValueError(f"server bind failed: {error}") from error
            self._listener = listener
            self._state = RendezvousState("running", str(actual[0]),
                                          int(actual[1]), len(self._records))
            thread = threading.Thread(
                target=self._accept, name="lan-atlas-rendezvous", daemon=True)
            self._thread = thread
            thread.start()
            return self._state

    def stop(self) -> None:
        """Request shutdown and unblock the accept loop promptly."""
        with self._lock:
            thread = self._thread
            listener = self._listener
            if thread is None or not thread.is_alive():
                if self._state.phase != "failed":
                    self._state = RendezvousState()
                return
            self._state = RendezvousState(
                "stopping", self._state.host, self._state.port,
                self._state.entries)
            self._stop.set()
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    logger.debug("Could not close server listener", exc_info=True)

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

    def state(self) -> RendezvousState:
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
                        logger.exception("Rendezvous listener failed: %s", error)
                    break
                with self._lock:
                    if self._active >= RV_MAX_CONNECTIONS or self._stop.is_set():
                        full = True
                    else:
                        full = False
                        self._active += 1
                if full:
                    try:
                        client.close()
                    except OSError:
                        logger.debug("Could not close excess client", exc_info=True)
                    continue
                worker = threading.Thread(
                    target=self._handled, args=(client,),
                    name="lan-atlas-rv-conn", daemon=True)
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
                    self._state = RendezvousState()
                else:
                    self._state = RendezvousState(
                        "failed", self._state.host, self._state.port,
                        self._state.entries, failed)

    def _handled(self, conn: socket.socket) -> None:
        try:
            self._handle(conn)
        finally:
            with self._lock:
                self._active = max(0, self._active - 1)
                self._handlers = [item for item in self._handlers
                                  if item is not threading.current_thread()
                                  and item.is_alive()]

    def _handle(self, conn: socket.socket) -> None:
        try:
            with conn:
                conn.settimeout(5.0)
                message = recv_message(conn)
                if message is None:
                    return
                validate_envelope(message)
                if message["type"] == "RV_ANNOUNCE":
                    check_announcement(message["body"]["entry"])
                    self._store(message["body"]["entry"])
                    send_message(conn, envelope(
                        "ACK", message["peer_id"], message["session_id"],
                        {"status": "accepted"}, message["message_id"]))
                elif message["type"] == "RV_QUERY":
                    body = serve_query(self, message["body"])
                    send_message(conn, envelope(
                        "RV_PAGE", message["peer_id"], message["session_id"],
                        body, message["message_id"]))
                else:
                    raise ProtocolError("rendezvous accepts RV frames only")
        except (OSError, ProtocolError, ValueError) as error:
            logger.debug("Rendezvous connection ended: %s", error)

    def _store(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self._expire_locked(time.monotonic())
            key = entry["peer_id"]
            self._records[key] = _Record(dict(entry), time.monotonic())
            self._records.move_to_end(key)
            while len(self._records) > self.max_entries:
                self._records.popitem(last=False)

    def _expire_locked(self, now: float) -> None:
        expired = [key for key, record in self._records.items()
                   if now - record.last_seen >= self.entry_ttl]
        for key in expired:
            del self._records[key]

    def snapshot(self) -> list[dict[str, Any]]:
        """Return live entries newest first for page slicing."""
        with self._lock:
            self._expire_locked(time.monotonic())
            return [record.data for record in
                    sorted(self._records.values(),
                           key=lambda item: item.last_seen, reverse=True)]


def serve_query(server: RendezvousServer,
                body: dict[str, Any]) -> dict[str, Any]:
    """Answer one RV_QUERY from live entries only."""
    if not isinstance(body, dict):
        raise ValueError("query body must be an object")
    limit = body.get("limit")
    if type(limit) is not int or not 1 <= limit <= RV_PAGE_LIMIT_MAX:
        raise ValueError("limit must be 1 to 50")
    entries = server.snapshot()
    cursor = body.get("cursor")
    start = 0
    if cursor is not None:
        if not isinstance(cursor, dict):
            raise ValueError("cursor must be an object or null")
        _canonical_id(cursor.get("last_peer"), "cursor last_peer")
        positions = [index for index, entry in enumerate(entries)
                     if entry["peer_id"] == cursor["last_peer"]]
        start = positions[-1] + 1 if positions else len(entries)
    page = entries[start:start + body["limit"]]
    complete = start + len(page) >= len(entries)
    return {
        "entries": page,
        "next_cursor": {"last_peer": page[-1]["peer_id"]} if page else None,
        "complete": complete,
    }


def announce_once(host: str, port: int, entry: dict[str, Any],
                  peer_id: str, session_id: str,
                  timeout: float = 5.0) -> None:
    """Publish one signed announcement and require server acceptance.

    The ACK is an untrusted receipt only; it proves the server stored
    bytes, not that any peer will ever see them."""
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        send_message(conn, envelope("RV_ANNOUNCE", peer_id, session_id,
                                    {"entry": entry}))
        reply = recv_message(conn)
    if reply is None:
        raise ProtocolError("no announcement response")
    validate_envelope(reply)
    if (reply["type"] != "ACK"
            or reply["body"].get("status") != "accepted"):
        raise ProtocolError("announcement not accepted")


def query(host: str, port: int, peer_id: str, session_id: str,
          limit: int = 50, timeout: float = 5.0) -> dict[str, Any]:
    """Fetch one directory page from a rendezvous server."""
    if type(limit) is not int or not 1 <= limit <= RV_PAGE_LIMIT_MAX:
        raise ValueError("limit must be 1 to 50")
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        send_message(conn, envelope("RV_QUERY", peer_id, session_id,
                                    {"cursor": None, "limit": limit}))
        reply = recv_message(conn)
    if reply is None:
        raise ProtocolError("no directory response")
    validate_envelope(reply)
    if reply["type"] != "RV_PAGE":
        raise ProtocolError("invalid directory response")
    return reply["body"]


def query_all(host: str, port: int, peer_id: str, session_id: str,
              max_pages: int = 5, timeout: float = 5.0) -> list[dict[str, Any]]:
    """Fetch bounded directory pages following cursors to completion."""
    if type(max_pages) is not int or not 1 <= max_pages <= 20:
        raise ValueError("max pages must be 1 to 20")
    collected: list[dict[str, Any]] = []
    cursor: dict[str, Any] | None = None
    for _ in range(max_pages):
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            send_message(conn, envelope("RV_QUERY", peer_id, session_id,
                                        {"cursor": cursor, "limit": 50}))
            reply = recv_message(conn)
        if reply is None:
            raise ProtocolError("no directory response")
        validate_envelope(reply)
        if reply["type"] != "RV_PAGE":
            raise ProtocolError("invalid directory response")
        for raw in reply["body"]["entries"]:
            if isinstance(raw, dict):
                collected.append(raw)
        if reply["body"]["complete"]:
            return collected
        cursor = reply["body"]["next_cursor"]
    return collected
