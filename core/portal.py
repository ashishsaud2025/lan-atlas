"""Bounded read-only HTTP portal for explicitly selected LAN interfaces."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv4Address, ip_address
import json
import logging
import secrets
import threading
import time
from collections import OrderedDict
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from core.discovery import Hello
from core.message_journal import MessageJournal
from core.peer_repository import PeerRepository
from core.services import (DirectoryEntry, DirectoryKind, LocalServiceDirectory,
                           browser_url)
from core.storage import PostStore

PORTAL_PORT = 8080
REQUEST_TIMEOUT = 2.0
PAGE_LIMIT = 50
MAX_GUESTS = 128
GUEST_TTL_S = 86400.0
MAX_DISPLAY_NAME = 64
MAX_CHAT_TEXT = 2000
MAX_CHAT_BODY = 16384
CHAT_RATE_S = 1.0
MAX_FEED_TEXT = 5000
MAX_FEED_BODY = 32768


class GuestStore:
    """Bound open-LAN guest sessions keyed by random cookie value."""

    def __init__(self) -> None:
        self._guests: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._lock = threading.Lock()

    def claim(self, display_name: str, cookie: str | None) -> tuple[str, str]:
        """Claim or refresh one guest session for an open LAN browser."""
        name = _validate_display_name(display_name)
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            existing = _extract_guest_id(cookie)
            if existing is not None and existing in self._guests:
                self._guests[existing] = (name, now)
                self._guests.move_to_end(existing)
                return existing, ""
            guest_id = secrets.token_hex(16)
            while guest_id in self._guests:
                guest_id = secrets.token_hex(16)
            self._guests[guest_id] = (name, now)
            while len(self._guests) > MAX_GUESTS:
                self._guests.popitem(last=False)
            return guest_id, f"guest_id={guest_id}; Path=/; HttpOnly; SameSite=Lax"

    def resolve(self, cookie: str | None) -> str | None:
        """Return the live guest ID for a cookie header, if present."""
        guest_id = _extract_guest_id(cookie)
        if guest_id is None:
            return None
        with self._lock:
            entry = self._guests.get(guest_id)
            if entry is None:
                return None
            name, _ = entry
            now = time.monotonic()
            self._expire(now)
            if guest_id not in self._guests:
                return None
            self._guests[guest_id] = (name, now)
            self._guests.move_to_end(guest_id)
            return guest_id

    def display(self, guest_id: str) -> str:
        """Return the display label for one live guest."""
        with self._lock:
            return self._guests[guest_id][0]

    def identity(self, guest_id: str) -> str:
        """Guests are never authenticated, even when names collide."""
        with self._lock:
            self._guests[guest_id]
            return "unverified_guest"

    def _expire(self, now: float) -> None:
        stale = [key for key, (_, seen) in self._guests.items()
                 if now - seen > GUEST_TTL_S]
        for key in stale:
            del self._guests[key]


def _validate_display_name(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("display name must be text")
    name = value.strip()
    if not name or len(name) > MAX_DISPLAY_NAME:
        raise ValueError("display name must contain 1 to 64 characters")
    if any(ord(char) < 32 or char == "\x7f" for char in name):
        raise ValueError("display name contains control characters")
    return name


def _extract_guest_id(cookie: object) -> str | None:
    if not isinstance(cookie, str) or not cookie:
        return None
    for part in cookie.split(";"):
        item = part.strip()
        if item.startswith("guest_id="):
            candidate = item[len("guest_id="):].strip()
            if len(candidate) == 32 and all(
                    char in "0123456789abcdef" for char in candidate):
                return candidate
            return None
    bare = cookie.strip()
    if len(bare) == 32 and all(
            char in "0123456789abcdef" for char in bare):
        return bare
    return None


@dataclass(frozen=True)
class PortalState:
    """Immutable server lifecycle state for desktop presentation."""

    phase: str = "stopped"
    address: str | None = None
    port: int | None = None
    error: str | None = None

    @property
    def url(self) -> str | None:
        """Return the current browser URL when the listener has an address."""
        if self.address is None or self.port is None:
            return None
        return f"http://{self.address}:{self.port}"


class PortalContent:
    """Expose copied core snapshots without granting administrative access."""

    def __init__(self, hello: Hello, peers: PeerRepository,
                 posts: PostStore | None,
                 messages: MessageJournal | None = None,
                 directory: LocalServiceDirectory | None = None,
                 room_sender: Any | None = None) -> None:
        self.hello = hello
        self.peers = peers
        self.posts = posts
        self.messages_store = messages or MessageJournal()
        self.directory_store = directory or LocalServiceDirectory(hello)
        self.room_sender = room_sender
        self.guests = GuestStore()
        self._chat_last: dict[str, float] = {}
        self._chat_lock = threading.Lock()

    def publish_room(self, display_name: str, text: str,
                     cookie: str | None) -> tuple[str, str | None]:
        """Relay one guest room message through the existing chat fan-out."""
        if self.room_sender is None:
            raise RuntimeError("room sends are not configured")
        name = _validate_display_name(display_name)
        if not isinstance(text, str):
            raise ValueError("chat text must be text")
        message = text.strip()
        if not message:
            raise ValueError("chat text must not be empty")
        if len(message) > MAX_CHAT_TEXT:
            raise ValueError("chat text exceeds 2000 characters")
        guest_id, set_cookie = self.guests.claim(name, cookie)
        now = time.monotonic()
        with self._chat_lock:
            last = self._chat_last.get(guest_id, 0.0)
            if now - last < CHAT_RATE_S:
                raise RuntimeError("slow down")
            self._chat_last[guest_id] = now
        try:
            message_id = self.room_sender(name, message)
        except RuntimeError:
            with self._chat_lock:
                self._chat_last.pop(guest_id, None)
            raise
        if not isinstance(message_id, str) or not message_id:
            raise RuntimeError("room sender returned no message ID")
        header = (f"guest_id={guest_id}; Path=/; HttpOnly; SameSite=Lax"
                  if set_cookie else None)
        return message_id, header

    def publish_feed(self, display_name: str, text: str,
                     cookie: str | None) -> tuple[str, str | None]:
        """Store one unsigned guest post without forging authorship."""
        if self.posts is None:
            raise RuntimeError("post storage is not configured")
        name = _validate_display_name(display_name)
        if not isinstance(text, str):
            raise ValueError("post text must be text")
        body = text.strip()
        if not body:
            raise ValueError("post text must not be empty")
        if len(body) > MAX_FEED_TEXT:
            raise ValueError("post text exceeds 5000 characters")
        guest_id, set_cookie = self.guests.claim(name, cookie)
        post = {"post_id": str(uuid4()), "author_id": self.hello.peer_id,
                "text": body, "created_ms": time.time_ns() // 1_000_000,
                "refs": [], "guest_name": name, "guest_id": guest_id}
        try:
            stored = self.posts.add(post)
        except ValueError as error:
            raise ValueError(str(error) or "Invalid post.") from error
        if not stored:
            raise RuntimeError("generated duplicate post ID")
        header = (f"guest_id={guest_id}; Path=/; HttpOnly; SameSite=Lax"
                  if set_cookie else None)
        return post["post_id"], header

    def status(self) -> dict[str, Any]:
        """Return current local and peer summary evidence."""
        summary = self.peers.overview_summary()
        return {
            "version": 1,
            "node": self.hello.name,
            "application_port": self.hello.tcp_port,
            "capabilities": list(self.hello.capabilities),
            "security": {
                "trust": "unverified",
                "transport": "plaintext",
            },
            "peers": {
                "observed": summary.observed,
                "nearby": summary.nearby,
                "stale": summary.stale,
                "responsive": summary.responsive,
                "measured": summary.measured,
                "latency_ms": {
                    "min": summary.min_ms,
                    "average": summary.avg_ms,
                    "max": summary.max_ms,
                },
            },
        }

    def feed(self) -> dict[str, Any]:
        """Return at most one bounded page from local and cached posts."""
        if self.posts is None:
            return {
                "available": False,
                "items": [],
                "complete": True,
                "reason": "Post storage is not configured.",
            }
        posts, next_cursor, complete = self.posts.page(PAGE_LIMIT)
        names = {record.hello.peer_id: record.hello.name
                 for record in self.peers.snapshot()}
        names[self.hello.peer_id] = self.hello.name
        items = []
        for post in posts:
            guest = post.get("guest_name") if isinstance(post, dict) else None
            if isinstance(guest, str) and guest:
                items.append({**post, "author_name": f"{guest} (guest)",
                              "provenance": "guest_unverified"})
            else:
                items.append({**post, "author_name": names.get(post["author_id"],
                                                               post["author_id"]),
                              "provenance": ("published_local" if post["author_id"]
                                             == self.hello.peer_id else "cached_copy")})
        return {
            "available": True,
            "items": items,
            "complete": complete,
            "next_cursor": next_cursor,
        }

    def messages(self) -> dict[str, Any]:
        """Return bounded room history without exposing direct messages."""
        snapshot = self.messages_store.snapshot()
        room = tuple(entry for entry in snapshot.entries if entry.scope == "room")
        visible = room[-PAGE_LIMIT:]
        items = [{
            "message_id": entry.message_id,
            "direction": entry.direction,
            "scope": entry.scope,
            "text": entry.text,
            "recorded_ms": entry.recorded_ms,
            "sender": {
                "name": entry.sender_name,
                "identity": "unverified",
            },
            "delivery": {
                state: sum(delivery.state == state
                           for delivery in entry.deliveries)
                for state in ("queued", "accepted", "failed", "uncertain")
            },
        } for entry in visible]
        return {
            "available": True,
            "items": items,
            "complete": len(room) <= PAGE_LIMIT,
            "retention": "process_lifetime_bounded",
        }

    def directory(self, kind: DirectoryKind) -> dict[str, Any]:
        """Return local publications with separate evidence fields."""
        snapshot = self.directory_store.snapshot(kind)
        return {
            "available": True,
            "scope": "local_session",
            "complete": True,
            "items": [_directory_value(entry) for entry in snapshot.entries],
        }

    def unavailable(self, kind: str) -> dict[str, Any]:
        """Return an honest empty result for a service without a core registry."""
        reasons = {
            "files": "No files have been explicitly published for browser access.",
        }
        return {"available": False, "items": [], "reason": reasons[kind]}


class _PortalHttpServer(HTTPServer):
    allow_reuse_address = True
    request_queue_size = 8

    def __init__(self, address: tuple[str, int], content: PortalContent) -> None:
        self.content = content
        super().__init__(address, _PortalHandler)
        self.timeout = 0.1


class _PortalHandler(BaseHTTPRequestHandler):
    server: _PortalHttpServer
    server_version = "LANAtlasPortal/1"
    sys_version = ""

    def setup(self) -> None:
        """Apply one finite request and response deadline per connection."""
        super().setup()
        self.connection.settimeout(REQUEST_TIMEOUT)

    def do_GET(self) -> None:
        """Serve one read-only HTML page or JSON snapshot."""
        self._handle(include_body=True)

    def do_HEAD(self) -> None:
        """Serve GET metadata without a response body."""
        self._handle(include_body=False)

    def do_POST(self) -> None:
        """Serve bounded guest writes; all other writes stay rejected."""
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == "/api/chat/send":
            self._handle_post_chat()
            return
        if path == "/api/feed/post":
            self._handle_post_feed()
            return
        self._method_not_allowed()

    def do_PUT(self) -> None:
        """Reject unsupported replacement requests."""
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        """Reject unsupported mutation requests."""
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        """Reject unsupported deletion requests."""
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:
        """Report the deliberately read-only method surface."""
        self._send(HTTPStatus.NO_CONTENT, "text/plain; charset=utf-8", b"",
                   include_body=False, extra_headers={"Allow": "GET, HEAD"})

    def log_message(self, format_string: str, *args: object) -> None:
        """Send bounded request records through project logging."""
        logging.info("Portal %s - %s", self.client_address[0],
                     format_string % args)

    def _handle(self, include_body: bool) -> None:
        try:
            status, content_type, body = self._route()
        except (OSError, TypeError, ValueError) as error:
            logging.exception("Portal request failed: %s", error)
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            content_type = "application/json; charset=utf-8"
            body = _json_bytes({"error": "Portal snapshot unavailable."})
        self._send(status, content_type, body, include_body)

    def _route(self) -> tuple[HTTPStatus, str, bytes]:
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == "/api/status":
            return _json_response(self.server.content.status())
        if path == "/api/feed":
            return _json_response(self.server.content.feed())
        if path == "/api/messages":
            return _json_response(self.server.content.messages())
        if path == "/api/services":
            return _json_response(self.server.content.directory(
                DirectoryKind.SERVICE))
        if path == "/api/games":
            return _json_response(self.server.content.directory(
                DirectoryKind.GAME))
        api_kinds = {"/api/files": "files"}
        if path in api_kinds:
            return _json_response(self.server.content.unavailable(api_kinds[path]))
        if path in {"/", "/files", "/chat", "/feed", "/services", "/games"}:
            body = _render_page(path, self.server.content).encode("utf-8")
            return HTTPStatus.OK, "text/html; charset=utf-8", body
        return _json_response({"error": "Not found."}, HTTPStatus.NOT_FOUND)

    def _method_not_allowed(self) -> None:
        body = _json_bytes({
            "error": "Portal writes are disabled.",
            "allowed": ["GET", "HEAD"],
        })
        self._send(HTTPStatus.METHOD_NOT_ALLOWED,
                   "application/json; charset=utf-8", body, True,
                   {"Allow": "GET, HEAD"})

    def _handle_post_chat(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Content length invalid."})
            return
        if length <= 0 or length > MAX_CHAT_BODY:
            code = HTTPStatus.REQUEST_ENTITY_TOO_LARGE if length > MAX_CHAT_BODY else HTTPStatus.BAD_REQUEST
            self._send_json(code, {"error": "Request body outside allowed range."})
            return
        try:
            raw = self.rfile.read(length)
        except (OSError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Request body unreadable."})
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Request body is not valid JSON."})
            return
        if not isinstance(payload, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Request body must be an object."})
            return
        try:
            message_id, set_cookie = self.server.content.publish_room(
                payload.get("display_name"), payload.get("text"),
                self.headers.get("Cookie"))
        except ValueError as error:
            text = str(error)
            code = (HTTPStatus.REQUEST_ENTITY_TOO_LARGE
                    if "exceeds 2000" in text else HTTPStatus.BAD_REQUEST)
            self._send_json(code, {"error": text or "Invalid chat send."})
            return
        except RuntimeError as error:
            text = str(error)
            if "slow down" in text or "queue full" in text:
                self._send_json(HTTPStatus.TOO_MANY_REQUESTS,
                                {"error": "Server busy, retry shortly."})
            else:
                self._send_json(HTTPStatus.SERVICE_UNAVAILABLE,
                                {"error": "Room sends are not configured."})
            return
        extra = {"Set-Cookie": set_cookie} if set_cookie else None
        self._send_json(HTTPStatus.OK, {"message_id": message_id}, extra)

    def _handle_post_feed(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Content length invalid."})
            return
        if length <= 0 or length > MAX_FEED_BODY:
            code = HTTPStatus.REQUEST_ENTITY_TOO_LARGE if length > MAX_FEED_BODY else HTTPStatus.BAD_REQUEST
            self._send_json(code, {"error": "Request body outside allowed range."})
            return
        try:
            raw = self.rfile.read(length)
        except (OSError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Request body unreadable."})
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Request body is not valid JSON."})
            return
        if not isinstance(payload, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Request body must be an object."})
            return
        try:
            post_id, set_cookie = self.server.content.publish_feed(
                payload.get("display_name"), payload.get("text"),
                self.headers.get("Cookie"))
        except ValueError as error:
            text = str(error)
            code = (HTTPStatus.REQUEST_ENTITY_TOO_LARGE
                    if "exceeds 5000" in text else HTTPStatus.BAD_REQUEST)
            self._send_json(code, {"error": text or "Invalid feed post."})
            return
        except RuntimeError as error:
            text = str(error)
            if "duplicate" in text:
                self._send_json(HTTPStatus.TOO_MANY_REQUESTS,
                                {"error": "Server busy, retry shortly."})
            else:
                self._send_json(HTTPStatus.SERVICE_UNAVAILABLE,
                                {"error": text or "Feed posts are not configured."})
            return
        extra = {"Set-Cookie": set_cookie} if set_cookie else None
        self._send_json(HTTPStatus.OK, {"post_id": post_id}, extra)

    def _send_json(self, status: HTTPStatus, value: dict[str, Any],
                   extra: dict[str, str] | None = None) -> None:
        self._send(status, "application/json; charset=utf-8",
                   _json_bytes(value), True, extra)

    def _send(self, status: HTTPStatus, content_type: str, body: bytes,
              include_body: bool, extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.close_connection = True
        if include_body and body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, TimeoutError) as error:
                logging.debug("Portal client left before response completed: %s", error)


class PortalServer:
    """Own one bounded HTTP worker and an explicitly selected IPv4 listener."""

    def __init__(self, hello: Hello, peers: PeerRepository,
                 posts: PostStore | None = None,
                 messages: MessageJournal | None = None,
                 directory: LocalServiceDirectory | None = None,
                 room_sender: Any | None = None,
                 allow_loopback: bool = False) -> None:
        self.content = PortalContent(hello, peers, posts, messages, directory,
                                     room_sender)
        self.allow_loopback = allow_loopback
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._server: _PortalHttpServer | None = None
        self._thread: threading.Thread | None = None
        self._state = PortalState()

    def start(self, address: str, port: int = PORTAL_PORT) -> PortalState:
        """Bind synchronously, then serve from one owned daemon worker."""
        parsed = ip_address(address)
        if not isinstance(parsed, IPv4Address):
            raise ValueError("portal requires an IPv4 bind address")
        if (parsed.is_unspecified or parsed.is_link_local or parsed.is_multicast
                or parsed.is_reserved
                or parsed.is_loopback and not self.allow_loopback):
            raise ValueError("select one concrete LAN interface address")
        if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
            raise ValueError("portal port must be from 0 through 65535")
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("portal is already running or stopping")
            self._stop.clear()
            try:
                server = _PortalHttpServer((str(parsed), port), self.content)
            except OSError as error:
                self._state = PortalState("failed", str(parsed), port, str(error))
                raise
            actual_address, actual_port = server.server_address[:2]
            self._server = server
            self._state = PortalState("running", str(actual_address),
                                      int(actual_port))
            thread = threading.Thread(
                target=self._serve, name="lan-atlas-portal", daemon=True)
            self._thread = thread
            try:
                thread.start()
            except RuntimeError:
                server.server_close()
                self._server = None
                self._state = PortalState("failed", str(actual_address),
                                          int(actual_port),
                                          "portal worker did not start")
                raise
            return self._state

    def stop(self) -> None:
        """Request worker cancellation without waiting in the Qt event loop."""
        with self._lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                if self._state.phase != "failed":
                    self._state = PortalState()
                return
            self._state = PortalState("stopping", self._state.address,
                                      self._state.port)
            self._stop.set()

    def join(self, timeout: float = 3.0) -> bool:
        """Wait a finite interval for the portal worker to release its port."""
        if timeout < 0:
            raise ValueError("timeout must not be negative")
        with self._lock:
            thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def state(self) -> PortalState:
        """Return one immutable lifecycle snapshot."""
        with self._lock:
            return self._state

    def _serve(self) -> None:
        with self._lock:
            server = self._server
        if server is None:
            return
        failed: str | None = None
        try:
            while not self._stop.is_set():
                server.handle_request()
        except OSError as error:
            if not self._stop.is_set():
                failed = str(error)
                logging.exception("Portal listener failed: %s", error)
            else:
                logging.debug("Portal listener closed during shutdown: %s", error)
        finally:
            server.server_close()
            with self._lock:
                self._server = None
                if failed is None:
                    self._state = PortalState()
                else:
                    self._state = PortalState("failed", self._state.address,
                                              self._state.port, failed)


def _json_response(value: dict[str, Any],
                   status: HTTPStatus = HTTPStatus.OK) -> tuple[HTTPStatus, str, bytes]:
    return status, "application/json; charset=utf-8", _json_bytes(value)


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def _render_page(path: str, content: PortalContent) -> str:
    status = content.status()
    title, page = _page_content(path, content, status)
    node = escape(str(status["node"]))
    nav = "".join(
        f'<a class="nav{(" active" if path == href else "")}" href="{href}">{label}</a>'
        for href, label in (("/", "Home"), ("/files", "Files"),
                            ("/chat", "Chat"), ("/feed", "Feed"),
                            ("/services", "Services"), ("/games", "Games")))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} | LAN Atlas Portal</title>
<style>
:root {{ color-scheme: dark; --bg:#071018; --panel:#101c27; --line:#253746;
  --text:#e7f0f5; --muted:#95a8b5; --teal:#56e0cf; --amber:#f0bd63; }}
* {{ box-sizing:border-box; }} body {{ margin:0; background:var(--bg); color:var(--text);
  font:16px/1.5 Inter,system-ui,sans-serif; }} header,main {{ width:min(980px,92vw);
  margin:auto; }} header {{ padding:28px 0 18px; }} .eyebrow {{ color:var(--teal);
  font:700 12px ui-monospace,monospace; letter-spacing:.16em; }} h1 {{ margin:.25rem 0;
  font-size:clamp(1.8rem,5vw,3.2rem); }} .muted {{ color:var(--muted); }} nav {{ display:flex;
  gap:8px; overflow-x:auto; padding:12px 0 22px; }} .nav {{ color:var(--muted);
  text-decoration:none; border:1px solid var(--line); border-radius:999px; padding:8px 13px;
  white-space:nowrap; }} .nav.active,.nav:hover {{ color:var(--teal); border-color:var(--teal); }}
.notice {{ border:1px solid #6f5427; color:var(--amber); background:#211b13; padding:12px 14px;
  border-radius:10px; margin-bottom:18px; }} .grid {{ display:grid;
  grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:14px; }} .card {{ display:block;
  color:inherit; text-decoration:none; border:1px solid var(--line); background:var(--panel);
  padding:18px; border-radius:12px; }} .card:hover {{ border-color:var(--teal); }}
.metric {{ color:var(--teal); font:700 2rem ui-monospace,monospace; }} .post {{ margin:0 0 14px;
  border-left:3px solid var(--teal); }} .meta {{ color:var(--muted);
  font:12px ui-monospace,monospace; }} footer {{ color:var(--muted); padding:38px 0;
  font-size:13px; }} code {{ font-family:ui-monospace,monospace; }}
</style>
</head>
<body>
<header><div class="eyebrow">LAN ATLAS PORTAL</div><h1>{node}</h1>
<div class="muted">Selected services from this device, available without Internet.</div>
<nav>{nav}</nav></header>
<main><div class="notice">Unverified LAN. Traffic is plaintext and browser writes are disabled.</div>
{page}<footer>Hosted directly by {node}. Administrative tools are not exposed.</footer></main>
</body>
</html>"""


def _page_content(path: str, content: PortalContent,
                  status: dict[str, Any]) -> tuple[str, str]:
    peers = status["peers"]
    if path == "/":
        cards = (
            ("/files", "Files", "No public catalog yet"),
            ("/chat", "Chat", "Read-only nearby room history"),
            ("/feed", "Feed", "Local and cached posts"),
            ("/services", "Services", "Explicit local publications"),
            ("/games", "Games", "Explicit local sessions"),
        )
        links = "".join(
            f'<a class="card" href="{href}"><h2>{label}</h2>'
            f'<div class="muted">{detail}</div></a>'
            for href, label, detail in cards)
        summary = (f'<section class="grid"><div class="card"><div class="metric">'
                   f'{peers["nearby"]}</div><div>Nearby sessions</div></div>'
                   f'<div class="card"><div class="metric">{peers["responsive"]}</div>'
                   f'<div>Measured responsive</div></div></section><h2>Portal services</h2>'
                   f'<section class="grid">{links}</section>')
        return "Home", summary
    if path == "/feed":
        feed = content.feed()
        if not feed["available"]:
            return "Feed", _empty_card("Feed unavailable", feed["reason"])
        posts = "".join(_post_card(post) for post in feed["items"])
        return "Feed", (f"<h2>Local and cached feed</h2>{posts}" if posts else
                        _empty_card("No cached posts", "Sync or publish from the desktop app."))
    if path == "/chat":
        messages = content.messages()
        rows = "".join(_message_card(message) for message in messages["items"])
        return "Chat", (f"<h2>Nearby room history</h2>{rows}" if rows else
                        _empty_card("No room messages", "History is retained for this process only."))
    if path in {"/services", "/games"}:
        kind = DirectoryKind.SERVICE if path == "/services" else DirectoryKind.GAME
        directory = content.directory(kind)
        rows = "".join(_directory_card(entry) for entry in directory["items"])
        title = "Services" if kind is DirectoryKind.SERVICE else "Games"
        return title, (f"<h2>Published {title.lower()}</h2>{rows}" if rows else
                       _empty_card(f"No {title.lower()} published",
                                   "Publish one from desktop Settings."))
    names = {
        "/files": ("Files", "No public files", "files"),
    }
    title, heading, kind = names[path]
    return title, _empty_card(heading, content.unavailable(kind)["reason"])


def _empty_card(title: str, detail: str) -> str:
    return (f'<section class="card"><h2>{escape(title)}</h2>'
            f'<div class="muted">{escape(detail)}</div></section>')


def _post_card(post: dict[str, Any]) -> str:
    created = datetime.fromtimestamp(
        post["created_ms"] / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (f'<article class="card post"><div class="meta">'
            f'{escape(str(post["author_name"]))} | {created} | '
            f'{escape(str(post["provenance"]).replace("_", " "))}</div>'
            f'<p>{escape(str(post["text"]))}</p></article>')


def _message_card(message: dict[str, Any]) -> str:
    created = datetime.fromtimestamp(
        message["recorded_ms"] / 1000,
        tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    states = ", ".join(
        f"{count} {state}" for state, count in message["delivery"].items()
        if count)
    return (f'<article class="card post"><div class="meta">'
            f'{escape(str(message["sender"]["name"]))} | observed {created} | '
            f'{escape(states or "no delivery evidence")}</div>'
            f'<p>{escape(str(message["text"]))}</p></article>')


def _directory_value(entry: DirectoryEntry) -> dict[str, Any]:
    return {
        "service_id": entry.service_id,
        "kind": entry.kind.value,
        "owner": {
            "peer_id": entry.owner_peer_id,
            "session_id": entry.owner_session_id,
            "name": entry.owner_name,
        },
        "name": entry.name,
        "description": entry.description,
        "url": browser_url(entry),
        "evidence": {
            "publication": "published_local",
            "reachability": "not_checked",
            "health": "not_defined",
        },
    }


def _directory_card(entry: dict[str, Any]) -> str:
    url = escape(str(entry["url"]), quote=True)
    description = escape(str(entry["description"] or "No description"))
    return (f'<a class="card post" href="{url}"><div class="meta">'
            'Published locally | Reachability not checked | Health not defined'
            f'</div><h2>{escape(str(entry["name"]))}</h2>'
            f'<p>{description}</p><code>{url}</code></a>')
