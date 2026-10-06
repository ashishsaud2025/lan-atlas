"""Bounded JSON framing and version-one envelopes for all platform clients."""

from __future__ import annotations

import json
import socket
import struct
import time
from typing import Any
from uuid import UUID, uuid4

from core.posts import PAGE_LIMIT_MAX, validate_cursor, validate_post

MAX_MESSAGE_SIZE = 1024 * 1024
MAX_FILE_SIZE = 1024 * 1024 * 1024
IO_TIMEOUT = 5.0
MESSAGE_TYPES = {"ECHO", "ECHO_REPLY", "CHAT", "ACK", "ERROR", "FILE_OFFER",
                 "FILE_ACCEPT", "FILE_DECLINE", "FILE_CHUNK", "FILE_DONE",
                 "FILE_RESULT", "POST_QUERY", "POST_PAGE",
                 "DIR_QUERY", "DIR_PAGE",
                 "RV_ANNOUNCE", "RV_QUERY", "RV_PAGE",
                 "RELAY_ALLOC", "RELAY_JOIN", "RELAY_READY"}
DIR_PAGE_LIMIT_MAX = 50


class ProtocolError(ValueError):
    """The remote or local message violates the application protocol."""


class FramingError(ProtocolError):
    """A length or premature EOF makes the stream unusable."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ProtocolError(f"nonstandard JSON constant: {value}")


def encode_message(message: dict[str, Any]) -> bytes:
    """Encode one object with its unsigned big-endian UTF-8 byte length."""
    if not isinstance(message, dict):
        raise ProtocolError("payload must be a JSON object")
    try:
        payload = json.dumps(message, ensure_ascii=False, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise ProtocolError("payload cannot be encoded as UTF-8 JSON") from error
    if not 1 <= len(payload) <= MAX_MESSAGE_SIZE:
        raise FramingError("payload length outside allowed range")
    return struct.pack("!I", len(payload)) + payload


def _receive_exact(sock: socket.socket, size: int, deadline: float,
                   allow_eof: bool = False) -> bytes | None:
    buffer = bytearray()
    while len(buffer) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("frame receive deadline exceeded")
        sock.settimeout(remaining)
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            if not buffer and allow_eof:
                return None
            raise FramingError("EOF inside a frame")
        buffer.extend(chunk)
    return bytes(buffer)


def recv_message(sock: socket.socket,
                 timeout: float = IO_TIMEOUT) -> dict[str, Any] | None:
    """Read exactly one frame; return None only for EOF before its prefix."""
    previous = sock.gettimeout()
    deadline = time.monotonic() + timeout
    try:
        prefix = _receive_exact(sock, 4, deadline, allow_eof=True)
        if prefix is None:
            return None
        length = struct.unpack("!I", prefix)[0]
        if not 1 <= length <= MAX_MESSAGE_SIZE:
            raise FramingError("payload length outside allowed range")
        payload = _receive_exact(sock, length, deadline)
        try:
            value = json.loads(payload.decode("utf-8"), object_pairs_hook=_pairs,
                               parse_constant=_constant)
            # Re-encoding also rejects lone surrogates and overflowed JSON numbers.
            encode_message(value)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ProtocolError("invalid UTF-8 JSON object") from error
        return value
    finally:
        sock.settimeout(previous)


def send_message(sock: socket.socket, message: dict[str, Any],
                 timeout: float = IO_TIMEOUT) -> None:
    """Send a complete frame within a finite write deadline."""
    frame = encode_message(message)
    previous = sock.gettimeout()
    try:
        sock.settimeout(timeout)
        sock.sendall(frame)
    finally:
        sock.settimeout(previous)


def validate_envelope(message: dict[str, Any]) -> None:
    """Validate version, routing fields, and bodies for implemented message types."""
    if type(message.get("version")) is not int or message["version"] != 1:
        raise ProtocolError("unsupported version")
    if not isinstance(message.get("type"), str) or message["type"] not in MESSAGE_TYPES:
        raise ProtocolError("unsupported message type")
    for key in ("message_id", "peer_id", "session_id"):
        value = message.get(key)
        try:
            if not isinstance(value, str) or str(UUID(value)) != value:
                raise ValueError("noncanonical UUID")
        except ValueError as error:
            raise ProtocolError(f"invalid {key}") from error
    body = message.get("body")
    if not isinstance(body, dict):
        raise ProtocolError("body must be an object")
    if message["type"] in {"ECHO_REPLY", "ACK", "ERROR", "POST_PAGE", "DIR_PAGE",
                             "RV_PAGE"}:
        try:
            UUID(message.get("reply_to", ""))
        except (ValueError, TypeError, AttributeError) as error:
            raise ProtocolError("reply requires reply_to UUID") from error
    if message["type"] == "CHAT":
        text = body.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > 4096:
            raise ProtocolError("chat text must contain 1 to 4096 characters")
        if not isinstance(body.get("scope"), str) or body["scope"] not in {"room", "dm"}:
            raise ProtocolError("invalid chat scope")
        if body["scope"] == "dm":
            try:
                UUID(body.get("to_session", ""))
            except (ValueError, TypeError, AttributeError) as error:
                raise ProtocolError("DM requires recipient session UUID") from error
    if message["type"].startswith("FILE_"):
        transfer_id = body.get("transfer_id")
        try:
            if not isinstance(transfer_id, str) or str(UUID(transfer_id)) != transfer_id:
                raise ValueError("noncanonical UUID")
        except ValueError as error:
            raise ProtocolError("transfer requires transfer_id UUID") from error
    if message["type"] == "FILE_OFFER":
        try:
            UUID(body.get("to_session", ""))
        except (ValueError, TypeError, AttributeError) as error:
            raise ProtocolError("offer requires recipient session UUID") from error
        name = body.get("name")
        if (not isinstance(name, str) or not name.strip() or len(name) > 255
                or name in {".", ".."} or any(c in name for c in "/\\:")
                or any(ord(c) < 32 for c in name)):
            raise ProtocolError("invalid offered filename")
        if type(body.get("size")) is not int or not 0 <= body["size"] <= MAX_FILE_SIZE:
            raise ProtocolError("file size outside allowed range")
        digest = body.get("sha256")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise ProtocolError("invalid SHA-256")
    if message["type"] == "FILE_CHUNK":
        if type(body.get("offset")) is not int or body["offset"] < 0:
            raise ProtocolError("chunk requires nonnegative offset")
        if not isinstance(body.get("data"), str) or not body["data"]:
            raise ProtocolError("chunk requires Base64 data")
    if message["type"] == "FILE_RESULT":
        if body.get("status") != "verified":
            raise ProtocolError("result requires verified status")
        if type(body.get("size")) is not int or not 0 <= body["size"] <= MAX_FILE_SIZE:
            raise ProtocolError("result size outside allowed range")
        digest = body.get("sha256")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise ProtocolError("invalid SHA-256")
    if message["type"] == "POST_QUERY":
        try:
            validate_cursor(body.get("cursor"))
        except ValueError as error:
            raise ProtocolError("invalid post cursor") from error
        if type(body.get("limit")) is not int or not 1 <= body["limit"] <= PAGE_LIMIT_MAX:
            raise ProtocolError("post page limit must be 1 to 50")
        author = body.get("author_id")
        if author is not None:
            try:
                if str(UUID(author)) != author:
                    raise ValueError("noncanonical UUID")
            except (ValueError, TypeError, AttributeError) as error:
                raise ProtocolError("invalid post author filter") from error
    if message["type"] == "POST_PAGE":
        posts = body.get("posts")
        if not isinstance(posts, list) or len(posts) > PAGE_LIMIT_MAX:
            raise ProtocolError("post page must list at most 50 posts")
        try:
            for post in posts:
                validate_post(post)
        except ValueError as error:
            raise ProtocolError("invalid post in page") from error
        try:
            next_cursor = validate_cursor(body.get("next_cursor"))
        except ValueError as error:
            raise ProtocolError("invalid post next cursor") from error
        if type(body.get("complete")) is not bool:
            raise ProtocolError("post page requires complete flag")
        if not posts and not body["complete"]:
            raise ProtocolError("empty post page must be complete")
        if not body["complete"] and next_cursor is None:
            raise ProtocolError("incomplete post page requires next cursor")
    if message["type"] == "DIR_QUERY":
        from core.directory_sync import validate_cursor as validate_dir_cursor
        try:
            validate_dir_cursor(body.get("cursor"))
        except ValueError as error:
            raise ProtocolError("invalid directory cursor") from error
        if type(body.get("limit")) is not int or not 1 <= body["limit"] <= DIR_PAGE_LIMIT_MAX:
            raise ProtocolError("directory page limit must be 1 to 50")
        kind = body.get("kind")
        if kind is not None and kind not in {"service", "game"}:
            raise ProtocolError("directory kind must be service, game, or null")
    if message["type"] == "DIR_PAGE":
        from core.services import validate_directory_entry
        from core.directory_sync import validate_cursor as validate_dir_cursor
        entries = body.get("entries")
        if not isinstance(entries, list) or len(entries) > DIR_PAGE_LIMIT_MAX:
            raise ProtocolError("directory page must list at most 50 entries")
        try:
            for raw in entries:
                validate_directory_entry(raw)
        except ValueError as error:
            raise ProtocolError("invalid entry in directory page") from error
        try:
            next_cursor = validate_dir_cursor(body.get("next_cursor"))
        except ValueError as error:
            raise ProtocolError("invalid directory next cursor") from error
        if type(body.get("complete")) is not bool:
            raise ProtocolError("directory page requires complete flag")
        if not entries and not body["complete"]:
            raise ProtocolError("empty directory page must be complete")
        if not body["complete"] and next_cursor is None:
            raise ProtocolError("incomplete directory page requires next cursor")
    if message["type"] == "RV_ANNOUNCE":
        from core.rendezvous import check_announcement
        entry = body.get("entry")
        if entry is None:
            raise ProtocolError("rendezvous announcement requires entry")
        try:
            check_announcement(entry)
        except ValueError as error:
            raise ProtocolError(f"invalid rendezvous entry: {error}") from error
    if message["type"] == "RV_QUERY":
        try:
            cursor = body.get("cursor")
            if cursor is not None:
                if not isinstance(cursor, dict):
                    raise ValueError("cursor must be an object or null")
                last = cursor.get("last_peer")
                if not isinstance(last, str) or str(UUID(last)) != last:
                    raise ValueError("invalid cursor last_peer")
            if type(body.get("limit")) is not int or not 1 <= body["limit"] <= 50:
                raise ValueError("limit must be 1 to 50")
        except (ValueError, TypeError, AttributeError) as error:
            raise ProtocolError(f"invalid rendezvous query: {error}") from error
    if message["type"] == "RV_PAGE":
        from core.rendezvous import check_announcement as check_rv
        entries = body.get("entries")
        if not isinstance(entries, list) or len(entries) > 50:
            raise ProtocolError("rendezvous page must list at most 50 entries")
        try:
            for raw in entries:
                check_rv(raw)
        except ValueError as error:
            raise ProtocolError(f"invalid entry in rendezvous page: {error}") from error
        try:
            next_cursor = body.get("next_cursor")
            if next_cursor is not None:
                if not isinstance(next_cursor, dict):
                    raise ValueError("cursor must be an object or null")
                last = next_cursor.get("last_peer")
                if not isinstance(last, str) or str(UUID(last)) != last:
                    raise ValueError("invalid cursor last_peer")
        except (ValueError, TypeError, AttributeError) as error:
            raise ProtocolError("invalid rendezvous next cursor") from error
        if type(body.get("complete")) is not bool:
            raise ProtocolError("rendezvous page requires complete flag")
        if not entries and not body["complete"]:
            raise ProtocolError("empty rendezvous page must be complete")
        if not body["complete"] and next_cursor is None:
            raise ProtocolError("incomplete rendezvous page requires next cursor")
    if message["type"] == "RELAY_ALLOC":
        if body != {}:
            raise ProtocolError("relay allocation takes no arguments")
    if message["type"] == "RELAY_JOIN":
        token = body.get("token")
        if (not isinstance(token, str) or len(token) != 32
                or any(c not in "0123456789abcdef" for c in token)):
            raise ProtocolError("relay join requires a 32 hex token")
    if message["type"] == "RELAY_READY":
        if body != {}:
            raise ProtocolError("relay ready takes no arguments")


def envelope(kind: str, peer_id: str, session_id: str, body: dict[str, Any],
             reply_to: str | None = None) -> dict[str, Any]:
    """Construct a validated request or correlated response."""
    message = {"version": 1, "type": kind, "message_id": str(uuid4()),
               "peer_id": peer_id, "session_id": session_id, "body": body}
    if reply_to is not None:
        message["reply_to"] = reply_to
    validate_envelope(message)
    return message
