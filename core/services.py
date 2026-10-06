"""Bounded local service and game publication directory."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, ip_address
import json
import os
from pathlib import Path
import tempfile
import threading
from urllib.parse import quote
from uuid import UUID, uuid4

from core.discovery import Hello

DIRECTORY_LIMIT = 64
CACHE_LIMIT = 256
NAME_LIMIT = 80
DESCRIPTION_LIMIT = 500
PATH_LIMIT = 255


class DirectoryKind(Enum):
    """Locally published entry category."""

    SERVICE = "service"
    GAME = "game"


@dataclass(frozen=True)
class DirectoryEntry:
    """Validated local publication without inferred availability evidence."""

    service_id: str
    owner_peer_id: str
    owner_session_id: str
    owner_name: str
    kind: DirectoryKind
    name: str
    description: str
    scheme: str
    host: str
    port: int
    path: str


@dataclass(frozen=True)
class DirectorySnapshot:
    """Immutable revisioned directory snapshot."""

    revision: int
    entries: tuple[DirectoryEntry, ...]


class LocalServiceDirectory:
    """Publish bounded session-local entries for desktop and portal views."""

    def __init__(self, owner: Hello, limit: int = DIRECTORY_LIMIT) -> None:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("directory limit must be a positive integer")
        self.owner = owner
        self.limit = limit
        self._entries: dict[str, DirectoryEntry] = {}
        self._revision = 0
        self._lock = threading.Lock()

    def register(self, kind: DirectoryKind | str, name: str, description: str,
                 scheme: str, host: str, port: int, path: str) -> DirectoryEntry:
        """Publish one validated local service or game for this session."""
        entry = self._entry(str(uuid4()), kind, name, description,
                            scheme, host, port, path)
        with self._lock:
            if len(self._entries) >= self.limit:
                raise RuntimeError("local directory is full")
            self._entries[entry.service_id] = entry
            self._revision += 1
        return entry

    def update(self, service_id: str, kind: DirectoryKind | str, name: str,
               description: str, scheme: str, host: str, port: int,
               path: str) -> DirectoryEntry:
        """Replace mutable fields while preserving publication identity."""
        entry = self._entry(service_id, kind, name, description,
                            scheme, host, port, path)
        with self._lock:
            if service_id not in self._entries:
                raise KeyError("unknown local directory entry")
            self._entries[service_id] = entry
            self._revision += 1
        return entry

    def withdraw(self, service_id: str) -> DirectoryEntry:
        """Remove one exact local publication."""
        with self._lock:
            try:
                entry = self._entries.pop(service_id)
            except KeyError as error:
                raise KeyError("unknown local directory entry") from error
            self._revision += 1
            return entry

    def get(self, service_id: str | None) -> DirectoryEntry | None:
        """Return one immutable local publication by identifier."""
        if service_id is None:
            return None
        with self._lock:
            return self._entries.get(service_id)

    def snapshot(self, kind: DirectoryKind | None = None) -> DirectorySnapshot:
        """Return deterministic entries, optionally filtered by category."""
        with self._lock:
            entries = tuple(self._entries.values())
            revision = self._revision
        filtered = (entries if kind is None else
                    tuple(entry for entry in entries if entry.kind is kind))
        ordered = tuple(sorted(filtered, key=lambda entry: (
            entry.kind.value, entry.name.casefold(), entry.service_id)))
        return DirectorySnapshot(revision, ordered)

    def _entry(self, service_id: str, kind: DirectoryKind | str, name: str,
                 description: str, scheme: str, host: str, port: int,
                 path: str) -> DirectoryEntry:
        parsed_kind, clean_name, clean_description, clean_scheme, clean_host, clean_path = _checked_fields(
            kind, name, description, scheme, host, path)
        _checked_port(port)
        _checked_id(service_id, "service_id")
        return DirectoryEntry(
            service_id, self.owner.peer_id, self.owner.session_id,
            self.owner.name, parsed_kind, clean_name, clean_description,
            clean_scheme, clean_host, port, clean_path)


OWNER_LIMIT = 64


class RemoteDirectoryCache:
    """Bounded process lifetime cache of other sessions' publications."""

    def __init__(self, limit: int = CACHE_LIMIT,
                 owner_limit: int = OWNER_LIMIT,
                 path: Path | str | None = None) -> None:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("cache limit must be a positive integer")
        if (not isinstance(owner_limit, int) or isinstance(owner_limit, bool)
                or owner_limit <= 0):
            raise ValueError("owner limit must be a positive integer")
        self.limit = limit
        self.owner_limit = owner_limit
        self.path = Path(path) if path is not None else None
        self._entries: dict[tuple[str, str], DirectoryEntry] = {}
        self._lock = threading.Lock()
        if self.path is not None and self.path.exists():
            self._entries = self._load()

    def merge(self, entries: list[dict[str, object]]) -> tuple[int, int]:
        """Validate and upsert one received page; return added and duplicate counts."""
        added = duplicates = 0
        with self._lock:
            for raw in entries:
                entry = validate_directory_entry(raw)
                key = (entry.owner_peer_id, entry.service_id)
                if key in self._entries:
                    if self._entries[key] == entry:
                        duplicates += 1
                    else:
                        self._entries[key] = entry
                        added += 1
                    continue
                if len(self._entries) >= self.limit:
                    oldest = next(iter(self._entries))
                    del self._entries[oldest]
                owned = [item for item in self._entries if item[0] == key[0]]
                if len(owned) >= self.owner_limit:
                    del self._entries[owned[0]]
                self._entries[key] = entry
                added += 1
            self._persist_locked()
            return added, duplicates

    def evict_owners(self, keep: set[str]) -> int:
        """Drop cached entries whose owner peer left all retained sessions."""
        with self._lock:
            stale = [key for key in self._entries if key[0] not in keep]
            for key in stale:
                del self._entries[key]
            if stale:
                self._persist_locked()
            return len(stale)

    def _load(self) -> dict[tuple[str, str], DirectoryEntry]:
        """Load persisted entries, failing loudly on corrupt documents."""
        assert self.path is not None
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("catalog file is not valid UTF-8 JSON") from error
        if not isinstance(document, dict):
            raise ValueError("catalog file must contain an object")
        if document.get("schema") != 1:
            raise ValueError("unsupported catalog file schema")
        if set(document) != {"schema", "entries"}:
            raise ValueError("catalog file has invalid fields")
        values = document.get("entries")
        if not isinstance(values, list):
            raise ValueError("catalog entries must be a list")
        entries: dict[tuple[str, str], DirectoryEntry] = {}
        for raw in values[:self.limit]:
            entry = validate_directory_entry(raw)
            entries[(entry.owner_peer_id, entry.service_id)] = entry
        return entries

    def _persist_locked(self) -> None:
        """Atomically persist entries when a file backs this cache."""
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "schema": 1,
            "entries": [entry_dict(entry)
                        for _, entry in sorted(self._entries.items())],
        }
        encoded = (json.dumps(document, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":")) + "\n").encode("utf-8")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, self.path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass

    def snapshot(self, kind: DirectoryKind | None = None) -> tuple[DirectoryEntry, ...]:
        """Return deterministic cached entries, optionally filtered by category."""
        with self._lock:
            entries = tuple(self._entries.values())
        filtered = (entries if kind is None else
                    tuple(entry for entry in entries if entry.kind is kind))
        return tuple(sorted(filtered, key=lambda entry: (
            entry.kind.value, entry.name.casefold(), entry.service_id)))

    def count(self) -> int:
        """Return the number of cached entries."""
        with self._lock:
            return len(self._entries)


def validate_directory_entry(value: object) -> DirectoryEntry:
    """Validate one received directory entry without trusting its origin."""
    if not isinstance(value, dict):
        raise ValueError("directory entry must be an object")
    expected = {"service_id", "owner_peer_id", "owner_session_id",
                "owner_name", "kind", "name", "description",
                "scheme", "host", "port", "path"}
    if set(value) != expected:
        raise ValueError("directory entry has invalid fields")
    _checked_id(value["service_id"], "service_id")
    _checked_id(value["owner_peer_id"], "owner_peer_id")
    _checked_id(value["owner_session_id"], "owner_session_id")
    owner_name = value["owner_name"]
    if (not isinstance(owner_name, str) or not owner_name.strip()
            or len(owner_name) > NAME_LIMIT):
        raise ValueError("owner name must contain 1 to 80 characters")
    parsed_kind, clean_name, clean_description, clean_scheme, clean_host, clean_path = _checked_fields(
        value["kind"], value["name"], value["description"],
        value["scheme"], value["host"], value["path"])
    port = value["port"]
    _checked_port(port)
    assert isinstance(port, int)
    return DirectoryEntry(
        value["service_id"], value["owner_peer_id"], value["owner_session_id"],
        owner_name.strip(), parsed_kind, clean_name, clean_description,
        clean_scheme, clean_host, port, clean_path)


def entry_dict(entry: DirectoryEntry) -> dict[str, object]:
    """Render one entry as plain JSON-compatible data for sync pages."""
    return {
        "service_id": entry.service_id,
        "owner_peer_id": entry.owner_peer_id,
        "owner_session_id": entry.owner_session_id,
        "owner_name": entry.owner_name,
        "kind": entry.kind.value,
        "name": entry.name,
        "description": entry.description,
        "scheme": entry.scheme,
        "host": entry.host,
        "port": entry.port,
        "path": entry.path,
    }


def _checked_fields(kind: DirectoryKind | str, name: object, description: object,
                    scheme: object, host: object,
                    path: object) -> tuple[DirectoryKind, str, str, str, str, str]:
    """Validate shared publication fields without stamping ownership."""
    parsed_kind = _kind(kind)
    clean_name = _text(name, "name", NAME_LIMIT, allow_empty=False)
    clean_description = _text(
        description, "description", DESCRIPTION_LIMIT, allow_empty=True)
    if not isinstance(scheme, str):
        raise ValueError("scheme must be http or https")
    clean_scheme = scheme.strip().lower()
    if clean_scheme not in {"http", "https"}:
        raise ValueError("scheme must be http or https")
    clean_host = _host(host)
    clean_path = _path(path)
    return (parsed_kind, clean_name, clean_description,
            clean_scheme, clean_host, clean_path)


def _checked_port(port: object) -> None:
    """Require a concrete port number for publication or sync."""
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be from 1 through 65535")


def _checked_id(value: object, label: str) -> None:
    """Require a canonical UUID string for entry and owner identity."""
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError(f"invalid {label}")


def browser_url(entry: DirectoryEntry) -> str:
    """Build one browser destination from validated structured fields."""
    host = _host(entry.host)
    scheme = entry.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("scheme must be http or https")
    if (not isinstance(entry.port, int) or isinstance(entry.port, bool)
            or not 1 <= entry.port <= 65535):
        raise ValueError("port must be from 1 through 65535")
    path = _path(entry.path)
    return f"{scheme}://{host}:{entry.port}{quote(path, safe='/-._~')}"


def _kind(value: DirectoryKind | str) -> DirectoryKind:
    if isinstance(value, DirectoryKind):
        return value
    try:
        return DirectoryKind(value)
    except ValueError as error:
        raise ValueError("kind must be service or game") from error


def _text(value: str, label: str, limit: int, allow_empty: bool) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    clean = value.strip()
    if not allow_empty and not clean:
        raise ValueError(f"{label} must not be blank")
    if len(clean) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in clean):
        raise ValueError(f"{label} contains control characters")
    return clean


def _host(value: str) -> str:
    try:
        parsed = ip_address(value.strip())
    except (AttributeError, ValueError) as error:
        raise ValueError("host must be a concrete IPv4 address") from error
    if (not isinstance(parsed, IPv4Address) or parsed.is_unspecified
            or parsed.is_loopback or parsed.is_link_local
            or parsed.is_multicast or parsed.is_reserved):
        raise ValueError("host must be a concrete non-loopback IPv4 address")
    return str(parsed)


def _path(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError("path must start with /")
    if len(value) > PATH_LIMIT:
        raise ValueError(f"path exceeds {PATH_LIMIT} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("path contains control characters")
    if any(char in value for char in ("\\", "?", "#")):
        raise ValueError("path must not contain backslash, query, or fragment")
    return value
