"""Explicit public file registry for open LAN browser sharing."""

from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path
from typing import Any

MAX_FILES = 256
MAX_TOTAL_BYTES = 1073741824
MAX_FILE_BYTES = 67108864
MAX_FILE_NAME = 255


class PublicFileRegistry:
    """Own one explicit directory of guest visible files with no overwrite."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}
        self._total = 0
        self._load()

    def publish(self, name: str, data: bytes, guest: str) -> dict[str, Any]:
        """Verify and atomically publish one file; names are unique."""
        clean = _validate_name(name)
        if not isinstance(data, bytes):
            raise ValueError("file data must be bytes")
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("file exceeds 64 MiB")
        digest = hashlib.sha256(data).hexdigest()
        with self._lock:
            if clean in self._entries:
                raise ValueError("file name already published")
            if len(self._entries) >= MAX_FILES:
                raise ValueError("public file catalog is full")
            if self._total + len(data) > MAX_TOTAL_BYTES:
                raise ValueError("public file storage is full")
            tmp = self.root / (clean + ".tmp")
            target = self.root / clean
            with tmp.open("wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, target)
            entry = {"file_id": clean, "name": clean, "size": len(data),
                     "sha256": digest, "guest": guest,
                     "created_ms": time.time_ns() // 1_000_000}
            self._entries[clean] = entry
            self._total += len(data)
            return dict(entry)

    def list(self) -> list[dict[str, Any]]:
        """Return published entries ordered by name."""
        with self._lock:
            return [dict(self._entries[key]) for key in sorted(self._entries)]

    def open_file(self, file_id: str) -> tuple[Path, str]:
        """Return the path and verified digest for one published file."""
        clean = _validate_name(file_id)
        with self._lock:
            entry = self._entries.get(clean)
        if entry is None:
            raise ValueError("unknown file")
        path = self.root / clean
        if not path.is_file():
            raise ValueError("file is no longer available")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            raise ValueError("file digest mismatch")
        return path, digest

    def _load(self) -> None:
        for child in sorted(self.root.iterdir()):
            if not child.is_file() or child.suffix == ".tmp":
                continue
            try:
                clean = _validate_name(child.name)
            except ValueError:
                continue
            data = child.read_bytes()
            if len(data) > MAX_FILE_BYTES:
                continue
            if len(self._entries) >= MAX_FILES:
                break
            if self._total + len(data) > MAX_TOTAL_BYTES:
                break
            self._entries[clean] = {
                "file_id": clean, "name": clean, "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "guest": "unknown", "created_ms": 0}
            self._total += len(data)


def _validate_name(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("file name must be text")
    name = value.strip()
    if not name or len(name) > MAX_FILE_NAME:
        raise ValueError("file name must contain 1 to 255 characters")
    if name in {".", ".."}:
        raise ValueError("invalid file name")
    if any(char in name for char in "/\\:"):
        raise ValueError("invalid file name")
    if any(ord(char) < 32 or char == "\x7f" for char in name):
        raise ValueError("file name contains control characters")
    return name
