"""Persistent transfer resume manifests with atomic writes and expiry."""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any
from uuid import UUID

MANIFEST_NAME = "resume.json"
SEND_NAME = "send.json"
MANIFEST_TTL_S = 604800
MAX_FILE_SIZE = 1024 * 1024 * 1024

_WRITE_LOCK = threading.Lock()


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _check_uuid(value: object) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("invalid UUID")
    return value


def _check_name(value: object) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > 255
            or value in {".", ".."} or any(c in value for c in "/\\:")
            or any(ord(c) < 32 for c in value)):
        raise ValueError("invalid file name")
    return value


def _check_digest(value: object) -> str:
    if (not isinstance(value, str) or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)):
        raise ValueError("invalid SHA-256")
    return value


def _purge(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        return


def _write_json(path: Path, record: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}-{secrets.token_hex(8)}.tmp")
    with _WRITE_LOCK:
        with tmp.open("w", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    return path


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _expired(saved_ms: object) -> bool:
    if type(saved_ms) is not int or saved_ms < 0:
        return True
    return _now_ms() - saved_ms > MANIFEST_TTL_S * 1000


def _validate_receive(record: dict[str, Any]) -> dict[str, Any]:
    validated = {
        "transfer_id": _check_uuid(record.get("transfer_id")),
        "name": _check_name(record.get("name")),
        "size": record.get("size"),
        "sha256": _check_digest(record.get("sha256")),
        "held": record.get("held"),
        "peer_id": _check_uuid(record.get("peer_id")),
        "session_id": _check_uuid(record.get("session_id")),
        "saved_ms": record.get("saved_ms"),
    }
    size, held = validated["size"], validated["held"]
    if (type(size) is not int or not 0 <= size <= MAX_FILE_SIZE
            or type(held) is not int or not 0 <= held <= size):
        raise ValueError("invalid held byte count")
    if _expired(validated["saved_ms"]):
        raise ValueError("manifest expired")
    return validated


def _validate_send(record: dict[str, Any]) -> dict[str, Any]:
    validated = {
        "transfer_id": _check_uuid(record.get("transfer_id")),
        "path": str(record.get("path") or ""),
        "peer_id": _check_uuid(record.get("peer_id")),
        "session_id": _check_uuid(record.get("session_id")),
        "saved_ms": record.get("saved_ms"),
    }
    if not validated["path"]:
        raise ValueError("invalid source path")
    if _expired(validated["saved_ms"]):
        raise ValueError("manifest expired")
    size, digest = record.get("size"), record.get("sha256")
    if size is not None or digest is not None:
        if (type(size) is not int or not 0 <= size <= MAX_FILE_SIZE):
            raise ValueError("invalid source size")
        validated["size"] = size
        validated["sha256"] = _check_digest(digest)
    return validated


class ReceiveManifest:
    """Own one receiver sidecar per partial file name."""

    @staticmethod
    def save(directory: Path, record: dict[str, Any]) -> Path:
        """Validate and atomically store one receiver record."""
        validated = _validate_receive({**record, "saved_ms": _now_ms()})
        return _write_json(Path(directory) / (validated["name"] + "." + MANIFEST_NAME),
                           validated)

    @staticmethod
    def load(directory: Path, name: str) -> dict[str, Any] | None:
        """Return one unexpired valid record, else None."""
        try:
            clean = _check_name(name)
        except ValueError:
            return None
        path = Path(directory) / (clean + "." + MANIFEST_NAME)
        record = _read_json(path)
        if record is None:
            _purge(path)
            return None
        try:
            return _validate_receive(record)
        except ValueError:
            _purge(path)
            return None

    @staticmethod
    def discard(directory: Path, name: str) -> None:
        """Remove one receiver sidecar without failing when absent."""
        try:
            clean = _check_name(name)
        except ValueError:
            return
        try:
            (Path(directory) / (clean + "." + MANIFEST_NAME)).unlink()
        except OSError:
            return


class SendManifest:
    """Own one sender sidecar per transfer ID."""

    @staticmethod
    def save(directory: Path, record: dict[str, Any]) -> Path:
        """Validate and atomically store one sender record."""
        validated = _validate_send({**record, "saved_ms": _now_ms()})
        return _write_json(Path(directory) / (validated["transfer_id"] + "." + SEND_NAME),
                           validated)

    @staticmethod
    def load(directory: Path, transfer_id: str) -> dict[str, Any] | None:
        """Return one unexpired valid record, else None."""
        try:
            clean = _check_uuid(transfer_id)
        except ValueError:
            return None
        path = Path(directory) / (clean + "." + SEND_NAME)
        record = _read_json(path)
        if record is None or record.get("transfer_id") != clean:
            _purge(path)
            return None
        try:
            return _validate_send(record)
        except ValueError:
            _purge(path)
            return None

    @staticmethod
    def discard(directory: Path, transfer_id: str) -> None:
        """Remove one sender sidecar without failing when absent."""
        try:
            clean = _check_uuid(transfer_id)
        except ValueError:
            return
        try:
            (Path(directory) / (clean + "." + SEND_NAME)).unlink()
        except OSError:
            return

    @staticmethod
    def scan(directory: Path) -> list[dict[str, Any]]:
        """Return unexpired sender records ordered by file name."""
        try:
            children = sorted(Path(directory).iterdir())
        except OSError:
            return []
        records = []
        for child in children:
            if not child.is_file() or not child.name.endswith("." + SEND_NAME):
                continue
            record = _read_json(child)
            if record is None:
                _purge(child)
                continue
            try:
                records.append(_validate_send(record))
            except ValueError:
                _purge(child)
                continue
        return records
