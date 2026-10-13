"""Stable Qt presentation models backed by canonical LAN Atlas state."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import time
from typing import Any

from PySide6.QtCore import (QAbstractListModel, QAbstractTableModel, QModelIndex,
                            QObject, QSortFilterProxyModel, Qt)
from PySide6.QtGui import QFont

from core.peer_repository import PeerRecord, TrustState
from core.services import DirectoryEntry, DirectoryKind, browser_url
from gui.theme.fonts import mono_family


@dataclass(frozen=True)
class ActivityEntry:
    """One retained operational event, separate from human messages."""

    timestamp: datetime
    category: str
    title: str
    detail: str = ""
    severity: str = "info"


@dataclass(frozen=True)
class MessageEntry:
    """One locally presented message with evidence-based state."""

    identifier: str
    sender: str
    text: str
    scope: str
    state: str
    outgoing: bool
    recorded_ms: int = 0


@dataclass(frozen=True)
class AdminDevice:
    """One observed endpoint with an explicit evidence source."""

    key: str
    label: str
    address: str
    source: str
    detail: str
    port: int | None = None
    capabilities: tuple[str, ...] = ()
    peer_id: str | None = None
    session_id: str | None = None


class AdminDeviceListModel(QAbstractListModel):
    """Present LAN observations without merging identities by address."""

    DeviceRole = Qt.ItemDataRole.UserRole + 1

    def __init__(self) -> None:
        super().__init__()
        self.devices: tuple[AdminDevice, ...] = ()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.devices)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not 0 <= index.row() < len(self.devices):
            return None
        device = self.devices[index.row()]
        endpoint = (f"{device.address}:{device.port}"
                    if device.port is not None else device.address)
        if role == Qt.ItemDataRole.DisplayRole:
            return f"{device.label}\n{endpoint} · {device.source}\n{device.detail}"
        if role == self.DeviceRole:
            return device
        if role == Qt.ItemDataRole.ToolTipRole:
            return (f"Evidence source: {device.source}\n{device.detail}\n"
                    "An observation is not identity or administrative authority.")
        if role == Qt.ItemDataRole.AccessibleTextRole:
            return (f"{device.label}, address {endpoint}, source {device.source}, "
                    f"{device.detail}")
        return None

    def set_devices(self, devices: tuple[AdminDevice, ...]) -> None:
        """Replace one complete combined observation snapshot."""
        self.beginResetModel()
        self.devices = devices
        self.endResetModel()

    def device_at(self, row: int) -> AdminDevice | None:
        """Return one observed endpoint by visible row."""
        return self.devices[row] if 0 <= row < len(self.devices) else None


class PeerListModel(QAbstractListModel):
    """Expose immutable roster snapshots while preserving session identity."""

    PeerRole = Qt.ItemDataRole.UserRole + 1

    def __init__(self) -> None:
        super().__init__()
        self.records: tuple[PeerRecord, ...] = ()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.records)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not 0 <= index.row() < len(self.records):
            return None
        peer = self.records[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            capabilities = " · ".join(capability_label(item)
                                      for item in peer.hello.capabilities) or "Presence only"
            age = max(0.0, time.monotonic() - peer.last_seen)
            state = "Nearby" if peer.nearby else "Offline / stale"
            trust = peer_trust_label(peer)
            return (f"{peer.hello.name} · {state} · seen {age:.1f}s ago\n"
                    f"{endpoint_label(peer)}  ·  {capabilities}\n"
                    f"{trust} · session {peer.hello.session_id[:8]}…")
        if role == self.PeerRole:
            return peer
        if role == Qt.ItemDataRole.ToolTipRole:
            return (f"Peer {peer.hello.peer_id}\nSession {peer.hello.session_id}\n"
                    f"Trust evidence: {peer_trust_label(peer)}. Discovery itself "
                    "is not authenticated.")
        if role == Qt.ItemDataRole.AccessibleTextRole:
            candidates = (", ".join(item.ip for item in peer.endpoint_candidates)
                          if peer.endpoint_candidates else peer.ip)
            return (f"{peer.hello.name}, endpoints {candidates}:{peer.hello.tcp_port}, "
                    f"{'nearby' if peer.nearby else 'offline or stale'}, "
                    f"{peer_trust_label(peer)}")
        return None

    def set_records(self, records: tuple[PeerRecord, ...]) -> None:
        """Replace one complete canonical repository snapshot atomically."""
        self.beginResetModel()
        self.records = records
        self.endResetModel()

    def record_at(self, row: int) -> PeerRecord | None:
        """Return one repository record by row."""
        return self.records[row] if 0 <= row < len(self.records) else None

    def refresh_ages(self) -> None:
        """Refresh derived last-seen labels without resetting selection."""
        if self.records:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.records) - 1, 0))


class PeerTableModel(QAbstractTableModel):
    """Dense evidence-only session table for Devices and Overview."""

    PeerRole = Qt.ItemDataRole.UserRole + 1
    HEADERS = ("SESSION", "OBSERVED ENDPOINT", "LAST HELLO", "CAPABILITIES")

    def __init__(self) -> None:
        super().__init__()
        self.records: tuple[PeerRecord, ...] = ()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.records)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if (role == Qt.ItemDataRole.DisplayRole
                and orientation == Qt.Orientation.Horizontal
                and 0 <= section < len(self.HEADERS)):
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not 0 <= index.row() < len(self.records):
            return None
        peer = self.records[index.row()]
        if role == self.PeerRole:
            return peer
        if role == Qt.ItemDataRole.FontRole and index.column() == 1:
            return QFont(mono_family())
        if role == Qt.ItemDataRole.DisplayRole:
            age = max(0.0, time.monotonic() - peer.last_seen)
            values = (
                (f"{peer.hello.name}\n"
                 f"{'Nearby' if peer.nearby else 'Offline / stale'} · "
                 f"{peer_trust_label(peer)} · {peer.hello.session_id[:8]}…"),
                endpoint_label(peer),
                f"{age:.1f} s ago\n{'Nearby' if peer.nearby else 'Stale'}",
                "  ·  ".join(capability_label(item)
                              for item in peer.hello.capabilities) or "Presence only",
            )
            return values[index.column()]
        if role == Qt.ItemDataRole.AccessibleTextRole:
            age = max(0.0, time.monotonic() - peer.last_seen)
            candidates = (", ".join(item.ip for item in peer.endpoint_candidates)
                          if peer.endpoint_candidates else peer.ip)
            values = (
                f"Session {peer.hello.name}, {peer_trust_label(peer)}, identifier "
                f"{peer.hello.session_id}",
                f"Observed endpoints {candidates}:{peer.hello.tcp_port}",
                f"Last HELLO {age:.1f} seconds ago, "
                f"{'nearby' if peer.nearby else 'offline or stale'}",
                "Capabilities " + (", ".join(
                    capability_label(item) for item in peer.hello.capabilities)
                    or "presence only"),
            )
            return values[index.column()]
        return None

    def set_records(self, records: tuple[PeerRecord, ...]) -> None:
        """Replace one complete canonical repository snapshot."""
        self.beginResetModel()
        self.records = records
        self.endResetModel()

    def record_at(self, row: int) -> PeerRecord | None:
        """Return one canonical peer record by table row."""
        return self.records[row] if 0 <= row < len(self.records) else None

    def refresh_ages(self) -> None:
        """Refresh last-HELLO cells without disturbing selection."""
        if self.records:
            self.dataChanged.emit(self.index(0, 2), self.index(len(self.records) - 1, 2))


class MessageListModel(QAbstractListModel):
    """Bound human-message history independently of operational logs."""

    def __init__(self, limit: int = 1000) -> None:
        super().__init__()
        self.limit = limit
        self.entries: list[MessageEntry] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.entries)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not 0 <= index.row() < len(self.entries):
            return None
        entry = self.entries[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            direction = "You" if entry.outgoing else entry.sender
            stamp = (datetime.fromtimestamp(entry.recorded_ms / 1000).strftime("%H:%M:%S")
                     if entry.recorded_ms > 0 else "time unavailable")
            return (f"{direction} · {entry.scope} · observed {stamp} local\n"
                    f"{entry.text}\n{entry.state}")
        if role == Qt.ItemDataRole.AccessibleTextRole:
            return f"{entry.sender}, {entry.text}, state {entry.state}"
        return None

    def append(self, entry: MessageEntry) -> None:
        """Append and evict oldest rows beyond the documented UI bound."""
        if len(self.entries) >= self.limit:
            remove = len(self.entries) - self.limit + 1
            self.beginRemoveRows(QModelIndex(), 0, remove - 1)
            del self.entries[:remove]
            self.endRemoveRows()
        row = len(self.entries)
        self.beginInsertRows(QModelIndex(), row, row)
        self.entries.append(entry)
        self.endInsertRows()

    def update_state(self, identifier: str, state: str) -> None:
        """Update one outgoing row from structured per-recipient evidence."""
        row = next((index for index, entry in enumerate(self.entries)
                    if entry.identifier == identifier and entry.outgoing), -1)
        if row < 0:
            return
        entry = self.entries[row]
        self.entries[row] = MessageEntry(entry.identifier, entry.sender, entry.text,
                                         entry.scope, state, entry.outgoing,
                                         entry.recorded_ms)
        index = self.index(row, 0)
        self.dataChanged.emit(index, index)

    def set_entries(self, entries: list[MessageEntry]) -> None:
        """Replace history from one bounded canonical journal snapshot."""
        self.beginResetModel()
        self.entries = entries[-self.limit:]
        self.endResetModel()


class DirectoryListModel(QAbstractListModel):
    """Present local publications without inferring reachability or health."""

    EntryRole = Qt.ItemDataRole.UserRole + 1

    def __init__(self, kind: DirectoryKind) -> None:
        super().__init__()
        self.kind = kind
        self.entries: tuple[DirectoryEntry, ...] = ()
        self.cached_ids: frozenset[tuple[str, str]] = frozenset()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.entries)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not 0 <= index.row() < len(self.entries):
            return None
        entry = self.entries[index.row()]
        key = (entry.owner_peer_id, entry.service_id)
        if key in self.cached_ids:
            provenance = (f"Cached copy · from {entry.owner_name} · "
                          "may be stale or withdrawn")
        else:
            provenance = "Published locally"
        if role == Qt.ItemDataRole.DisplayRole:
            description = entry.description or "No description"
            return (f"{entry.name}\n{browser_url(entry)}\n{description}\n"
                    f"{provenance} · Reachability not checked · Health not defined")
        if role == self.EntryRole:
            return entry
        if role == Qt.ItemDataRole.AccessibleTextRole:
            return (f"{entry.kind.value} {entry.name}, {provenance.lower()} at "
                    f"{browser_url(entry)}, reachability not checked, health not defined")
        return None

    def set_entries(self, entries: tuple[DirectoryEntry, ...],
                    cached_ids: frozenset[tuple[str, str]] = frozenset()) -> None:
        """Replace one complete filtered directory snapshot."""
        self.beginResetModel()
        self.entries = tuple(entry for entry in entries if entry.kind is self.kind)
        self.cached_ids = cached_ids
        self.endResetModel()

    def entry_at(self, row: int) -> DirectoryEntry | None:
        """Return one publication by visible row."""
        return self.entries[row] if 0 <= row < len(self.entries) else None


class TransferListModel(QAbstractListModel):
    """Track the latest visible state for each bounded transfer."""

    def __init__(self, limit: int = 128) -> None:
        super().__init__()
        self.limit = limit
        self.identifiers: list[str] = []
        self.rows: dict[str, dict[str, Any]] = {}

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.identifiers)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not 0 <= index.row() < len(self.identifiers):
            return None
        identifier = self.identifiers[index.row()]
        row = self.rows[identifier]
        if role == Qt.ItemDataRole.DisplayRole:
            progress = ""
            if "bytes" in row and "total" in row:
                progress = f" · {row['bytes']}/{row['total']} bytes"
            return (f"{row.get('name', identifier)}\n{row.get('state', 'pending')}"
                    f"{progress}\n{identifier[:8]}…")
        if role == Qt.ItemDataRole.UserRole:
            return row
        if role == Qt.ItemDataRole.AccessibleTextRole:
            return f"Transfer {row.get('name', identifier)}, {row.get('state', 'pending')}"
        return None

    def upsert(self, value: dict[str, Any]) -> str | None:
        """Insert or update a transfer and return an evicted identifier, if any."""
        identifier = value["id"]
        if identifier not in self.rows:
            removed = None
            if len(self.identifiers) >= self.limit:
                self.beginRemoveRows(QModelIndex(), 0, 0)
                removed = self.identifiers.pop(0)
                self.rows.pop(removed, None)
                self.endRemoveRows()
            row = len(self.identifiers)
            self.beginInsertRows(QModelIndex(), row, row)
            self.identifiers.append(identifier)
            self.rows[identifier] = dict(value)
            self.endInsertRows()
            return removed
        row = self.identifiers.index(identifier)
        self.rows[identifier].update(value)
        index = self.index(row, 0)
        self.dataChanged.emit(index, index)
        return None


def human_bytes(count: float) -> str:
    """Format one byte count without implying false precision."""
    value = max(0.0, float(count))
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024.0 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} GiB"


def transfer_pace(samples: tuple[tuple[float, float], ...], done: float,
                  total: float) -> tuple[float | None, float | None]:
    """Derive measured rate and ETA from event arrival samples only."""
    if len(samples) < 2 or total <= 0 or done >= total:
        return None, None
    first_time, first_bytes = samples[0]
    last_time, last_bytes = samples[-1]
    elapsed = last_time - first_time
    moved = last_bytes - first_bytes
    if elapsed <= 0 or moved <= 0:
        return None, None
    rate = moved / elapsed
    return rate, (total - done) / rate


def format_eta(seconds: float | None) -> str:
    """Format one ETA estimate with coarse honest granularity."""
    if seconds is None:
        return "unavailable"
    total = max(0, int(seconds))
    if total < 60:
        return f"{total}s"
    if total < 3600:
        return f"{total // 60}m {total % 60:02d}s"
    return f"{total // 3600}h {(total % 3600) // 60:02d}m"


class TerminalTransferProxy(QSortFilterProxyModel):
    """Expose only finished transfers without duplicating model state."""

    def __init__(self, terminal: frozenset[str],
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._terminal = terminal

    def filterAcceptsRow(self, source_row: int,
                         source_parent: QModelIndex) -> bool:
        """Accept rows whose stored state reached a terminal phase."""
        del source_parent
        model = self.sourceModel()
        if not isinstance(model, TransferListModel):
            return True
        if not 0 <= source_row < len(model.identifiers):
            return False
        return (model.rows[model.identifiers[source_row]].get("state")
                in self._terminal)


class PostListModel(QAbstractListModel):
    """Present a bounded feed snapshot without treating wall time as consensus."""

    def __init__(self) -> None:
        super().__init__()
        self.posts: list[dict[str, Any]] = []
        self.local_peer_id = ""
        self.author_names: dict[str, str] = {}
        self.security_labels: dict[str, str] = {}
        self.edited_ids: set[str] = set()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.posts)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not 0 <= index.row() < len(self.posts):
            return None
        post = self.posts[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            author_id = post["author_id"]
            author = self.author_names.get(author_id, f"Peer {author_id[:8]}…")
            provenance = ("Published locally" if author_id == self.local_peer_id
                          else "Cached copy")
            try:
                stamp = datetime.fromtimestamp(
                    post["created_ms"] / 1000).strftime("%Y-%m-%d %H:%M")
            except (OSError, OverflowError, ValueError):
                stamp = "time unavailable"
            refs = f"\n{len(post['refs'])} attachment reference(s)" if post["refs"] else ""
            security = self.security_labels.get(post["post_id"], "Unsigned")
            if "tombstone" in post:
                return (f"{author} · {provenance}\nPost deleted by author · {security}\n"
                        f"Reported {stamp}; peer clocks may differ")
            edited = " · edited" if post["post_id"] in self.edited_ids else ""
            return (f"{author} · {provenance}{edited}\n{post['text']}\n"
                    f"Reported {stamp}; peer clocks may differ · {security}{refs}")
        if role == Qt.ItemDataRole.AccessibleTextRole:
            return f"Post by {post['author_id']}, {post['text']}"
        return None

    def set_posts(self, posts: list[dict[str, Any]], local_peer_id: str,
                  author_names: dict[str, str],
                  security_labels: dict[str, str] | None = None,
                  edited_ids: set[str] | None = None) -> None:
        """Replace the visible bounded page and its current author labels."""
        self.beginResetModel()
        self.posts = posts
        self.local_peer_id = local_peer_id
        self.author_names = dict(author_names)
        self.security_labels = dict(security_labels or {})
        self.edited_ids = set(edited_ids or set())
        self.endResetModel()

    def set_author_names(self, author_names: dict[str, str]) -> None:
        """Refresh display labels without reading or replacing post storage."""
        self.author_names = dict(author_names)
        if self.posts:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.posts) - 1, 0))


class ActivityListModel(QAbstractListModel):
    """Retain bounded, structured operational events for inspection."""

    def __init__(self, limit: int = 500) -> None:
        super().__init__()
        self.limit = limit
        self.entries: list[ActivityEntry] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.entries)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not 0 <= index.row() < len(self.entries):
            return None
        entry = self.entries[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            stamp = entry.timestamp.strftime("%H:%M:%S")
            suffix = f"\n{entry.detail}" if entry.detail else ""
            return f"{stamp} · {entry.category}\n{entry.title}{suffix}"
        if role == Qt.ItemDataRole.AccessibleTextRole:
            return f"{entry.category}, {entry.title}, {entry.detail}"
        return None

    def append(self, entry: ActivityEntry) -> None:
        """Append one event and discard the oldest event at the bound."""
        if len(self.entries) >= self.limit:
            self.beginRemoveRows(QModelIndex(), 0, 0)
            self.entries.pop(0)
            self.endRemoveRows()
        row = len(self.entries)
        self.beginInsertRows(QModelIndex(), row, row)
        self.entries.append(entry)
        self.endInsertRows()


def capability_label(value: str) -> str:
    """Translate known wire capability names without hiding unknown values."""
    return {"chat_v1": "Chat", "file_v1": "Files", "posts_v1": "Posts",
            "echo_v1": "Echo", "secure_transport_v1": "Secure TLS",
            "ipv6_v1": "IPv6", "directory_v1": "Directory"}.get(value, value)


def peer_trust_label(peer: PeerRecord) -> str:
    """Describe stored key evidence without claiming current authentication."""
    return {
        TrustState.UNVERIFIED: "Unverified",
        TrustState.PAIRED: "Paired key",
        TrustState.KEY_CHANGED: "Key changed",
    }[peer.trust_state]


def endpoint_label(peer: PeerRecord) -> str:
    """Present preferred endpoint with honest alternative count."""
    base = f"{peer.ip}:{peer.hello.tcp_port}"
    total = len(peer.endpoint_candidates) if peer.endpoint_candidates else 1
    if total > 1:
        return f"{base} +{total - 1}"
    return base
