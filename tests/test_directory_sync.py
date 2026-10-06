from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from uuid import uuid4

import pytest

from core.chat import ChatService
from core.directory_sync import merge_page, serve_query, validate_cursor
from core.discovery import Hello
from core.protocol import ProtocolError, envelope, validate_envelope
from core.roster import Peer
from core.services import (
    DirectoryKind, LocalServiceDirectory, RemoteDirectoryCache,
    validate_directory_entry,
)


def _free_port(sock_type: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _hello(name: str, capabilities: tuple[str, ...] = ("directory_v1",)) -> Hello:
    return Hello(str(uuid4()), str(uuid4()), name, _free_port(), capabilities)


def _owner() -> Hello:
    return Hello(str(uuid4()), str(uuid4()), "Owner")


def _entry_data(peer_id: str, session_id: str, name: str = "Project") -> dict[str, object]:
    return {
        "service_id": str(uuid4()), "owner_peer_id": peer_id,
        "owner_session_id": session_id, "owner_name": "Owner",
        "kind": "service", "name": name, "description": "LAN project",
        "scheme": "http", "host": "192.168.1.20", "port": 8000, "path": "/",
    }


def test_validate_entry_rejects_bad_shapes() -> None:
    good = _entry_data(str(uuid4()), str(uuid4()))
    assert validate_directory_entry(good).name == "Project"
    bad_host = dict(good, host="0.0.0.0")
    with pytest.raises(ValueError):
        validate_directory_entry(bad_host)
    missing = dict(good)
    del missing["path"]
    with pytest.raises(ValueError):
        validate_directory_entry(missing)
    with pytest.raises(ValueError):
        validate_cursor({"last_service": "bad"})


def test_serve_pages_with_cursor_kind_and_byte_budget() -> None:
    directory = LocalServiceDirectory(_owner())
    for index in range(4):
        directory.register(DirectoryKind.SERVICE, f"service-{index}", "",
                           "http", "192.168.1.20", 8000 + index, "/")
    directory.register(DirectoryKind.GAME, "game-0", "",
                       "http", "192.168.1.20", 9000, "/")
    first = serve_query(directory, {"cursor": None, "limit": 2, "kind": None})
    assert len(first["entries"]) == 2 and first["complete"] is False
    second = serve_query(directory, {"cursor": first["next_cursor"],
                                     "limit": 10, "kind": None})
    assert second["complete"] is True
    games = serve_query(directory, {"cursor": None, "limit": 10,
                                    "kind": "game"})
    assert len(games["entries"]) == 1 and games["complete"] is True
    with pytest.raises(ValueError):
        serve_query(directory, {"cursor": None, "limit": 10, "kind": "other"})


def test_merge_rejects_invalid_page_atomically() -> None:
    cache = RemoteDirectoryCache()
    owner = _owner()
    good = _entry_data(owner.peer_id, owner.session_id)
    bad = dict(good, port=0)
    with pytest.raises(ValueError):
        merge_page(cache, [good, bad])
    assert cache.count() == 0


def test_catalog_persists_across_restarts(tmp_path: Path) -> None:
    path = tmp_path / "catalog.json"
    first = RemoteDirectoryCache(path=path)
    owner = _owner()
    assert merge_page(first, [_entry_data(owner.peer_id, owner.session_id,
                                          "Kept")]) == (1, 0)
    second = RemoteDirectoryCache(path=path)
    assert second.count() == 1
    assert second.snapshot()[0].name == "Kept"
    assert second.evict_owners({"nobody"}) == 1
    assert RemoteDirectoryCache(path=path).count() == 0


def test_catalog_rejects_corrupt_files(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{bad", encoding="utf-8")
    with pytest.raises(ValueError):
        RemoteDirectoryCache(path=broken)
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"schema": 1, "entries": [{"bogus": 1}]}),
                     encoding="utf-8")
    with pytest.raises(ValueError):
        RemoteDirectoryCache(path=wrong)


def test_service_catalog_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "catalog.json"
    first = ChatService(_hello("First"),
                        remote_catalog=RemoteDirectoryCache(path=path))
    owner = _owner()
    first.remote_catalog.merge([_entry_data(owner.peer_id, owner.session_id)])
    second = ChatService(_hello("Second"),
                         remote_catalog=RemoteDirectoryCache(path=path))
    assert second.remote_catalog.count() == 1


def test_merge_upserts_republished_entries() -> None:
    cache = RemoteDirectoryCache(limit=2)
    owner = _owner()
    first = _entry_data(owner.peer_id, owner.session_id, "Alpha")
    assert merge_page(cache, [first]) == (1, 0)
    assert merge_page(cache, [first]) == (0, 1)
    renamed = dict(first, name="Beta")
    assert merge_page(cache, [renamed]) == (1, 0)
    assert cache.snapshot()[0].name == "Beta"
    other = _entry_data(str(uuid4()), str(uuid4()), "Gamma")
    third = _entry_data(str(uuid4()), str(uuid4()), "Delta")
    assert merge_page(cache, [other, third]) == (2, 0)
    assert cache.count() == 2


def test_per_owner_quota_and_eviction() -> None:
    cache = RemoteDirectoryCache(limit=256, owner_limit=2)
    owner = _owner()
    pages = [_entry_data(owner.peer_id, owner.session_id, f"n{index}")
             for index in range(3)]
    assert merge_page(cache, pages) == (3, 0)
    assert cache.count() == 2
    assert cache.evict_owners({owner.peer_id}) == 0
    assert cache.evict_owners({"00000000-0000-4000-8000-000000000099"}) == 2
    assert cache.count() == 0


def test_forged_owner_page_is_rejected() -> None:
    holder = _hello("Holder")
    service = ChatService(_hello("Reader"))
    forged = _entry_data(str(uuid4()), str(uuid4()), "Spoofed")
    query = envelope("DIR_QUERY", service.hello.peer_id,
                     service.hello.session_id,
                     {"cursor": None, "limit": 50, "kind": None})
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        peer = Peer(Hello(holder.peer_id, holder.session_id, holder.name,
                          listener.getsockname()[1], ("directory_v1",)),
                    "127.0.0.1", 0)

        def respond() -> None:
            from core.protocol import recv_message, send_message
            conn, _ = listener.accept()
            with conn:
                request = recv_message(conn)
                assert request is not None
                send_message(conn, envelope(
                    "DIR_PAGE", holder.peer_id, holder.session_id,
                    {"entries": [forged], "next_cursor": None,
                     "complete": True}, request["message_id"]))

        worker = threading.Thread(target=respond, daemon=True)
        worker.start()
        with pytest.raises(ProtocolError, match="owner differs"):
            service._sync_directory_peer(peer, query)
        worker.join(5)
    assert service.remote_catalog.count() == 0


def test_directory_envelopes_validate() -> None:
    owner = _owner()
    query = envelope("DIR_QUERY", owner.peer_id, owner.session_id,
                     {"cursor": None, "limit": 10, "kind": None})
    validate_envelope(query)
    page = envelope("DIR_PAGE", owner.peer_id, owner.session_id,
                    serve_query(LocalServiceDirectory(owner),
                                {"cursor": None, "limit": 10, "kind": None}),
                    query["message_id"])
    validate_envelope(page)
    with pytest.raises(ProtocolError):
        validate_envelope(envelope("DIR_QUERY", owner.peer_id, owner.session_id,
                                   {"cursor": None, "limit": 0, "kind": None}))
    with pytest.raises(ProtocolError):
        validate_envelope(envelope("DIR_QUERY", owner.peer_id, owner.session_id,
                                   {"cursor": None, "limit": 10, "kind": "other"}))


def test_shared_envelope_vectors_cover_directory(tmp_path: Path) -> None:
    del tmp_path
    import json
    path = Path(__file__).parents[1] / "protocol/fixtures/envelopes-v1.json"
    kinds = {message["type"] for message in
             json.loads(path.read_text(encoding="utf-8"))["valid"]}
    assert {"DIR_QUERY", "DIR_PAGE"} <= kinds


def _wait_until(predicate: object, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        assert callable(predicate)
        if predicate():  # type: ignore[operator]
            return
        time.sleep(0.02)
    raise TimeoutError("condition was not reached")


def test_live_directory_sync_between_services() -> None:
    holder = ChatService(_hello("Holder"),
                         discovery_port=_free_port(socket.SOCK_DGRAM),
                         broadcast="127.0.0.1")
    reader = ChatService(_hello("Reader"),
                         discovery_port=_free_port(socket.SOCK_DGRAM),
                         broadcast="127.0.0.1")
    holder.directory.register(DirectoryKind.SERVICE, "Shared", "LAN project",
                              "http", "192.168.1.20", 8000, "/")
    holder.start()
    reader.start()
    try:
        peer = Peer(holder.hello, "127.0.0.1", time.monotonic())
        reader.sync_directory(peer)
        _wait_until(lambda: reader.remote_catalog.count() == 1)
        entry = reader.remote_catalog.snapshot()[0]
        assert entry.name == "Shared"
        assert entry.owner_peer_id == holder.hello.peer_id
    finally:
        holder.stop()
        reader.stop()
        assert holder.join(10)
        assert reader.join(10)


def test_sync_requires_directory_capability() -> None:
    service = ChatService(_hello("Local", ()))
    peer = Peer(_hello("Remote", ("chat_v1",)), "127.0.0.1", 0)
    with pytest.raises(ValueError, match="directory_v1"):
        service.sync_directory(peer)


def test_listener_serves_correlated_directory_page() -> None:
    service = ChatService(_hello("Holder"))
    service.directory.register(DirectoryKind.GAME, "Arena", "", "http",
                               "192.168.1.20", 9000, "/")
    worker = threading.Thread(target=service._receive_worker, daemon=True)
    worker.start()
    client, server = socket.socketpair()
    from core.protocol import recv_message, send_message
    request = envelope("DIR_QUERY", str(uuid4()), str(uuid4()),
                       {"cursor": None, "limit": 10, "kind": None})
    try:
        service._incoming.put(server)
        with client:
            send_message(client, request)
            reply = recv_message(client)
        assert reply is not None
        validate_envelope(reply)
        assert reply["type"] == "DIR_PAGE"
        assert reply["reply_to"] == request["message_id"]
        assert reply["body"]["entries"][0]["name"] == "Arena"
    finally:
        client.close()
        service.stop()
        worker.join(2)
    assert not worker.is_alive()


def test_gui_shows_cached_entries_and_syncs(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    service = ChatService(_hello("Local"))
    window = MainWindow(service)
    try:
        assert window.directory_peer.count() == 1
        window._sync_directory()
        assert "directory-capable" in window.log.toPlainText()
        service.directory.register(DirectoryKind.SERVICE, "Mine", "", "http",
                                   "192.168.1.20", 8000, "/")
        owner = _owner()
        service.remote_catalog.merge([_entry_data(
            owner.peer_id, owner.session_id, "Theirs")])
        window._refresh_directory()
        texts = [window.service_model.data(window.service_model.index(row, 0))
                 for row in range(window.service_model.rowCount())]
        assert any("Published locally" in text for text in texts)
        assert any("Cached copy" in text for text in texts)
    finally:
        window.close()
        app.processEvents()
