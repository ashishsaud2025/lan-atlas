from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from uuid import uuid4

import pytest

from core.chat import ChatService
from core.discovery import Hello
from core.identity import DeviceIdentity
from core.protocol import ProtocolError, envelope, validate_envelope
from core.rendezvous import (
    RendezvousServer,
    announce_once,
    check_announcement,
    query,
    sign_announcement,
    verify_announcement,
)
from core.secure_transport import SecureTransport
from core.trust import TrustStore


def _identity(tmp_path: Path, name: str) -> DeviceIdentity:
    peer_id = str(uuid4())
    return DeviceIdentity.load_or_create(tmp_path / f"{name}.pem", peer_id)


def _entry(identity: DeviceIdentity) -> dict[str, object]:
    return sign_announcement(
        identity, str(uuid4()), "Node", "203.0.113.9", 50001, 50003,
        ["chat_v1"])


def test_sign_verify_round_trip(tmp_path: Path) -> None:
    identity = _identity(tmp_path, "node")
    entry = _entry(identity)
    assert verify_announcement(entry, identity.fingerprint) == (True, "")


def test_tampering_rejected(tmp_path: Path) -> None:
    identity = _identity(tmp_path, "node")
    entry = _entry(identity)
    tampered = dict(entry, host="198.51.100.7")
    assert verify_announcement(tampered, identity.fingerprint)[0] is False
    assert verify_announcement(entry, "0" * 64)[0] is False
    assert verify_announcement({"bogus": True}, None)[0] is False
    with pytest.raises(ValueError):
        check_announcement(dict(entry, capabilities=["bad cap!"]))


def test_server_register_query_expire() -> None:
    server = RendezvousServer(entry_ttl=0.2)
    state = server.start("127.0.0.1", 0, allow_loopback=True)
    assert state.phase == "running"
    assert state.port is not None
    try:
        from core.rendezvous import serve_query
        assert serve_query(
            server, {"cursor": None, "limit": 50, "kind": None})["complete"] is True
        with pytest.raises(RuntimeError):
            server.start("127.0.0.1", 0, allow_loopback=True)
    finally:
        server.stop()
        assert server.join(5)
        assert server.state().phase == "stopped"


def test_server_rejects_bad_binds() -> None:
    server = RendezvousServer()
    with pytest.raises(ValueError):
        server.start("0.0.0.0", 50004)
    with pytest.raises(ValueError):
        server.start("127.0.0.1", 50004)
    assert server.state().phase == "stopped"


def test_live_announce_and_query(tmp_path: Path) -> None:
    server = RendezvousServer()
    state = server.start("127.0.0.1", 0, allow_loopback=True)
    assert state.port is not None
    try:
        first = _identity(tmp_path, "first")
        entry = _entry(first)
        announce_once("127.0.0.1", state.port, entry, entry["peer_id"],
                      entry["session_id"])
        page = query("127.0.0.1", state.port, str(uuid4()), str(uuid4()))
        assert page["complete"] is True
        assert [item["peer_id"] for item in page["entries"]] == [entry["peer_id"]]
        assert verify_announcement(
            page["entries"][0], first.fingerprint) == (True, "")
    finally:
        server.stop()
        assert server.join(5)


def test_rendezvous_envelopes_validate() -> None:
    peer, session = str(uuid4()), str(uuid4())
    announce = {"version": 1, "type": "RV_ANNOUNCE",
                "message_id": str(uuid4()), "peer_id": peer,
                "session_id": session, "body": {"entry": {}}}
    with pytest.raises(ProtocolError):
        validate_envelope(announce)
    query_message = {"version": 1, "type": "RV_QUERY",
                     "message_id": str(uuid4()), "peer_id": peer,
                     "session_id": session,
                     "body": {"cursor": None, "limit": 0}}
    with pytest.raises(ProtocolError):
        validate_envelope(query_message)


def test_fixture_vectors_cover_rendezvous() -> None:
    path = Path(__file__).parents[1] / "protocol/fixtures/envelopes-v1.json"
    kinds = {message["type"] for message in
             json.loads(path.read_text(encoding="utf-8"))["valid"]}
    assert {"RV_ANNOUNCE", "RV_QUERY", "RV_PAGE"} <= kinds


def _service(tmp_path: Path, name: str) -> ChatService:
    peer_id = str(uuid4())
    identity = DeviceIdentity.load_or_create(
        tmp_path / f"{name}-{peer_id}.pem", peer_id)
    hello = Hello(peer_id, str(uuid4()), name, 50001,
                  ("chat_v1", "secure_transport_v1"),
                  50003, identity.fingerprint)
    transport = SecureTransport(
        identity, TrustStore(tmp_path / f"{name}-trust.json"), hello)
    return ChatService(hello, secure_transport=transport)


def test_service_register_and_lookup(tmp_path: Path) -> None:
    server = RendezvousServer()
    state = server.start("127.0.0.1", 0, allow_loopback=True)
    assert state.port is not None
    publisher = _service(tmp_path, "Publisher")
    reader = _service(tmp_path, "Reader")
    reader.secure_transport.trust_store.pair(
        publisher.hello.peer_id,
        publisher.secure_transport.identity.certificate_der, "Publisher")
    try:
        publisher.rendezvous_register(
            "127.0.0.1", state.port, "203.0.113.9", 50001, 50003)
        deadline = time.monotonic() + 8
        results: list[tuple[dict[str, object], bool]] = []
        while time.monotonic() < deadline:
            results = reader.rendezvous_lookup("127.0.0.1", state.port)
            if results:
                break
            time.sleep(0.2)
        assert len(results) == 1
        entry, trusted = results[0]
        assert trusted is True
        assert entry["host"] == "203.0.113.9"
        publisher.rendezvous_stop()
    finally:
        server.stop()
        assert server.join(5)


def test_lookup_marks_unknown_keys_unverified(tmp_path: Path) -> None:
    server = RendezvousServer()
    state = server.start("127.0.0.1", 0, allow_loopback=True)
    assert state.port is not None
    publisher = _service(tmp_path, "Publisher")
    reader = _service(tmp_path, "Reader")
    try:
        publisher.rendezvous_register(
            "127.0.0.1", state.port, "203.0.113.9", 50001, 50003)
        deadline = time.monotonic() + 8
        results: list[tuple[dict[str, object], bool]] = []
        while time.monotonic() < deadline:
            results = reader.rendezvous_lookup("127.0.0.1", state.port)
            if results:
                break
            time.sleep(0.2)
        assert results and results[0][1] is False
        publisher.rendezvous_stop()
    finally:
        server.stop()
        assert server.join(5)


def test_lookup_pages_and_drops_bad_signatures(tmp_path: Path) -> None:
    server = RendezvousServer()
    state = server.start("127.0.0.1", 0, allow_loopback=True)
    assert state.port is not None
    try:
        good = _entry(_identity(tmp_path, "good"))
        announce_once("127.0.0.1", state.port, good,
                      good["peer_id"], good["session_id"])
        bad = _entry(_identity(tmp_path, "bad"))
        bad["host"] = "198.51.100.7"
        announce_once("127.0.0.1", state.port, bad, bad["peer_id"],
                      bad["session_id"])
        from core.rendezvous import query_all
        page = query_all("127.0.0.1", state.port, str(uuid4()), str(uuid4()))
        assert {item["peer_id"] for item in page} == {bad["peer_id"],
                                                     good["peer_id"]}
        for index in range(54):
            extra = _identity(tmp_path, f"extra-{index}")
            record = _entry(extra)
            announce_once("127.0.0.1", state.port, record,
                          record["peer_id"], record["session_id"])
        full = query_all("127.0.0.1", state.port, str(uuid4()), str(uuid4()))
        assert len(full) == 56
    finally:
        server.stop()
        assert server.join(5)


def test_gui_lookup_results_show_verification(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    service = _service(tmp_path, "Local")
    window = MainWindow(service)
    try:
        window.rv_host.setText("")
        window._lookup_rendezvous()
        assert "rendezvous server" in window.log.toPlainText()
        assert window.rv_results.count() == 0
    finally:
        window.close()
        app.processEvents()
