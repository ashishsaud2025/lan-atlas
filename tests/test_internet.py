from __future__ import annotations

import socket
import time
from pathlib import Path
from uuid import uuid4

import pytest

from core.addressbook import AddressBook
from core.chat import ChatService
from core.discovery import Hello
from core.identity import DeviceIdentity
from core.roster import Peer
from core.scope import is_internet_host
from core.secure_transport import SecureTransport
from core.trust import TrustStore


def _free_port(sock_type: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize("host", [
    "127.0.0.1", "192.168.1.65", "10.0.0.9", "172.16.4.2", "169.254.8.7",
    "::1", "fe80::1", "fe80::1%3", "fc00::9",
])
def test_local_scope_hosts(host: str) -> None:
    assert is_internet_host(host) is False


@pytest.mark.parametrize("host", [
    "8.8.8.8", "1.1.1.1", "100.64.0.9", "192.0.2.1", "2001:db8::1",
    "224.0.0.1", "ff02::1",
])
def test_internet_scope_hosts(host: str) -> None:
    assert is_internet_host(host) is True


def test_scope_rejects_bad_hosts() -> None:
    with pytest.raises(ValueError):
        is_internet_host("")
    with pytest.raises(ValueError):
        is_internet_host("0.0.0.0")
    with pytest.raises(ValueError):
        is_internet_host("not a host !!")
    with pytest.raises(ValueError):
        is_internet_host("nonexistent.invalid")


def test_resolve_host_pins_addresses() -> None:
    from core.scope import resolve_host
    assert resolve_host("127.0.0.1") == ("127.0.0.1",)
    assert resolve_host("fe80::1%3") == ("fe80::1%3",)
    assert all(not item.startswith("??") for item in resolve_host("localhost"))
    with pytest.raises(ValueError):
        resolve_host("nonexistent.invalid")


def test_address_book_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "book.json"
    book = AddressBook(path)
    peer_id = str(uuid4())
    entry = book.add(peer_id, " Cabin ", "203.0.113.9", 50003,
                     ["chat_v1"], "a" * 64)
    assert entry.label == "Cabin"
    assert book.get(peer_id) == entry
    assert [item.peer_id for item in book.snapshot()] == [peer_id]
    assert AddressBook(path).get(peer_id) == entry
    assert book.remove(peer_id) is True
    assert book.remove(peer_id) is False
    assert AddressBook(path).snapshot() == ()


def test_address_book_rejects_bad_entries(tmp_path: Path) -> None:
    book = AddressBook(tmp_path / "book.json")
    peer_id = str(uuid4())
    with pytest.raises(ValueError):
        book.add("bad", "Label", "203.0.113.9", 50003, [], "a" * 64)
    with pytest.raises(ValueError):
        book.add(peer_id, "Label", "", 50003, [], "a" * 64)
    with pytest.raises(ValueError):
        book.add(peer_id, "Label", "203.0.113.9", 0, [], "a" * 64)
    with pytest.raises(ValueError):
        book.add(peer_id, "Label", "203.0.113.9", 50003, [], "xyz")
    (tmp_path / "broken.json").write_text("{bad", encoding="utf-8")
    with pytest.raises(ValueError):
        AddressBook(tmp_path / "broken.json")
    with pytest.raises(ValueError):
        book.add(peer_id, "Label", "host\x00name", 50003, [], "a" * 64)


def test_unpaired_internet_dial_refused_without_packets(
        tmp_path: Path) -> None:
    plain = ChatService(Hello(str(uuid4()), str(uuid4()), "Local"))
    target = Hello(str(uuid4()), str(uuid4()), "Remote")
    peer = Peer(target, "8.8.8.8", time.monotonic())
    with pytest.raises(ValueError, match="pair on LAN first"):
        plain._connect_peer(peer)
    service = _paired_service(tmp_path, "Local")
    with pytest.raises(ValueError, match="pair on LAN first"):
        service.request_pair(peer)


def _paired_service(tmp_path: Path, name: str) -> ChatService:
    peer_id = str(uuid4())
    identity = DeviceIdentity.load_or_create(
        tmp_path / f"{name}-{peer_id}.pem", peer_id)
    hello = Hello(
        peer_id, str(uuid4()), name, _free_port(),
        ("chat_v1", "file_v1", "posts_v1", "secure_transport_v1",
         "directory_v1"),
        _free_port(), identity.fingerprint)
    trust = TrustStore(tmp_path / f"{name}-{peer_id}-trust.json")
    transport = SecureTransport(identity, trust, hello)
    return ChatService(
        hello, discovery_port=_free_port(socket.SOCK_DGRAM),
        broadcast="127.0.0.1", secure_transport=transport,
        address_book=tmp_path / f"{name}-book.json")


def test_dial_peer_resolves_session_over_tls(tmp_path: Path) -> None:
    first = _paired_service(tmp_path, "First")
    second = _paired_service(tmp_path, "Second")
    assert first.hello.secure_port is not None
    assert second.hello.secure_port is not None
    second_identity = second.secure_transport.identity
    first.secure_transport.trust_store.pair(
        second_identity.peer_id, second_identity.certificate_der, "Second")
    second.start()
    try:
        first.address_book.add(
            second_identity.peer_id, "Second", "127.0.0.1",
            second.hello.secure_port,
            ["chat_v1", "directory_v1"], second_identity.fingerprint)
        peer = first.dial_peer(second_identity.peer_id)
        assert peer.hello.peer_id == second_identity.peer_id
        assert peer.hello.session_id == second.hello.session_id
        assert peer.ip == "127.0.0.1"
        assert "directory_v1" in peer.hello.capabilities
    finally:
        second.stop()
        assert second.join(10)


def test_dial_peer_requires_pairing_and_matching_key(
        tmp_path: Path) -> None:
    service = _paired_service(tmp_path, "Local")
    stranger = str(uuid4())
    service.address_book.add(stranger, "Stranger", "127.0.0.1", 50003,
                             ["chat_v1"], "b" * 64)
    with pytest.raises(ValueError, match="not paired"):
        service.dial_peer(stranger)
    with pytest.raises(ValueError, match="no address book entry"):
        service.dial_peer(str(uuid4()))


def test_inbound_pairing_refused_when_disallowed(
        tmp_path: Path) -> None:
    import threading
    from core.secure_transport import SecureTransportError
    maker = _paired_service
    server = maker(tmp_path, "Server")
    client = maker(tmp_path, "Client")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    server_node_hello = Hello(
        server.hello.peer_id, server.hello.session_id, server.hello.name,
        server.hello.tcp_port, server.hello.capabilities, port,
        server.hello.certificate_sha256)
    server.secure_transport.local_hello = server_node_hello
    errors: list[Exception] = []

    def serve() -> None:
        try:
            raw, _ = listener.accept()
            server.secure_transport.accept(raw, allow_pairing=False)
        except Exception as error:  # noqa: BLE001 - recorded for assertion
            errors.append(error)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    client_hello = Hello(
        server_node_hello.peer_id, server_node_hello.session_id,
        server_node_hello.name, server_node_hello.tcp_port,
        server_node_hello.capabilities, server_node_hello.secure_port,
        server_node_hello.certificate_sha256)
    from core.roster import Peer as RosterPeer
    import time as _time
    with pytest.raises(Exception):
        client.secure_transport.request_pair(
            RosterPeer(client_hello, "127.0.0.1", _time.monotonic()))
    worker.join(5)
    listener.close()
    assert errors and "internet pairing refused" in str(errors[0])
    assert server.secure_transport.pending() == ()


def test_gui_key_changed_entry_state(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    service = _paired_service(tmp_path, "Local")
    window = MainWindow(service)
    try:
        other = str(uuid4())
        other_identity = DeviceIdentity.load_or_create(
            tmp_path / "other.pem", other)
        service.secure_transport.trust_store.pair(
            other, other_identity.certificate_der, "Remote")
        service.address_book.add(other, "Remote", "203.0.113.9", 50003,
                                 ["chat_v1"], "c" * 64)
        window._refresh_internet_list()
        assert window.internet_list.count() == 1
        assert "Key changed" in window.internet_list.item(0).text()
    finally:
        window.close()
        app.processEvents()


def test_gui_internet_card_blocks_unpaired_dialog(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    service = _paired_service(tmp_path, "Local")
    window = MainWindow(service)
    try:
        assert window.internet_list.count() == 0
        window._add_internet_peer()
        assert "paired session" in window.log.toPlainText()
        assert not window._queue_internet_action("session-id", "send")
        assert window._queue_internet_action(("inet", str(uuid4())), "send")
        assert "no address book entry" in window.log.toPlainText()
    finally:
        window.close()
        app.processEvents()
