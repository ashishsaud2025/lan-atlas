from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from uuid import uuid4

import pytest

from core.chat import ChatService
from core.discovery import Hello
from core.identity import DeviceIdentity
from core.protocol import ProtocolError, envelope, validate_envelope
from core.relay import RelayServer, join, reserve
from core.secure_transport import SecureTransport
from core.trust import TrustStore


def _free_port(sock_type: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_relay_frames_validate() -> None:
    peer, session = str(uuid4()), str(uuid4())
    validate_envelope(envelope("RELAY_ALLOC", peer, session, {}))
    validate_envelope(envelope(
        "RELAY_JOIN", peer, session, {"token": "a" * 32}))
    validate_envelope(envelope("RELAY_READY", peer, session, {}))
    bad = {"version": 1, "type": "RELAY_JOIN",
           "message_id": str(uuid4()), "peer_id": peer,
           "session_id": session, "body": {"token": ""}}
    with pytest.raises(ProtocolError):
        validate_envelope(bad)
    long_token = {"version": 1, "type": "RELAY_JOIN",
                  "message_id": str(uuid4()), "peer_id": peer,
                  "session_id": session, "body": {"token": "ab" * 32}}
    with pytest.raises(ProtocolError):
        validate_envelope(long_token)
    with pytest.raises(ValueError):
        join("127.0.0.1", 50005, peer, session, "short")
    nonempty = {"version": 1, "type": "RELAY_ALLOC",
                "message_id": str(uuid4()), "peer_id": peer,
                "session_id": session, "body": {"extra": 1}}
    with pytest.raises(ProtocolError):
        validate_envelope(nonempty)


def test_fixture_vectors_cover_relay() -> None:
    path = Path(__file__).parents[1] / "protocol/fixtures/envelopes-v1.json"
    kinds = {message["type"] for message in
             json.loads(path.read_text(encoding="utf-8"))["valid"]}
    assert {"RELAY_ALLOC", "RELAY_JOIN", "RELAY_READY"} <= kinds


def test_server_lifecycle_and_validation() -> None:
    server = RelayServer(allow_loopback=True)
    state = server.start("127.0.0.1", 0)
    assert state.phase == "running"
    assert state.port is not None
    try:
        with pytest.raises(RuntimeError):
            server.start("127.0.0.1", 0)
    finally:
        server.stop()
        assert server.join(5)
        assert server.state().phase == "stopped"
    strict = RelayServer()
    with pytest.raises(ValueError):
        strict.start("0.0.0.0", 50005)
    with pytest.raises(ValueError):
        strict.start("127.0.0.1", 50005)
    assert strict.state().phase == "stopped"


def test_raw_pipe_carries_bytes_both_ways() -> None:
    server = RelayServer(allow_loopback=True)
    state = server.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        holder, token = reserve("127.0.0.1", state.port, str(uuid4()),
                                str(uuid4()))
        echoed: list[bytes] = []

        def answer() -> None:
            from core.protocol import recv_message, validate_envelope
            try:
                holder.settimeout(5)
                ready = recv_message(holder)
                assert ready is not None
                validate_envelope(ready)
                assert ready["type"] == "RELAY_READY"
                data = holder.recv(65536)
                echoed.append(data)
                holder.sendall(b"holder says hi")
            except (OSError, ProtocolError, ValueError, AssertionError):
                pass
            finally:
                holder.close()

        helper = threading.Thread(target=answer, daemon=True)
        helper.start()
        peer = join("127.0.0.1", state.port, str(uuid4()), str(uuid4()),
                    token)
        with peer:
            peer.sendall(b"joiner says hi")
            peer.settimeout(5)
            assert peer.recv(65536) == b"holder says hi"
        helper.join(5)
        assert echoed == [b"joiner says hi"]
        with pytest.raises(ProtocolError):
            join("127.0.0.1", state.port, str(uuid4()), str(uuid4()), token)
    finally:
        server.stop()
        assert server.join(5)


def _paired_service(tmp_path: Path, name: str) -> ChatService:
    peer_id = str(uuid4())
    identity = DeviceIdentity.load_or_create(
        tmp_path / f"{name}-{peer_id}.pem", peer_id)
    hello = Hello(peer_id, str(uuid4()), name, _free_port(),
                  ("chat_v1", "secure_transport_v1"),
                  _free_port(), identity.fingerprint)
    trust = TrustStore(tmp_path / f"{name}-trust.json")
    transport = SecureTransport(identity, trust, hello)
    return ChatService(
        hello, discovery_port=_free_port(socket.SOCK_DGRAM),
        broadcast="127.0.0.1", secure_transport=transport,
        address_book=tmp_path / f"{name}-book.json")


def test_relay_dm_end_to_end(tmp_path: Path) -> None:
    sender = _paired_service(tmp_path, "Sender")
    holder_service = _paired_service(tmp_path, "Holder")
    sender_peer = sender.hello.peer_id
    holder_peer = holder_service.hello.peer_id
    sender.secure_transport.trust_store.pair(
        holder_peer, holder_service.secure_transport.identity.certificate_der,
        "Holder")
    holder_service.secure_transport.trust_store.pair(
        sender_peer, sender.secure_transport.identity.certificate_der,
        "Sender")
    sender.address_book.add(holder_peer, "Holder", "127.0.0.1", 50003,
                                ["chat_v1", "secure_transport_v1"],
                                holder_service.secure_transport.identity.fingerprint)
    server = RelayServer(allow_loopback=True)
    state = server.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        holder_sock, token = reserve(
            "127.0.0.1", state.port, holder_service.hello.peer_id,
            holder_service.hello.session_id)
        hosted: list[str] = []

        def host() -> None:
            try:
                from core.protocol import recv_message, validate_envelope
                from core.protocol import send_message as _send
                holder_sock.settimeout(10)
                message = recv_message(holder_sock)
                assert message is not None
                validate_envelope(message)
                assert message["type"] == "RELAY_READY"
                channel = holder_service.secure_transport.accept(holder_sock)
                assert channel is not None
                try:
                    holder_service._dispatch_inbound(
                        channel.socket, True, channel.peer_id,
                        channel.session_id)
                finally:
                    channel.socket.close()
            except Exception as error:  # noqa: BLE001 - recorded
                hosted.append(str(error))
            finally:
                holder_sock.close()

        worker = threading.Thread(target=host, daemon=True)
        worker.start()
        identifier = sender.relay_send(holder_peer, "127.0.0.1", state.port,
                                       token, "hello over relay")
        worker.join(10)
        assert not hosted
        entries = sender.message_journal.snapshot().entries
        assert entries[0].message_id == identifier
        assert entries[0].deliveries[0].state == "accepted"
        assert entries[0].deliveries[0].authenticated
        incoming = holder_service.message_journal.snapshot().entries
        assert incoming and incoming[0].text == "hello over relay"
        assert incoming[0].authenticated
    finally:
        server.stop()
        assert server.join(5)


def test_pairing_over_relay_refused(tmp_path: Path) -> None:
    from core.roster import Peer
    from core.secure_transport import SecureTransportError
    import time
    maker = _paired_service
    server_node = maker(tmp_path, "Server")
    client_node = maker(tmp_path, "Client")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    errors: list[Exception] = []

    def serve() -> None:
        try:
            raw, _ = listener.accept()
            server_node.secure_transport.accept(raw, allow_pairing=False)
        except Exception as error:  # noqa: BLE001 - recorded
            errors.append(error)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    target = Hello(
        server_node.hello.peer_id, server_node.hello.session_id,
        server_node.hello.name, server_node.hello.tcp_port,
        server_node.hello.capabilities, port,
        server_node.hello.certificate_sha256)
    with pytest.raises(Exception):
        client_node.secure_transport.request_pair(
            Peer(target, "127.0.0.1", time.monotonic()))
    worker.join(5)
    listener.close()
    assert errors and "internet pairing refused" in str(errors[0])


def test_gui_relay_controls_validate_input(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    service = _paired_service(tmp_path, "Local")
    window = MainWindow(service)
    try:
        window.relay_host.setText("")
        window._reserve_relay()
        assert "relay server" in window.log.toPlainText()
        window.recipient.clear()
        window.recipient.addItem("Nearby room", None)
        window._send_via_relay()
        assert "Internet peer" in window.log.toPlainText()
    finally:
        window.close()
        app.processEvents()
