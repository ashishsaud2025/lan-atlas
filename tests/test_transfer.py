from __future__ import annotations

import base64
import socket
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from core.discovery import Hello
from core.protocol import ProtocolError, envelope, recv_message, send_message, validate_envelope
from core.roster import Peer
from core.transfer import TransferError, TransferService, validate_accept, validate_offer

EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class Emitter:
    """Collect service events across worker threads."""

    def __init__(self) -> None:
        self.items: list[tuple[str, Any]] = []

    def __call__(self, kind: str, data: Any) -> bool:
        self.items.append((kind, data))
        return True


def _hello(name: str, port: int = 50001) -> Hello:
    return Hello(str(uuid4()), str(uuid4()), name, port, ("file_v1",))


def _states(emitter: Emitter, identifier: str) -> list[str]:
    return [data["state"] for kind, data in emitter.items
            if kind == "transfer" and data["id"] == identifier]


def _wait_done(*services: TransferService, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(not service._transfers for service in services):
            return True
        time.sleep(0.05)
    return False


def _wait_offer(emitter: Emitter, timeout: float = 10.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for kind, data in emitter.items:
            if kind == "file_offer":
                return data["id"]
        time.sleep(0.05)
    raise TimeoutError("file offer was not published")


def _offer(sender: Hello, receiver: Hello, name: str = "notes.txt") -> dict[str, Any]:
    return envelope("FILE_OFFER", sender.peer_id, sender.session_id,
                    {"transfer_id": str(uuid4()), "name": name, "size": 0,
                     "sha256": EMPTY_SHA, "to_session": receiver.session_id})


def test_offer_validation() -> None:
    sender, receiver = _hello("Sender"), _hello("Receiver")
    assert validate_offer(_offer(sender, receiver), receiver.session_id)["name"] == "notes.txt"
    bad = _offer(sender, receiver)
    bad["body"]["to_session"] = sender.session_id
    with pytest.raises(TransferError):
        validate_offer(bad, receiver.session_id)
    for name in ("", "..", "a/b", "a\\b", "a:b", "x" * 256):
        with pytest.raises(ProtocolError):
            _offer(sender, receiver, name)


def test_offer_accepts_resume_id_and_accept_offset() -> None:
    sender, receiver = _hello("Sender"), _hello("Receiver")
    offer = _offer(sender, receiver)
    offer["body"]["resume_id"] = offer["body"]["transfer_id"]
    assert validate_offer(offer, receiver.session_id)["resume_id"] == offer["body"]["transfer_id"]
    bad = _offer(sender, receiver)
    bad["body"]["resume_id"] = "not-a-uuid"
    with pytest.raises(TransferError):
        validate_offer(bad, receiver.session_id)
    assert validate_accept({"transfer_id": offer["body"]["transfer_id"], "offset": 0}, 0) == 0
    with pytest.raises(TransferError):
        validate_accept({"transfer_id": offer["body"]["transfer_id"], "offset": 2 ** 31}, 10)
    with pytest.raises(TransferError):
        validate_accept({"transfer_id": "not-a-uuid", "offset": 0}, 10)


def test_file_body_validation() -> None:
    sender, receiver = _hello("Sender"), _hello("Receiver")
    with pytest.raises(ProtocolError):
        envelope("FILE_CHUNK", sender.peer_id, sender.session_id,
                 {"transfer_id": str(uuid4()), "offset": -1, "data": "aGk="})
    message = envelope("FILE_RESULT", sender.peer_id, sender.session_id,
                       {"transfer_id": str(uuid4()), "status": "verified",
                        "size": 0, "sha256": EMPTY_SHA})
    message["body"]["status"] = "broken"
    with pytest.raises(ProtocolError):
        validate_envelope(message)


def _deliver(source: bytes, tmp_path: Path, accept: bool) -> tuple[list[str], list[str], Path]:
    sender_hello, receiver_hello = _hello("Sender"), _hello("Receiver")
    sender_emit, receiver_emit = Emitter(), Emitter()
    sender = TransferService(sender_hello, sender_emit)
    receiver = TransferService(receiver_hello, receiver_emit)
    src = tmp_path / "source.bin"
    src.write_bytes(source)
    dest = tmp_path / "dest.bin"
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    try:
        peer = Peer(Hello(receiver_hello.peer_id, receiver_hello.session_id, "Receiver",
                          listener.getsockname()[1], ("file_v1",)), "127.0.0.1", 0.0)
        identifier = sender.send(src, peer)
        conn, _ = listener.accept()
        conn.settimeout(10)
        try:
            offer = recv_message(conn)
            assert offer is not None
            receiver.receive(conn, offer)
        except Exception:
            conn.close()
            raise
        assert _wait_offer(receiver_emit) == identifier
        assert receiver.decide(identifier, dest if accept else None)
        assert _wait_done(sender, receiver)
        return _states(sender_emit, identifier), _states(receiver_emit, identifier), dest
    finally:
        sender.stop()
        receiver.stop()
        assert sender.join(5)
        assert receiver.join(5)
        listener.close()


@pytest.mark.parametrize("size", [0, 2, 200000], ids=["empty", "small", "multi-chunk"])
def test_end_to_end_accept(tmp_path: Path, size: int) -> None:
    source = bytes(size)
    sender_states, receiver_states, dest = _deliver(source, tmp_path, True)
    assert "verified" in sender_states
    assert "saved" in receiver_states
    assert dest.read_bytes() == source


def test_end_to_end_decline(tmp_path: Path) -> None:
    sender_states, receiver_states, dest = _deliver(b"hi", tmp_path, False)
    assert "declined" in sender_states
    assert "declined" in receiver_states
    assert not dest.exists()


def test_hash_mismatch(tmp_path: Path) -> None:
    sender_hello, receiver_hello = _hello("Sender"), _hello("Receiver")
    receiver_emit = Emitter()
    receiver = TransferService(receiver_hello, receiver_emit)
    offer = envelope("FILE_OFFER", sender_hello.peer_id, sender_hello.session_id,
                     {"transfer_id": str(uuid4()), "name": "notes.txt", "size": 2,
                      "sha256": "0" * 64, "to_session": receiver_hello.session_id})
    first, second = socket.socketpair()
    dest = tmp_path / "dest.bin"
    try:
        receiver.receive(second, offer)
        identifier = _wait_offer(receiver_emit)
        assert receiver.decide(identifier, dest)
        assert recv_message(first, timeout=10)["type"] == "FILE_ACCEPT"
        chunk = envelope("FILE_CHUNK", sender_hello.peer_id, sender_hello.session_id,
                         {"transfer_id": offer["body"]["transfer_id"], "offset": 0,
                          "data": base64.b64encode(b"hi").decode("ascii")})
        send_message(first, chunk)
        send_message(first, envelope("FILE_DONE", sender_hello.peer_id,
                                     sender_hello.session_id,
                                     {"transfer_id": offer["body"]["transfer_id"]}))
        assert recv_message(first, timeout=10) is None
        assert _wait_done(receiver)
        assert "failed" in _states(receiver_emit, identifier)
        assert not dest.exists()
        leftovers = list(tmp_path.glob(".lman-*.part"))
        assert leftovers == []
    finally:
        first.close()
        receiver.stop()
        assert receiver.join(5)


def test_sender_cancel_during_offer(tmp_path: Path) -> None:
    sender_hello = _hello("Sender")
    sender_emit, receiver_emit = Emitter(), Emitter()
    sender = TransferService(sender_hello, sender_emit)
    receiver = TransferService(_hello("Receiver"), receiver_emit)
    src = tmp_path / "source.bin"
    src.write_bytes(b"hi")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    try:
        peer = Peer(Hello(receiver.hello.peer_id, receiver.hello.session_id, "Receiver",
                          listener.getsockname()[1], ("file_v1",)), "127.0.0.1", 0.0)
        identifier = sender.send(src, peer)
        conn, _ = listener.accept()
        conn.settimeout(10)
        try:
            offer = recv_message(conn)
            assert offer is not None
            receiver.receive(conn, offer)
        except Exception:
            conn.close()
            raise
        assert _wait_offer(receiver_emit) == identifier
        sender.cancel(identifier)
        assert _wait_done(sender, receiver)
        assert "cancelled" in _states(sender_emit, identifier)
        assert "failed" in _states(receiver_emit, identifier)
    finally:
        sender.stop()
        receiver.stop()
        assert sender.join(5)
        assert receiver.join(5)
        listener.close()


def test_destination_exists_declines_promptly(tmp_path: Path) -> None:
    sender_states, receiver_states, dest = _deliver(b"hi", tmp_path, True)
    assert "verified" in sender_states
    assert dest.read_bytes() == b"hi"
    src = tmp_path / "second.bin"
    src.write_bytes(b"xy")
    sender_hello = _hello("Sender")
    sender_emit, receiver_emit = Emitter(), Emitter()
    sender = TransferService(sender_hello, sender_emit)
    receiver = TransferService(_hello("Receiver"), receiver_emit)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    try:
        peer = Peer(Hello(receiver.hello.peer_id, receiver.hello.session_id, "Receiver",
                          listener.getsockname()[1], ("file_v1",)), "127.0.0.1", 0.0)
        identifier = sender.send(src, peer)
        conn, _ = listener.accept()
        conn.settimeout(10)
        try:
            offer = recv_message(conn)
            assert offer is not None
            receiver.receive(conn, offer)
        except Exception:
            conn.close()
            raise
        assert _wait_offer(receiver_emit) == identifier
        assert receiver.decide(identifier, dest)
        assert _wait_done(sender, receiver)
        assert "declined" in _states(sender_emit, identifier)
        assert "failed" in _states(receiver_emit, identifier)
        assert dest.read_bytes() == b"hi"
    finally:
        sender.stop()
        receiver.stop()
        assert sender.join(5)
        assert receiver.join(5)
        listener.close()


def test_transfer_limit() -> None:
    service = TransferService(_hello("Receiver"), Emitter())
    pairs = [socket.socketpair() for _ in range(4)]
    try:
        for first, second in pairs:
            service.receive(second, _offer(_hello("Sender"), service.hello))
        with pytest.raises(TransferError):
            extra, other = socket.socketpair()
            try:
                service.receive(extra, _offer(_hello("Sender"), service.hello))
            finally:
                extra.close()
                other.close()
    finally:
        for first, second in pairs:
            first.close()
        service.stop()
        assert service.join(5)


def test_gui_transfer_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from gui.main_window import MainWindow

    from core.chat import ChatService

    app = QApplication.instance() or QApplication([])
    window = MainWindow(ChatService(_hello("Alice")))
    window.update_transfer({"id": "one", "name": "notes.txt", "state": "queued",
                            "bytes": 1, "total": 2})
    assert "1/2" in window.transfer_list.itemText(0)
    window.update_transfer({"id": "one", "state": "saved", "bytes": 2, "total": 2,
                            "path": "dest"})
    assert "2/2" in window.transfer_list.itemText(0)
    assert "saved" in window.log.toPlainText()
    window.close()
