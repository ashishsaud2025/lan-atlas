from __future__ import annotations

import base64
import hashlib
import socket
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from core.discovery import Hello
from core.protocol import envelope, recv_message, send_message
from core.resume import ReceiveManifest, SendManifest
from core.transfer import CHUNK_SIZE, TransferError, TransferService

TID = "00000000-0000-4000-8000-000000000001"
PID = "00000000-0000-4000-8000-000000000002"
SID = "00000000-0000-4000-8000-000000000003"


def _receive_record(**overrides):
    record = {"transfer_id": TID, "name": "notes.txt", "size": 10,
              "sha256": "a" * 64, "held": 4, "peer_id": PID,
              "session_id": SID}
    record.update(overrides)
    return record


def test_corrupt_manifest_discards_to_none(tmp_path):
    (tmp_path / "resume.json").write_text("{broken", encoding="utf-8")
    assert ReceiveManifest.load(tmp_path, "notes.txt") is None


def test_expired_manifest_loads_none(tmp_path):
    import json
    record = _receive_record(saved_ms=1)
    (tmp_path / ("notes.txt." + "resume.json")).write_text(
        json.dumps(record), encoding="utf-8")
    assert ReceiveManifest.load(tmp_path, "notes.txt") is None


def test_save_load_round_trip(tmp_path):
    ReceiveManifest.save(tmp_path, _receive_record())
    loaded = ReceiveManifest.load(tmp_path, "notes.txt")
    assert loaded is not None
    assert loaded["held"] == 4
    assert loaded["sha256"] == "a" * 64


def test_send_manifest_round_trip(tmp_path):
    SendManifest.save(tmp_path, {"transfer_id": TID, "path": "notes.txt",
                                 "peer_id": PID, "session_id": SID})
    loaded = SendManifest.load(tmp_path, TID)
    assert loaded is not None
    assert loaded["peer_id"] == PID


class Emitter:
    def __init__(self) -> None:
        self.items: list[tuple[str, Any]] = []

    def __call__(self, kind: str, data: Any) -> bool:
        self.items.append((kind, data))
        return True


def _hello(name: str) -> Hello:
    return Hello(str(uuid4()), str(uuid4()), name, 50001, ("file_v1",))


def _wait_offer(emitter: Emitter, timeout: float = 10.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for kind, data in emitter.items:
            if kind == "file_offer":
                return data["id"]
        time.sleep(0.05)
    raise TimeoutError("file offer was not published")


def _wait_done(service: TransferService, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not service._transfers:
            return True
        time.sleep(0.05)
    return False


def _seed_partial(tmp_path: Path, original: bytes, held: int, sender: Hello,
                  receiver: Hello, transfer_id: str) -> Path:
    dest = tmp_path / "dest.bin"
    (tmp_path / "dest.bin.part").write_bytes(original[:held])
    digest = hashlib.sha256(original).hexdigest()
    ReceiveManifest.save(tmp_path, {"transfer_id": transfer_id, "name": "dest.bin",
                                    "size": len(original), "sha256": digest,
                                    "held": held, "peer_id": sender.peer_id,
                                    "session_id": sender.session_id})
    return dest


def test_receiver_resumes_from_manifest_offset(tmp_path):
    original = bytes(range(256)) * 800
    assert len(original) == 204800
    sender, receiver_hello = _hello("Sender"), _hello("Receiver")
    transfer_id = str(uuid4())
    held = 131072
    dest = _seed_partial(tmp_path, original, held, sender, receiver_hello, transfer_id)
    digest = hashlib.sha256(original).hexdigest()
    emit = Emitter()
    receiver = TransferService(receiver_hello, emit)
    first, second = socket.socketpair()
    try:
        offer = envelope("FILE_OFFER", sender.peer_id, sender.session_id,
                         {"transfer_id": transfer_id, "name": "dest.bin",
                          "size": len(original), "sha256": digest,
                          "to_session": receiver_hello.session_id,
                          "resume_id": transfer_id})
        receiver.receive(second, offer)
        identifier = _wait_offer(emit)
        assert receiver.decide(identifier, dest)
        accept = recv_message(first, timeout=10)
        assert accept is not None and accept["type"] == "FILE_ACCEPT"
        assert accept["body"].get("offset") == held
        offset = held
        while offset < len(original):
            chunk = original[offset:offset + CHUNK_SIZE]
            send_message(first, envelope(
                "FILE_CHUNK", sender.peer_id, sender.session_id,
                {"transfer_id": transfer_id, "offset": offset,
                 "data": base64.b64encode(chunk).decode("ascii")}))
            offset += len(chunk)
        send_message(first, envelope("FILE_DONE", sender.peer_id, sender.session_id,
                                     {"transfer_id": transfer_id}))
        result = recv_message(first, timeout=10)
        assert result is not None and result["type"] == "FILE_RESULT"
        assert _wait_done(receiver)
        assert dest.read_bytes() == original
    finally:
        first.close()
        receiver.stop()
        assert receiver.join(5)


def test_wrong_sender_peer_restarts_at_zero(tmp_path):
    original = bytes(1000)
    sender, receiver_hello = _hello("Sender"), _hello("Receiver")
    stranger = _hello("Stranger")
    transfer_id = str(uuid4())
    dest = _seed_partial(tmp_path, original, 500, stranger, receiver_hello, transfer_id)
    digest = hashlib.sha256(original).hexdigest()
    emit = Emitter()
    receiver = TransferService(receiver_hello, emit)
    first, second = socket.socketpair()
    try:
        offer = envelope("FILE_OFFER", sender.peer_id, sender.session_id,
                         {"transfer_id": transfer_id, "name": "dest.bin",
                          "size": len(original), "sha256": digest,
                          "to_session": receiver_hello.session_id,
                          "resume_id": transfer_id})
        receiver.receive(second, offer)
        identifier = _wait_offer(emit)
        assert receiver.decide(identifier, dest)
        accept = recv_message(first, timeout=10)
        assert accept is not None and accept["type"] == "FILE_ACCEPT"
        assert accept["body"].get("offset", 0) == 0
        receiver.cancel(identifier)
        assert _wait_done(receiver)
    finally:
        first.close()
        receiver.stop()
        assert receiver.join(5)


def _fake_receiver_accept(first: socket.socket, sender: Hello, receiver_hello: Hello,
                          transfer_id: str, offset: int, original: bytes) -> None:
    size = len(original)
    digest = hashlib.sha256(original).hexdigest()
    offer = recv_message(first, timeout=10)
    assert offer is not None and offer["type"] == "FILE_OFFER"
    assert offer["body"]["transfer_id"] == transfer_id
    send_message(first, envelope("FILE_ACCEPT", receiver_hello.peer_id,
                                 receiver_hello.session_id,
                                 {"transfer_id": transfer_id, "offset": offset}))
    received = bytearray()
    while True:
        message = recv_message(first, timeout=10)
        assert message is not None
        if message["type"] == "FILE_DONE":
            break
        assert message["type"] == "FILE_CHUNK"
        assert message["body"]["offset"] == offset + len(received)
        received += base64.b64decode(message["body"]["data"])
    assert bytes(received) == original[offset:]
    send_message(first, envelope("FILE_RESULT", receiver_hello.peer_id,
                                 receiver_hello.session_id,
                                 {"transfer_id": transfer_id, "status": "verified",
                                  "size": size, "sha256": digest}))


def test_sender_seeks_and_reseeds_on_offset(tmp_path):
    original = bytes(range(256)) * 800
    assert len(original) == 204800
    sender_hello, receiver_hello = _hello("Sender"), _hello("Receiver")
    src = tmp_path / "source.bin"
    src.write_bytes(original)
    emit = Emitter()
    sender = TransferService(sender_hello, emit)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    try:
        from core.roster import Peer
        from core.discovery import Hello as HelloInfo
        peer = Peer(HelloInfo(receiver_hello.peer_id, receiver_hello.session_id,
                              "Receiver", listener.getsockname()[1], ("file_v1",)),
                    "127.0.0.1", 0.0)
        identifier = sender.send(src, peer)
        conn, _ = listener.accept()
        conn.settimeout(10)
        try:
            _fake_receiver_accept(conn, sender_hello, receiver_hello, identifier,
                                  131072, original)
        finally:
            conn.close()
        assert _wait_done(sender)
        states = [data["state"] for kind, data in emit.items
                  if kind == "transfer" and data["id"] == identifier]
        assert "verified" in states
    finally:
        sender.stop()
        assert sender.join(5)
        listener.close()


def test_changed_source_restarts_with_new_id(tmp_path):
    sender_hello, receiver_hello = _hello("Sender"), _hello("Receiver")
    src = tmp_path / "source.bin"
    src.write_bytes(bytes(1000))
    from core.roster import Peer
    from core.discovery import Hello as HelloInfo
    peer = Peer(HelloInfo(receiver_hello.peer_id, receiver_hello.session_id,
                          "Receiver", 50099, ("file_v1",)), "127.0.0.1", 0.0)
    service = TransferService(sender_hello, Emitter())
    old_id = str(uuid4())
    SendManifest.save(tmp_path, {"transfer_id": old_id, "path": str(src),
                                 "size": 1000,
                                 "sha256": hashlib.sha256(bytes(1000)).hexdigest(),
                                 "peer_id": receiver_hello.peer_id,
                                 "session_id": receiver_hello.session_id})
    src.write_bytes(bytes(1001))
    try:
        new_id = service.resume_pending(peer, tmp_path)
        assert new_id is not None and new_id != old_id
        service.cancel(new_id)
    finally:
        service.stop()
        assert service.join(5)
