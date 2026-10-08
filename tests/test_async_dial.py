from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
import socket
import threading
import time
from uuid import uuid4

import pytest

from core.chat import ChatService
from core.discovery import Hello
from core.identity import DeviceIdentity
from core.roster import Peer
from core.secure_transport import SecureTransport, SecureTransportError
from core.trust import TrustStore


@pytest.fixture
def dial_service(tmp_path: Path) -> Iterator[tuple[ChatService, Hello]]:
    identity = DeviceIdentity.load_or_create(tmp_path / "local.pem", str(uuid4()))
    remote = DeviceIdentity.load_or_create(tmp_path / "remote.pem", str(uuid4()))
    hello = Hello(identity.peer_id, str(uuid4()), "Local", 50001,
                  ("secure_transport_v1",), 50003, identity.fingerprint)
    target = Hello(remote.peer_id, str(uuid4()), "Remote", 50001,
                   ("chat_v1", "file_v1", "posts_v1", "directory_v1",
                    "secure_transport_v1"), 50003, remote.fingerprint)
    trust = TrustStore(tmp_path / "trust.json")
    trust.pair(remote.peer_id, remote.certificate_der, "Remote")
    service = ChatService(
        hello, secure_transport=SecureTransport(identity, trust, hello),
        address_book=tmp_path / "book.json")
    service.address_book.add(target.peer_id, target.name, "127.0.0.1", 50003,
                             target.capabilities, remote.fingerprint)
    yield service, target
    service.stop()
    assert service.join(5)


def wait_result(service: ChatService, token: str) -> Peer:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        peer = service.take_dial_result(token)
        if peer is not None:
            return peer
        time.sleep(0.005)
    pytest.fail("dial result did not arrive")


def test_async_dial_does_not_block_and_survives_full_event_queue(
        dial_service: tuple[ChatService, Hello],
        monkeypatch: pytest.MonkeyPatch) -> None:
    service, target = dial_service
    entered, release = threading.Event(), threading.Event()
    caller = threading.get_ident()

    def probe(host: str, port: int, peer_id: str,
              **kwargs: object) -> tuple[str, str]:
        assert threading.get_ident() != caller
        entered.set()
        assert release.wait(5)
        return target.session_id, host

    monkeypatch.setattr(service.secure_transport, "probe_session", probe)
    while not service.events.full():
        service.events.put_nowait(("status", "busy"))
    try:
        token = service.dial_peer_async(target.peer_id)
        assert entered.wait(2)
        assert service.take_dial_result(token) is None
        release.set()
        peer = wait_result(service, token)
        assert peer.hello.peer_id == target.peer_id
        assert peer.hello.session_id == target.session_id
        assert peer.ip == "127.0.0.1"
        with pytest.raises(ValueError, match="unknown"):
            service.take_dial_result(token)
    finally:
        release.set()


def test_dial_queue_bounds_unconsumed_results(
        dial_service: tuple[ChatService, Hello],
        monkeypatch: pytest.MonkeyPatch) -> None:
    service, target = dial_service
    entered, release = threading.Event(), threading.Event()
    calls: list[int] = []

    def probe(host: str, port: int, peer_id: str,
              **kwargs: object) -> tuple[str, str]:
        calls.append(threading.get_ident())
        entered.set()
        assert release.wait(5)
        return target.session_id, host

    monkeypatch.setattr(service.secure_transport, "probe_session", probe)
    try:
        tokens = [service.dial_peer_async(target.peer_id) for _ in range(8)]
        assert entered.wait(2)
        with pytest.raises(RuntimeError, match="full"):
            service.dial_peer_async(target.peer_id)
        release.set()
        wait_result(service, tokens.pop())
        replacement = service.dial_peer_async(target.peer_id)
        with pytest.raises(RuntimeError, match="full"):
            service.dial_peer_async(target.peer_id)
        for token in [*tokens, replacement]:
            wait_result(service, token)
        assert len(calls) == 1
    finally:
        release.set()


@pytest.mark.parametrize("change", ["remove", "replace", "forget"])
def test_completed_dial_rechecks_entry_and_trust(
        dial_service: tuple[ChatService, Hello],
        monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    service, target = dial_service
    monkeypatch.setattr(service.secure_transport, "probe_session",
                        lambda host, port, peer_id, **kw: (target.session_id, host))
    token = service.dial_peer_async(target.peer_id)
    deadline = time.monotonic() + 5
    while target.peer_id not in service._dial_cache and time.monotonic() < deadline:
        time.sleep(0.005)
    assert target.peer_id in service._dial_cache
    if change == "remove":
        service.address_book.remove(target.peer_id)
    elif change == "replace":
        service.address_book.add(target.peer_id, "Moved", "127.0.0.2", 50004,
                                 target.capabilities, target.certificate_sha256)
    else:
        service.secure_transport.trust_store.forget(target.peer_id)
    with pytest.raises(ValueError):
        wait_result(service, token)


def test_dial_cache_is_bound_to_entry(
        dial_service: tuple[ChatService, Hello],
        monkeypatch: pytest.MonkeyPatch) -> None:
    service, target = dial_service
    calls: list[tuple[str, int]] = []

    def probe(host: str, port: int, peer_id: str,
              **kwargs: object) -> tuple[str, str]:
        calls.append((host, port))
        return target.session_id, host

    monkeypatch.setattr(service.secure_transport, "probe_session", probe)
    first = wait_result(service, service.dial_peer_async(target.peer_id))
    assert first.ip == "127.0.0.1"
    service.address_book.add(target.peer_id, "Moved", "127.0.0.2", 50004,
                             target.capabilities, target.certificate_sha256)
    second = wait_result(service, service.dial_peer_async(target.peer_id))
    assert second.ip == "127.0.0.2"
    assert calls == [("127.0.0.1", 50003), ("127.0.0.2", 50004)]


def test_failed_dial_releases_capacity_and_worker_recovers(
        dial_service: tuple[ChatService, Hello],
        monkeypatch: pytest.MonkeyPatch) -> None:
    service, target = dial_service

    def fail(host: str, port: int, peer_id: str,
             **kwargs: object) -> tuple[str, str]:
        raise SecureTransportError("unreachable")

    monkeypatch.setattr(service.secure_transport, "probe_session", fail)
    with pytest.raises(ValueError, match="dial failed"):
        wait_result(service, service.dial_peer_async(target.peer_id))
    monkeypatch.setattr(service.secure_transport, "probe_session",
                        lambda host, port, peer_id, **kw: (target.session_id, host))
    assert wait_result(service, service.dial_peer_async(target.peer_id)).ip == "127.0.0.1"


def test_stop_discards_queued_dials_and_joins_worker(
        dial_service: tuple[ChatService, Hello],
        monkeypatch: pytest.MonkeyPatch) -> None:
    service, target = dial_service
    entered, release = threading.Event(), threading.Event()
    calls: list[str] = []

    def probe(host: str, port: int, peer_id: str,
              **kwargs: object) -> tuple[str, str]:
        calls.append(peer_id)
        entered.set()
        assert release.wait(5)
        return target.session_id, host

    monkeypatch.setattr(service.secure_transport, "probe_session", probe)
    try:
        token = service.dial_peer_async(target.peer_id)
        assert entered.wait(2)
        service.dial_peer_async(target.peer_id)
        service.stop()
        assert not service.join(0.01)
        with pytest.raises(RuntimeError, match="stopping"):
            service.dial_peer_async(target.peer_id)
        with pytest.raises(RuntimeError, match="stopping"):
            service.take_dial_result(token)
        release.set()
        assert service.join(3)
        assert calls == [target.peer_id]
        assert target.peer_id not in service._dial_cache
    finally:
        release.set()


@pytest.mark.parametrize("change", ["remove", "replace", "forget"])
def test_dialed_peer_cannot_downgrade_or_use_changed_entry(
        dial_service: tuple[ChatService, Hello],
        monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    service, target = dial_service
    monkeypatch.setattr(service.secure_transport, "probe_session",
                        lambda host, port, peer_id, **kw: (target.session_id, host))
    peer = wait_result(service, service.dial_peer_async(target.peer_id))
    if change == "remove":
        service.address_book.remove(target.peer_id)
    elif change == "replace":
        service.address_book.add(target.peer_id, "Moved", "127.0.0.2", 50004,
                                 target.capabilities, target.certificate_sha256)
    else:
        service.secure_transport.trust_store.forget(target.peer_id)
    attempts: list[object] = []

    def connect(*args: object, **kwargs: object) -> None:
        attempts.append(args)
        raise OSError("network must not be reached")

    monkeypatch.setattr(socket, "create_connection", connect)
    with pytest.raises(ValueError):
        service._connect_peer(peer)
    assert not attempts


@pytest.mark.parametrize("stop_during", ["dns", "first_attempt"])
def test_probe_never_starts_another_connection_after_stop(
        dial_service: tuple[ChatService, Hello],
        monkeypatch: pytest.MonkeyPatch, stop_during: str) -> None:
    service, target = dial_service
    entered, release = threading.Event(), threading.Event()
    attempts: list[str] = []

    def resolve(host: str) -> tuple[str, ...]:
        if stop_during == "dns":
            entered.set()
            assert release.wait(5)
        return ("127.0.0.1", "127.0.0.2")

    def probe_one(host: str, *args: object, **kwargs: object) -> str:
        attempts.append(host)
        if stop_during == "first_attempt":
            entered.set()
            assert release.wait(5)
        raise OSError("cancelled probe")

    monkeypatch.setattr("core.secure_transport.resolve_host", resolve)
    monkeypatch.setattr(service.secure_transport, "_probe_one", probe_one)
    try:
        service.dial_peer_async(target.peer_id)
        assert entered.wait(2)
        service.stop()
        release.set()
        assert service.join(3)
        assert attempts == ([] if stop_during == "dns" else ["127.0.0.1"])
    finally:
        release.set()


@pytest.mark.parametrize("change", ["remove", "replace", "forget"])
def test_changed_entry_during_probe_never_populates_cache(
        dial_service: tuple[ChatService, Hello],
        monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    service, target = dial_service
    entered, release = threading.Event(), threading.Event()

    def probe(host: str, port: int, peer_id: str,
              **kwargs: object) -> tuple[str, str]:
        entered.set()
        assert release.wait(5)
        return target.session_id, host

    monkeypatch.setattr(service.secure_transport, "probe_session", probe)
    try:
        token = service.dial_peer_async(target.peer_id)
        assert entered.wait(2)
        if change == "remove":
            service.address_book.remove(target.peer_id)
        elif change == "replace":
            service.address_book.add(target.peer_id, "Moved", "127.0.0.2", 50004,
                                     target.capabilities, target.certificate_sha256)
        else:
            service.secure_transport.trust_store.forget(target.peer_id)
        release.set()
        with pytest.raises(ValueError):
            wait_result(service, token)
        assert target.peer_id not in service._dial_cache
    finally:
        release.set()


def test_stop_interrupts_connecting_probe_socket(
        dial_service: tuple[ChatService, Hello],
        monkeypatch: pytest.MonkeyPatch) -> None:
    service, target = dial_service
    entered, closed = threading.Event(), threading.Event()

    class ConnectingSocket:
        def settimeout(self, timeout: float) -> None:
            pass

        def connect(self, address: tuple[str, int]) -> None:
            entered.set()
            assert closed.wait(5)
            raise OSError("interrupted connect")

        def shutdown(self, how: int) -> None:
            closed.set()

        def close(self) -> None:
            closed.set()

    monkeypatch.setattr(socket, "socket", lambda *args: ConnectingSocket())
    try:
        service.dial_peer_async(target.peer_id)
        assert entered.wait(2)
        service.stop()
        assert closed.wait(1)
        assert service.join(3)
        assert not service._active
    finally:
        closed.set()
