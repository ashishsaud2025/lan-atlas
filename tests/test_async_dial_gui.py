from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
import threading
import time
from typing import TYPE_CHECKING

import pytest

from core.chat import ChatService
from core.discovery import Hello
from core.storage import JsonLinesPostStore
from test_async_dial import dial_service, wait_result

if TYPE_CHECKING:
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow


@pytest.fixture
def dial_window(dial_service: tuple[ChatService, Hello],
                monkeypatch: pytest.MonkeyPatch,
                tmp_path: Path) -> Iterator[tuple[MainWindow, Hello, QApplication]]:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    service, target = dial_service
    service.post_store = JsonLinesPostStore(tmp_path / "posts.jsonl")
    window = MainWindow(service)
    for combo in (window.recipient, window.feed_peer, window.directory_peer):
        combo.addItem("Remote Internet", ("inet", target.peer_id))
        combo.setCurrentIndex(combo.count() - 1)
    yield window, target, app
    window.close()
    app.processEvents()


def pump(app: QApplication, predicate: Callable[[], bool]) -> None:
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    assert predicate()


@pytest.mark.parametrize("action,kind", [
    ("send", "CHAT"), ("sync_feed", "POST_QUERY"),
    ("_sync_directory", "DIR_QUERY"), ("send_file", "file"),
])
def test_gui_resumes_original_action_without_blocking(
        dial_window: tuple[MainWindow, Hello, QApplication],
        monkeypatch: pytest.MonkeyPatch, action: str, kind: str) -> None:
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QFileDialog

    window, target, app = dial_window
    service = window.service
    entered, release = threading.Event(), threading.Event()
    main_thread = threading.get_ident()
    dialogs: list[int] = []
    ticks: list[bool] = []

    def probe(host: str, port: int, peer_id: str,
              **kwargs: object) -> tuple[str, str]:
        assert threading.get_ident() != main_thread
        entered.set()
        assert release.wait(5)
        return target.session_id, host

    def choose(*args: object) -> tuple[str, str]:
        dialogs.append(threading.get_ident())
        return "", ""

    monkeypatch.setattr(service.secure_transport, "probe_session", probe)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", choose)
    window.input.setText("Original draft")
    try:
        getattr(window, action)()
        assert entered.wait(2)
        getattr(window, action)()
        QTimer.singleShot(0, lambda: ticks.append(True))
        pump(app, lambda: bool(ticks))
        assert service._outgoing.empty()
        assert not dialogs
        assert "Resolving" in window.log.toPlainText()
        for combo in (window.recipient, window.feed_peer, window.directory_peer):
            combo.setCurrentIndex(0)
        window.input.setText("New draft")
        release.set()
        pump(app, lambda: bool(dialogs) or not service._outgoing.empty())
        if kind == "file":
            assert dialogs == [main_thread]
        else:
            peer, message = service._outgoing.get_nowait()
            assert peer.hello.peer_id == target.peer_id
            assert message["type"] == kind
            if kind == "CHAT":
                assert message["body"]["text"] == "Original draft"
                assert message["body"]["to_session"] == target.session_id
        window.drain()
        assert service._outgoing.empty()
        assert window.input.text() == "New draft"
    finally:
        release.set()


def test_gui_failed_probe_keeps_draft_and_can_retry(
        dial_window: tuple[MainWindow, Hello, QApplication],
        monkeypatch: pytest.MonkeyPatch) -> None:
    window, target, app = dial_window

    def fail(host: str, port: int, peer_id: str,
             **kwargs: object) -> tuple[str, str]:
        raise OSError("offline test endpoint")

    monkeypatch.setattr(window.service.secure_transport, "probe_session", fail)
    window.input.setText("Keep me")
    window.send()
    pump(app, lambda: "dial failed" in window.log.toPlainText())
    assert window.input.text() == "Keep me"
    assert window.service._outgoing.empty()
    monkeypatch.setattr(window.service.secure_transport, "probe_session",
                        lambda host, port, peer_id, **kw: (target.session_id, host))
    window.send()
    pump(app, lambda: not window.service._outgoing.empty())
    assert window.input.text() == ""


def test_gui_close_cancels_pending_send(
        dial_window: tuple[MainWindow, Hello, QApplication],
        monkeypatch: pytest.MonkeyPatch) -> None:
    window, target, app = dial_window
    entered, release = threading.Event(), threading.Event()

    def probe(host: str, port: int, peer_id: str,
              **kwargs: object) -> tuple[str, str]:
        entered.set()
        assert release.wait(5)
        return target.session_id, host

    monkeypatch.setattr(window.service.secure_transport, "probe_session", probe)
    try:
        window.input.setText("Do not send after close")
        window.send()
        assert entered.wait(2)
        window.close()
        release.set()
        assert window.service.join(3)
        window.drain()
        assert window.service._outgoing.empty()
        assert not window._pending_internet
    finally:
        release.set()


@pytest.mark.parametrize("change", ["remove", "replace", "forget", "stop"])
def test_file_picker_revalidates_before_admission(
        dial_window: tuple[MainWindow, Hello, QApplication],
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path, change: str) -> None:
    from PySide6.QtWidgets import QFileDialog

    window, target, app = dial_window
    service = window.service
    chosen: list[bool] = []
    path = tmp_path / "offer.txt"
    path.write_text("Private file", encoding="utf-8")
    monkeypatch.setattr(service.secure_transport, "probe_session",
                        lambda host, port, peer_id, **kw: (target.session_id, host))

    def choose(*args: object) -> tuple[str, str]:
        if change == "remove":
            service.address_book.remove(target.peer_id)
        elif change == "replace":
            service.address_book.add(target.peer_id, "Moved", "127.0.0.2", 50004,
                                     target.capabilities, target.certificate_sha256)
        elif change == "forget":
            service.secure_transport.trust_store.forget(target.peer_id)
        else:
            service.stop()
        chosen.append(True)
        return str(path), ""

    def connect(peer: object) -> None:
        raise OSError("network must not be reached")

    monkeypatch.setattr(QFileDialog, "getOpenFileName", choose)
    monkeypatch.setattr(service.transfers, "connector", connect)
    window.send_file()
    pump(app, lambda: bool(chosen))
    assert window.transfer_rows == {}
    assert "changed" in window.log.toPlainText() or any(
        text in window.log.toPlainText()
        for text in ("no address book entry", "not paired", "stopping"))


def test_gui_full_dial_queue_keeps_draft_and_allows_retry(
        dial_window: tuple[MainWindow, Hello, QApplication],
        monkeypatch: pytest.MonkeyPatch) -> None:
    window, target, app = dial_window
    service = window.service
    entered, release = threading.Event(), threading.Event()

    def probe(host: str, port: int, peer_id: str,
              **kwargs: object) -> tuple[str, str]:
        entered.set()
        assert release.wait(5)
        return target.session_id, host

    monkeypatch.setattr(service.secure_transport, "probe_session", probe)
    try:
        tokens = [service.dial_peer_async(target.peer_id) for _ in range(8)]
        assert entered.wait(2)
        window.input.setText("Retry this draft")
        window.send()
        assert "queue full" in window.log.toPlainText()
        assert not window._pending_internet
        assert window.input.text() == "Retry this draft"
        release.set()
        for token in tokens:
            wait_result(service, token)
        window.send()
        pump(app, lambda: not service._outgoing.empty())
        _, message = service._outgoing.get_nowait()
        assert message["body"]["text"] == "Retry this draft"
    finally:
        release.set()
