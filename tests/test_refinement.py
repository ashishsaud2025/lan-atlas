from __future__ import annotations

from uuid import uuid4

import pytest

from core.chat import ChatService
from core.discovery import Hello


def _service() -> ChatService:
    hello = Hello(str(uuid4()), str(uuid4()), "Local", 50001,
                  ("chat_v1", "file_v1", "posts_v1"))
    return ChatService(hello)


@pytest.fixture
def app() -> object:
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app: object, tmp_path) -> object:
    from pathlib import Path

    from PySide6.QtWidgets import QApplication

    from core.storage import JsonLinesPostStore
    from gui.main_window import MainWindow

    service = _service()
    service.post_store = JsonLinesPostStore(tmp_path / "posts.jsonl")
    result = MainWindow(service)
    result.show()
    QApplication.processEvents()
    yield result
    result.close()
    QApplication.processEvents()


def test_nav_badges_show_counts_and_clamp(app: object, window: object) -> None:
    window.navigation.set_badge(2, "3")
    assert "3" in window.navigation.page_items[2].text()
    window.navigation.set_badge(2, "150")
    assert "99+" in window.navigation.page_items[2].text()
    window.navigation.set_badge(2, "")
    assert window.navigation.page_items[2].text() == "Devices"


def test_overview_hero_toggles_service(app: object, window: object) -> None:
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    assert window.hero_action.text() == 'Start session'
    QTest.mouseClick(window.hero_action, Qt.MouseButton.LeftButton)
    assert window.hero_action.text() == 'Stop session'
    QTest.mouseClick(window.hero_action, Qt.MouseButton.LeftButton)
    assert window.hero_action.text() == 'Session stopped'
    assert not window.hero_action.isEnabled()


def test_empty_states_guide_next_action(app: object, window: object) -> None:
    from PySide6.QtWidgets import QLabel

    from gui.components import empty_state
    widget = empty_state('No messages yet', 'Start chatting', lambda: None)
    texts = [child.text() for child in widget.findChildren(QLabel)]
    assert any('No messages yet' in text for text in texts)
    assert not window.messages_empty.isHidden()
    assert not window.files_empty.isHidden()
    assert not window.feed_empty.isHidden()


def test_messages_empty_hides_on_first_row(app: object, window: object) -> None:
    from PySide6.QtWidgets import QApplication

    from gui.models import MessageEntry
    assert not window.messages_empty.isHidden()
    window.message_model.append(MessageEntry('id-1', 'Peer', 'hi', 'room', 'accepted', False, 0))
    QApplication.processEvents()
    assert window.messages_empty.isHidden()


def test_hero_shows_stopped_state(app: object, window: object) -> None:
    import time
    from uuid import uuid4

    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest

    from core.discovery import Hello
    from core.peer_repository import PeerRecord
    hello = Hello(str(uuid4()), str(uuid4()), 'P', 50001, ('chat_v1',))
    window.peer_records = (PeerRecord(hello, '192.168.1.2', time.monotonic()),)
    QTest.mouseClick(window.hero_action, Qt.MouseButton.LeftButton)
    assert window.hero_action.text() == 'Stop session'
    QTest.mouseClick(window.hero_action, Qt.MouseButton.LeftButton)
    assert window.hero_action.text() == 'Session stopped'
    assert not window.hero_action.isEnabled()
    assert window.hero_count.text() == '0'


def test_badge_unknown_index_warns(app: object, window: object, caplog) -> None:
    import logging
    window.navigation.set_badge(999, '3')
    assert window.navigation.page_items.get(999) is None
    assert any('999' in record.message for record in caplog.records
               if record.levelno >= logging.WARNING)
