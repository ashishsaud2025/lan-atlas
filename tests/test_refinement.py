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
