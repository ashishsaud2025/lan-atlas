"""Small reusable widgets for the LAN Atlas shell."""

from __future__ import annotations

from collections.abc import Callable
import logging
from typing import Any

from PySide6.QtCore import QPoint, QRect, QSize, Qt, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QFrame, QLabel, QListWidget, QListWidgetItem, QPushButton, QVBoxLayout, QWidget,
)

from gui.theme import COLORS, GEOMETRY, SPACING


class NavigationRail(QFrame):
    """Persistent grouped primary navigation."""

    selected = Signal(int)

    def __init__(self, groups: tuple[tuple[str, tuple[tuple[str, int | None], ...]], ...]) -> None:
        super().__init__()
        self.setObjectName("Navigation")
        self.setFixedWidth(GEOMETRY["navigation"])
        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACING["sm"], SPACING["md"],
                                  SPACING["sm"], SPACING["md"])
        self.list = QListWidget()
        self.list.setObjectName("NavigationList")
        self.list.setAccessibleName("Primary navigation")
        self.list.setIconSize(QSize(18, 18))
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.page_items: dict[int, QListWidgetItem] = {}
        self.base_labels: dict[int, str] = {}
        for group, pages in groups:
            heading = QListWidgetItem(group.upper())
            heading.setFlags(Qt.ItemFlag.NoItemFlags)
            heading.setData(257, "group")
            self.list.addItem(heading)
            for page, index in pages:
                if index is None:
                    continue
                label = page
                item = QListWidgetItem(label)
                item.setIcon(_navigation_icon(page))
                item.setData(256, index)
                self.page_items[index] = item
                self.base_labels[index] = page
                self.list.addItem(item)
        self.list.currentItemChanged.connect(self._emit_page)
        self.list.setCurrentItem(self.page_items[0])
        layout.addWidget(self.list, 1)

    def set_compact(self, compact: bool) -> None:
        """Adjust rail density without changing its navigation structure."""
        width = (GEOMETRY["navigation_compact"] if compact
                 else GEOMETRY["navigation"])
        self.setFixedWidth(width)

    def select(self, index: int) -> None:
        """Select a page from keyboard shortcuts or contextual actions."""
        item = self.page_items.get(index)
        if item is not None:
            self.list.setCurrentItem(item)

    def set_badge(self, index: int, text: str) -> None:
        """Show a count badge on one page, clearing back to its base label."""
        item = self.page_items.get(index)
        if item is None:
            logging.warning("Navigation badge index missing: %s", index)
            return
        base = self.base_labels.get(index, item.text())
        shown = text.strip()
        if shown.isdigit() and int(shown) > 99:
            shown = "99+"
        item.setText(base if not shown else f"{base} ({shown})")

    def _emit_page(self, current: QListWidgetItem | None,
                   previous: QListWidgetItem | None) -> None:
        del previous
        if current is not None:
            value: Any = current.data(256)
            if isinstance(value, int):
                self.selected.emit(value)


def page_header(title: str, subtitle: str) -> QWidget:
    """Build a consistent page heading."""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 6)
    heading = QLabel(title)
    heading.setObjectName("PageTitle")
    detail = QLabel(subtitle)
    detail.setObjectName("PageSubtitle")
    detail.setWordWrap(True)
    layout.addWidget(heading)
    layout.addWidget(detail)
    return widget


def card(title: str, value: str) -> tuple[QFrame, QLabel]:
    """Create a compact overview metric card and return its value label."""
    frame = QFrame()
    frame.setProperty("card", True)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(SPACING["lg"], SPACING["lg"],
                              SPACING["lg"], SPACING["lg"])
    label = QLabel(title)
    label.setObjectName("MetricLabel")
    metric = QLabel(value)
    metric.setObjectName("MetricValue")
    layout.addWidget(label)
    layout.addWidget(metric)
    return frame, metric


def action_button(text: str, callback: Callable[[], None],
                  primary: bool = False) -> QPushButton:
    """Create a consistently styled action button."""
    button = QPushButton(text)
    button.setProperty("primary", primary)
    button.clicked.connect(callback)
    return button


def primary_action(text: str, callback: Callable[[], None]) -> QPushButton:
    """Create the one solid primary action for a page."""
    return action_button(text, callback, primary=True)


def empty_state(explanation: str, action_text: str,
                callback: Callable[[], None]) -> QFrame:
    """Build a guidance card with an explanation and one next action."""
    frame = QFrame()
    frame.setProperty("card", True)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(SPACING["lg"], SPACING["lg"],
                              SPACING["lg"], SPACING["lg"])
    detail = QLabel(explanation)
    detail.setObjectName("PageSubtitle")
    detail.setWordWrap(True)
    layout.addWidget(detail)
    layout.addWidget(primary_action(action_text, callback))
    return frame


def _navigation_icon(page: str) -> QIcon:
    """Draw Lucide-style stroke glyphs from theme tokens without dependencies."""
    pixmap = QPixmap(36, 36)
    pixmap.setDevicePixelRatio(2.0)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.scale(2.0, 2.0)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(COLORS["on-surface-variant"]), 2.0)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    if page == "Overview":
        for x, y in ((2, 2), (10, 2), (2, 10), (10, 10)):
            painter.drawRoundedRect(x, y, 6, 6, 1.5, 1.5)
    elif page == "Network":
        painter.drawLine(4, 6, 9, 9)
        painter.drawLine(14, 4, 9, 9)
        painter.drawLine(9, 9, 5, 14)
        for point in (QPoint(4, 5), QPoint(14, 3), QPoint(9, 9), QPoint(5, 14)):
            painter.drawEllipse(point, 2, 2)
    elif page == "Devices":
        painter.drawRoundedRect(QRect(2, 3, 14, 10), 2, 2)
        painter.drawLine(6, 16, 12, 16)
        painter.drawLine(9, 13, 9, 16)
    elif page == "Workbench":
        painter.drawRoundedRect(QRect(2, 3, 14, 10), 2, 2)
        painter.drawLine(6, 16, 12, 16)
        painter.drawLine(9, 13, 9, 16)
        painter.drawLine(5, 6, 13, 11)
    elif page == "Files":
        painter.drawLine(2, 7, 2, 15)
        painter.drawLine(2, 15, 16, 15)
        painter.drawLine(16, 15, 16, 7)
        painter.drawLine(16, 7, 11, 7)
        painter.drawLine(8, 7, 8, 4)
        painter.drawLine(8, 4, 4, 4)
        painter.drawLine(4, 4, 4, 7)
        painter.drawLine(4, 7, 2, 7)
    elif page == "Transfers":
        painter.drawLine(6, 3, 6, 15)
        painter.drawLine(3, 6, 6, 3)
        painter.drawLine(6, 3, 9, 6)
        painter.drawLine(12, 3, 12, 15)
        painter.drawLine(9, 12, 12, 15)
        painter.drawLine(12, 15, 15, 12)
    elif page == "Messages":
        painter.drawRoundedRect(QRect(2, 3, 14, 10), 2, 2)
        painter.drawLine(6, 13, 6, 16)
        painter.drawLine(6, 16, 9, 13)
        painter.drawLine(5, 6, 13, 6)
        painter.drawLine(5, 9, 11, 9)
    elif page == "Feed":
        painter.drawEllipse(QPoint(4, 14), 1.5, 1.5)
        painter.drawArc(QRect(2, 7, 9, 9), 0, 90 * 16)
        painter.drawArc(QRect(2, 3, 14, 14), 0, 90 * 16)
    elif page == "Games":
        painter.drawRoundedRect(QRect(2, 6, 14, 8), 3, 3)
        painter.drawLine(5, 8, 5, 12)
        painter.drawLine(3, 10, 7, 10)
        painter.drawPoint(12, 9)
        painter.drawPoint(14, 11)
    elif page == "Activity":
        painter.drawLine(2, 13, 6, 13)
        painter.drawLine(6, 13, 9, 5)
        painter.drawLine(9, 5, 12, 13)
        painter.drawLine(12, 13, 16, 10)
    elif page == "Settings":
        painter.drawEllipse(QPoint(9, 9), 3, 3)
        for step in range(8):
            painter.save()
            painter.translate(9, 9)
            painter.rotate(45 * step)
            painter.drawLine(0, -7, 0, -5)
            painter.restore()
    else:
        painter.drawEllipse(QRect(3, 3, 12, 12))
        painter.drawEllipse(QRect(7, 7, 4, 4))
    painter.end()
    return QIcon(pixmap)
