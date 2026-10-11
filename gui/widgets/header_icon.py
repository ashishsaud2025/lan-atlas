"""Small painted card-header glyphs reusing the nav icon technique.

Shapes follow the Material Symbols reference at header scale: hub uses
diagonal spokes so it never reads as a lens, stats keeps bars only to
avoid the query lens search connotation, and the inspector stays a
neutral person glyph since device type is unknowable."""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPen, QPixmap
from PySide6.QtWidgets import QLabel

from gui.theme.tokens import COLORS

_VALID_KINDS = ("hub", "stats", "table", "inspector", "activity", "radar")


def header_icon(kind: str) -> QLabel:
    """Return an 18px label with a painted glyph for a card header."""
    if kind not in _VALID_KINDS:
        raise ValueError(f"unknown header icon: {kind}")
    pixmap = QPixmap(36, 36)
    pixmap.setDevicePixelRatio(2.0)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.scale(2.0, 2.0)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(COLORS["primary"]), 2.0)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    if kind == "hub":
        _hub(painter)
    elif kind == "stats":
        _stats(painter)
    elif kind == "table":
        _table(painter)
    elif kind == "inspector":
        _inspector(painter)
    elif kind == "radar":
        _radar(painter)
    else:
        _activity(painter)
    painter.end()
    label = QLabel()
    label.setPixmap(pixmap)
    label.setFixedSize(18, 18)
    label.setAccessibleName(f"{kind} header icon")
    return label


def _hub(painter: QPainter) -> None:
    """Draw a hub cross with outer nodes and no handle-like diagonal."""
    painter.setBrush(QColor(COLORS["primary"]))
    painter.drawEllipse(QPointF(9, 9), 1.6, 1.6)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    for node in (QPointF(9, 3), QPointF(15, 9),
                 QPointF(9, 15), QPointF(3, 9)):
        painter.drawLine(QPointF(9, 9), node)
        painter.setBrush(QColor(COLORS["primary"]))
        painter.drawEllipse(node, 1.8, 1.8)
        painter.setBrush(Qt.BrushStyle.NoBrush)


def _stats(painter: QPainter) -> None:
    """Draw ascending bars over a baseline for the metrics header."""
    for x, top in ((4.5, 11.5), (9, 8), (13.5, 4.5)):
        painter.setPen(QPen(QColor(COLORS["primary"]), 2.5))
        painter.drawLine(x, 15, x, top)
    painter.setPen(QPen(QColor(COLORS["primary"]), 1.5))
    painter.drawLine(2, 15, 16, 15)


def _table(painter: QPainter) -> None:
    """Draw stacked rows with left ticks for the peer list header."""
    for y in (5.5, 9, 12.5):
        painter.drawLine(6.5, y, 16, y)
        painter.fillRect(2, int(y - 1), 2, 2, QColor(COLORS["primary"]))


def _inspector(painter: QPainter) -> None:
    """Draw a neutral person glyph that claims no device type."""
    painter.drawEllipse(QPointF(9, 5.8), 2.3, 2.3)
    painter.drawArc(3, 8, 12, 9, 25 * 16, 130 * 16)


def _radar(painter: QPainter) -> None:
    """Draw a ring with a sweep for the network mode control."""
    painter.drawEllipse(QPointF(9, 9), 6, 6)
    painter.drawEllipse(QPointF(9, 9), 1.5, 1.5)
    painter.drawLine(QPointF(9, 9), QPointF(13.5, 4.5))


def _activity(painter: QPainter) -> None:
    """Draw the existing pulse line for the activity header."""
    painter.drawLine(2, 12, 6, 12)
    painter.drawLine(6, 12, 9, 5)
    painter.drawLine(9, 5, 12, 13)
    painter.drawLine(12, 13, 16, 9)
