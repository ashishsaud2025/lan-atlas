"""Persistent shell header with branding, node chips, and trust pill.

The widget owns no networking. MainWindow pushes values through setters
and keeps its existing PeerRepository wiring untouched."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPen, QPixmap
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy

from gui.theme.tokens import COLORS, SPACE
from gui.widgets.mono_label import MonoLabel

_VALID_VERIFICATION = ("unverified", "verified")
_HEIGHT = 58


def _radar_mark() -> QLabel:
    """Paint a small radar glyph with the established icon technique."""
    mark = QLabel()
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
    painter.drawEllipse(2, 2, 14, 14)
    painter.drawEllipse(6, 6, 6, 6)
    painter.drawLine(9, 9, 15, 4)
    painter.end()
    mark.setPixmap(pixmap)
    mark.setFixedSize(18, 18)
    mark.setAccessibleName("LAN Atlas mark")
    return mark


class TopBar(QFrame):
    """Fixed header shared by every page, driven only through setters."""

    verified_selected = Signal()

    def __init__(self, node_name: str, peer_short: str) -> None:
        super().__init__()
        self.setObjectName("ApplicationHeader")
        self.setFixedHeight(_HEIGHT)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(SPACE["md"], SPACE["sm"],
                                  SPACE["md"], SPACE["sm"])
        layout.setSpacing(SPACE["sm"])
        layout.addWidget(_radar_mark())
        wordmark = QLabel("LAN ATLAS")
        wordmark.setObjectName("Brand")
        layout.addWidget(wordmark)
        version = MonoLabel("v1 local")
        version.setProperty("chip", True)
        layout.addWidget(version)
        self.identity = MonoLabel(f"NODE · {node_name}\n{peer_short}")
        self.identity.setObjectName("HeaderMetric")
        layout.addWidget(self.identity)
        self.nearby = MonoLabel("0 sessions nearby")
        self.nearby.setObjectName("HeaderMetric")
        layout.addWidget(self.nearby)
        self.network = MonoLabel("Network core configured")
        self.network.setObjectName("HeaderMetric")
        layout.addWidget(self.network)
        self.transfers = MonoLabel("0 active transfers")
        self.transfers.setObjectName("HeaderMetric")
        layout.addWidget(self.transfers)
        layout.addStretch(1)
        self.command = QPushButton("Commands  Ctrl+K")
        self.command.setEnabled(False)
        self.command.setToolTip("Command palette reserved for a later phase")
        layout.addWidget(self.command)
        self.security = QPushButton("◇  Unverified LAN")
        self.security.setProperty("security", True)
        self.security.setProperty("state", "unverified")
        self.security.setToolTip(
            "Discovery remains self-reported. Trust and authenticated TLS are "
            "established separately for each explicitly paired device.")
        self.security.setSizePolicy(QSizePolicy.Policy.Fixed,
                                    QSizePolicy.Policy.Fixed)
        layout.addWidget(self.security)
        self._verification = "unverified"

    def set_identity(self, text: str) -> None:
        """Update the node identity chip from shell state."""
        self.identity.setText(text)

    def set_nearby(self, text: str) -> None:
        """Update the session count chip from shell state."""
        self.nearby.setText(text)

    def set_network(self, text: str) -> None:
        """Update the network state chip from shell state."""
        self.network.setText(text)

    def set_transfers(self, text: str) -> None:
        """Update the transfer count chip from shell state."""
        self.transfers.setText(text)

    def set_verification(self, state: str) -> None:
        """Switch the trust pill between the two known vocabulary states."""
        if state not in _VALID_VERIFICATION:
            raise ValueError(f"unknown verification state: {state}")
        self._verification = state
        self.security.setProperty("state", state)
        self.security.setText("◇  Unverified LAN"
                              if state == "unverified" else "●  Verified LAN")
        self.security.style().unpolish(self.security)
        self.security.style().polish(self.security)
        self.security.update()

    def verification(self) -> str:
        """Return the current trust pill state for tests."""
        return self._verification
