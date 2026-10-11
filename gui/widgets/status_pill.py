"""State pill styled only through QSS attribute selectors."""

from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QLabel

_VALID_STATES = (
    "reachable", "compatible", "nearby", "unverified", "paired",
    "key_changed", "offline",
)


class StatusPill(QLabel):
    """Small state badge whose colors come from QSS, never instance code."""

    def __init__(self, text: str = "", state: str = "nearby") -> None:
        super().__init__(text)
        self.setObjectName("StatusPill")
        font = self.font()
        font.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 108)
        self.setFont(font)
        self._state = "nearby"
        self.set_state(state)

    def set_state(self, state: str) -> None:
        """Update the state property and repolish so QSS reselects."""
        if state not in _VALID_STATES:
            raise ValueError(f"unknown pill state: {state}")
        self._state = state
        self.setProperty("state", state)
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()

    def state(self) -> str:
        """Return the current pill state for tests and debugging."""
        return self._state
