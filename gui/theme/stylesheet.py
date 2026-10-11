"""QSS for Overview presentation widgets built from design tokens.

Only token values are used so palette or density tweaks stay centralized."""

from __future__ import annotations

from gui.theme.tokens import BUTTON_RADIUS_PX, COLORS, FONTS, RADIUS, SPACE


def _styles() -> dict[str, dict[str, object]]:
    """Return typed access to the typography styles without casting inline."""
    styles = FONTS["styles"]
    assert isinstance(styles, dict)
    return styles  # type: ignore[return-value]


def build_stylesheet() -> str:
    """Build Overview widget QSS from tokens for cards, pills, and inputs."""
    code_sm = _styles()["label-code-sm"]
    assert isinstance(code_sm, dict)
    return f"""
        QFrame[card="true"] {{
            background: {COLORS["surface-container-low"]};
            border: 1px solid {COLORS["surface-container"]};
            border-radius: {RADIUS["DEFAULT"]}px;
        }}
        QLabel#MetricLabel {{
            color: {COLORS["on-surface-variant"]};
            font-size: 12px;
        }}
        QLabel#MetricValue {{
            color: {COLORS["on-surface"]};
            font-family: "{FONTS["mono"]}";
            font-size: 22px;
            font-weight: 700;
        }}
        QLabel#StatusPill {{
            font-family: "{FONTS["mono"]}";
            font-size: {code_sm["size"]}px;
            font-weight: {code_sm["weight"]};
            border-radius: {RADIUS["sm"]}px;
            padding: {SPACE["xs"]}px {SPACE["sm"]}px;
            border: 1px solid {COLORS["outline-variant"]};
            color: {COLORS["on-surface-variant"]};
            background: {COLORS["surface-container-low"]};
        }}
        QLabel#StatusPill[state="reachable"] {{
            color: {COLORS["primary"]};
            border: 1px solid {COLORS["primary"]};
            background: {COLORS["surface-container"]};
        }}
        QLabel#StatusPill[state="compatible"] {{
            color: {COLORS["primary-fixed-dim"]};
            border: 1px solid {COLORS["primary-container"]};
            background: {COLORS["surface-container"]};
        }}
        QLabel#StatusPill[state="nearby"] {{
            color: {COLORS["on-surface"]};
            border: 1px solid {COLORS["outline-variant"]};
            background: {COLORS["surface-container-high"]};
        }}
        QLabel#StatusPill[state="unverified"] {{
            color: {COLORS["tertiary"]};
            border: 1px solid {COLORS["on-tertiary-fixed-variant"]};
            background: {COLORS["surface-container-low"]};
        }}
        QLabel#StatusPill[state="paired"] {{
            color: {COLORS["secondary"]};
            border: 1px solid {COLORS["secondary"]};
            background: {COLORS["surface-container-low"]};
        }}
        QLabel#StatusPill[state="key_changed"] {{
            color: {COLORS["error"]};
            border: 1px solid {COLORS["error"]};
            background: {COLORS["surface-container-low"]};
        }}
        QLabel#StatusPill[state="offline"] {{
            color: {COLORS["outline"]};
            border: 1px dashed {COLORS["outline-variant"]};
            background: {COLORS["surface-container-lowest"]};
        }}
        QPushButton[primary="true"] {{
            background: {COLORS["primary-container"]};
            color: {COLORS["on-primary"]};
            border: 1px solid {COLORS["primary-container"]};
            border-radius: {BUTTON_RADIUS_PX}px;
            font-weight: 600;
            padding: {SPACE["sm"]}px {SPACE["md"]}px;
        }}
        QPushButton[primary="true"]:hover {{
            background: {COLORS["primary"]};
        }}
        QPushButton[ghost="true"] {{
            background: {COLORS["surface-container-low"]};
            border: 1px solid {COLORS["surface-container-highest"]};
            color: {COLORS["on-surface-variant"]};
            border-radius: {BUTTON_RADIUS_PX}px;
            padding: {SPACE["sm"]}px {SPACE["md"]}px;
        }}
        QPushButton[ghost="true"]:hover {{
            border: 1px solid {COLORS["primary"]};
            color: {COLORS["on-surface"]};
        }}
        QPushButton[security="true"][state="unverified"] {{
            color: {COLORS["tertiary"]};
            background: {COLORS["surface-container-low"]};
            border: 1px solid {COLORS["on-tertiary-fixed-variant"]};
        }}
        QPushButton[security="true"][state="verified"] {{
            color: {COLORS["secondary"]};
            background: {COLORS["surface-container-low"]};
            border: 1px solid {COLORS["secondary"]};
        }}
        QLineEdit:focus, QComboBox:focus {{
            border: 1px solid {COLORS["primary-container"]};
        }}
        QTabWidget::pane {{
            background: {COLORS["surface-container-low"]};
            border: 1px solid {COLORS["surface-container"]};
            border-radius: {RADIUS["DEFAULT"]}px;
        }}
        QTabBar::tab {{
            background: {COLORS["surface-container"]};
            color: {COLORS["on-surface-variant"]};
            border: 1px solid {COLORS["surface-container"]};
            border-radius: {RADIUS["sm"]}px;
            padding: {SPACE["xs"]}px {SPACE["sm"]}px;
        }}
        QTabBar::tab:selected {{
            color: {COLORS["primary"]};
            border: 1px solid {COLORS["primary-container"]};
        }}
        QTabBar::tab:!enabled {{
            color: {COLORS["outline"]};
        }}
        QLabel#PulseDot {{
            background: {COLORS["primary"]};
            border-radius: 4px;
        }}
        QPushButton[filterchip="true"] {{
            background: {COLORS["surface-container"]};
            color: {COLORS["on-surface-variant"]};
            border: 1px solid {COLORS["surface-container"]};
            border-radius: {RADIUS["sm"]}px;
            padding: {SPACE["xs"]}px {SPACE["sm"]}px;
        }}
        QPushButton[filterchip="true"][active="true"] {{
            background: {COLORS["surface-container-high"]};
            color: {COLORS["primary"]};
            border: 1px solid {COLORS["surface-container-high"]};
        }}
    """
