"""Overview presentation helpers with no data fetching of their own.

Callers pass repository snapshots in and keep owning signal connections."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout,
                               QWidget)

from core.peer_repository import OverviewSummary, PeerRecord, TrustState
from core.discovery import Hello
from gui.components import primary_action
from gui.models import ActivityListModel
from gui.theme.tokens import SPACE
from gui.widgets.activity_log import ActivityLogWidget
from gui.widgets.mono_label import MonoLabel
from gui.widgets.peer_row import peer_state
from gui.widgets.radar_map import RadarMapWidget
from gui.widgets.segmented_bar import SegmentedBar
from gui.widgets.sparkline import SparklineWidget
from gui.widgets.status_pill import StatusPill


def metric_card(title: str, initial: str) -> tuple[QFrame, MonoLabel]:
    """Build one telemetry card reusing the shared card stylesheet."""
    frame = QFrame()
    frame.setProperty("card", True)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(SPACE["lg"], SPACE["lg"], SPACE["lg"], SPACE["lg"])
    label = MonoLabel(title)
    label.setObjectName("MetricLabel")
    value = MonoLabel(initial)
    value.setObjectName("MetricValue")
    layout.addWidget(label)
    layout.addWidget(value)
    return frame, value


def hero(on_toggle: Callable[[], None]) -> tuple[QFrame, MonoLabel, QPushButton]:
    """Build the Overview hero with a big count and one session action."""
    frame = QFrame()
    frame.setProperty("card", True)
    layout = QHBoxLayout(frame)
    layout.setContentsMargins(SPACE["lg"], SPACE["lg"], SPACE["lg"], SPACE["lg"])
    count = MonoLabel("0")
    count.setObjectName("HeroCount")
    count.setStyleSheet("font-size: 44px; font-weight: 700;")
    text = QVBoxLayout()
    caption = MonoLabel("sessions nearby")
    caption.setObjectName("MetricLabel")
    text.addWidget(count)
    text.addWidget(caption)
    layout.addLayout(text, 1)
    action = primary_action("Start session", on_toggle)
    layout.addWidget(action, 0)
    return frame, count, action


def radar_map(local: Hello, mode: str) -> RadarMapWidget:
    """Build the Overview radar bound later to the existing selection slot."""
    return RadarMapWidget(local, mode)


def activity_log(model: ActivityListModel) -> ActivityLogWidget:
    """Build the inline event log over the shared activity rows."""
    return ActivityLogWidget(model)


def inspector_row(label_text: str) -> tuple[QWidget, MonoLabel]:
    """Build one muted-key plus mono-value inspector row for Overview."""
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(SPACE["sm"])
    key = QLabel(label_text)
    key.setObjectName("SectionLabel")
    value = MonoLabel("—")
    value.setObjectName("TechnicalDetail")
    value.setWordWrap(True)
    layout.addWidget(key)
    layout.addWidget(value, 1)
    return row, value


def state_pill_for(record: PeerRecord | None) -> StatusPill:
    """Build the pill from the one ladder the list rows also read."""
    if record is None:
        return StatusPill("Offline", "offline")
    key = peer_state(record)
    text = {"nearby": "Nearby", "reachable": "Reachable",
            "compatible": "Compatible", "offline": "Offline"}[key]
    return StatusPill(text, key)


def trust_pill(record: PeerRecord | None = None) -> StatusPill:
    """Build a per-peer stored-key pill without claiming active authentication."""
    if record is None or record.trust_state is TrustState.UNVERIFIED:
        return StatusPill("Unverified", "unverified")
    if record.trust_state is TrustState.KEY_CHANGED:
        return StatusPill("Key changed", "key_changed")
    return StatusPill("Paired key", "paired")


def breakdown_segments(summary: OverviewSummary) -> list[tuple[float, str]]:
    """Split observed hosts into responsive, offline, and untested shares."""
    if summary.observed <= 0:
        return [(1.0, "surface-container-highest")]
    rest = summary.observed - summary.responsive - summary.stale
    return [(summary.responsive / summary.observed, "primary"),
            (summary.stale / summary.observed, "outline"),
            (max(0, rest) / summary.observed, "surface-container-highest")]


def sparkline_samples(records: tuple[PeerRecord, ...]) -> list[float]:
    """Collect sorted measured latencies for the distribution chart."""
    return sorted(record.latency_ms for record in records
                  if record.latency_ms is not None)


def refresh_distribution(sparkline: SparklineWidget,
                         bar: SegmentedBar,
                         records: tuple[PeerRecord, ...],
                         summary: OverviewSummary) -> None:
    """Push one snapshot into the sparkline and breakdown bar widgets."""
    sparkline.set_samples(sparkline_samples(records))
    bar.set_segments(breakdown_segments(summary))
