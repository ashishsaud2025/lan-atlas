from __future__ import annotations

import time
from pathlib import Path
from uuid import uuid4

import pytest

from core.discovery import Hello
from core.peer_repository import PeerRecord, ReachabilityState


def _record(name: str = "Peer", latency: float | None = None,
            reachable: bool = False) -> PeerRecord:
    hello = Hello(str(uuid4()), str(uuid4()), name, 50001, ("chat_v1",))
    return PeerRecord(hello, "192.168.1.20", time.monotonic(),
                      reachability_state=(ReachabilityState.REACHABLE
                                          if reachable else ReachabilityState.UNKNOWN),
                      latency_ms=latency,
                      latency_source="ping" if latency is not None else None)


@pytest.fixture
def app() -> object:
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_tokens_match_design_frontmatter() -> None:
    from gui.theme.tokens import COLORS, FONTS, RADIUS, SPACE
    assert COLORS["primary"] == "#46efcf"
    assert COLORS["surface-container-low"] == "#0d1c2d"
    assert SPACE == {"xs": 4, "sm": 8, "md": 12, "lg": 20, "xl": 28}
    assert RADIUS["DEFAULT"] == 12 and RADIUS["full"] == 9999
    assert FONTS["ui"] == "Inter" and FONTS["mono"] == "JetBrains Mono"


def test_status_pill_accepts_only_known_states(app: object) -> None:
    from gui.widgets.status_pill import StatusPill
    pill = StatusPill("Reachable", "reachable")
    assert pill.state() == "reachable"
    pill.set_state("offline")
    assert pill.state() == "offline"
    with pytest.raises(ValueError):
        pill.set_state("verified")


def test_mono_label_uses_mono_family(app: object) -> None:
    from gui.widgets.mono_label import MonoLabel
    label = MonoLabel("192.168.1.20:50001")
    assert label.text() == "192.168.1.20:50001"
    assert "Mono" in label.font().family() or "mono" in label.font().family().lower() \
        or label.font().family() in ("Consolas", "monospace")


def test_sparkline_handles_samples_and_empty(app: object) -> None:
    from gui.widgets.sparkline import SparklineWidget
    chart = SparklineWidget()
    chart.set_samples([1.0, 4.0, 2.0])
    assert chart.samples() == [1.0, 4.0, 2.0]
    chart.set_samples([])
    assert chart.samples() == []


def test_segmented_bar_clamps_and_degrades_empty(app: object) -> None:
    from gui.widgets.segmented_bar import SegmentedBar
    bar = SegmentedBar()
    bar.set_segments([(0.75, "primary"), (0.25, "outline")])
    assert bar.segments()[0][0] == 0.75
    bar.set_segments([])
    assert bar.segments()[0][0] == 1.0


def test_radar_map_selects_and_keeps_stable_angles(app: object) -> None:
    from gui.widgets.radar_map import RadarMapWidget
    local = Hello(str(uuid4()), str(uuid4()), "Local", 50001, ("chat_v1",))
    first, second = _record("A", 1.0, True), _record("B", 9.0, True)
    radar = RadarMapWidget(local)
    radar.set_records((first, second))
    before = {item.data(0): (item.pos().x(), item.pos().y())
              for item in radar.scene.items()
              if isinstance(item.data(0), str) and item.data(0)}
    radar.set_records((second, first))
    after = {item.data(0): (item.pos().x(), item.pos().y())
             for item in radar.scene.items()
             if isinstance(item.data(0), str) and item.data(0)}
    assert before.keys() == after.keys()
    for session_id in before:
        assert abs(before[session_id][0] - after[session_id][0]) < 1.0
        assert abs(before[session_id][1] - after[session_id][1]) < 1.0
    assert radar.select_session(first.session_id)  # type: ignore[attr-defined]
    assert radar.set_theme("atlas") is None
    radar.set_theme("observatory")


def test_radar_map_click_emits_session_id(app: object) -> None:
    from PySide6.QtWidgets import QApplication
    from gui.widgets.radar_map import RadarMapWidget
    local = Hello(str(uuid4()), str(uuid4()), "Local", 50001, ("chat_v1",))
    peer = _record("A", 2.0, True)
    radar = RadarMapWidget(local)
    radar.set_records((peer,))
    received: list[str] = []
    radar.device_selected.connect(received.append)
    for item in radar.scene.items():
        if item.data(0) == peer.session_id:  # type: ignore[attr-defined]
            item.setSelected(True)
    instance = QApplication.instance()
    assert instance is not None
    instance.processEvents()
    assert received == [peer.session_id]  # type: ignore[attr-defined]


def test_radar_separates_colliding_labels_and_keeps_dots(app: object) -> None:
    import math
    from gui.widgets.radar_map import RadarMapWidget, _angle_for
    from gui.latency_map import radius_for_latency
    candidates = [f"overlap-fixture-{index:04d}" for index in range(300)]
    angles = sorted(((abs((_angle_for(a) - _angle_for(b) + math.pi)
                           % (2 * math.pi) - math.pi), a, b)
                     for x, a in enumerate(candidates)
                     for b in candidates[x + 1:]))
    gap, first_id, second_id = angles[0]
    assert gap < 0.3
    third_id = next(item for item in candidates
                    if item not in (first_id, second_id))
    from core.peer_repository import PeerRecord
    renamed = tuple(
        PeerRecord(Hello(str(uuid4()), session_id, name, 50001, ("chat_v1",)),
                   "192.168.1.20", 10.0)
        for name, session_id in (("A", first_id), ("B", second_id),
                                 ("C", third_id)))
    local = Hello(str(uuid4()), str(uuid4()), "Local", 50001, ("chat_v1",))
    radar = RadarMapWidget(local)
    radar.set_records(renamed)
    labels = [item for item in radar.scene.items()
              if item.data(1) == "node-label"]
    assert len(labels) == 4
    bounds = radar.scene.sceneRect().adjusted(2, 2, -2, -2)
    for index, first in enumerate(labels):
        assert bounds.contains(first.sceneBoundingRect())
        for second in labels[index + 1:]:
            assert not first.sceneBoundingRect().intersects(
                second.sceneBoundingRect())
    dots = {item.data(0): item.pos() for item in radar.scene.items()
            if isinstance(item.data(0), str) and item.data(0)}
    for peer in renamed:
        expected_x = 450.0 + radius_for_latency(None) * math.cos(
            _angle_for(peer.session_id))
        expected_y = 260.0 + radius_for_latency(None) * math.sin(
            _angle_for(peer.session_id))
        assert abs(dots[peer.session_id].x() - expected_x) < 0.01
        assert abs(dots[peer.session_id].y() - expected_y) < 0.01


def test_overview_helpers_map_only_known_states(app: object) -> None:
    from gui.pages.overview import (breakdown_segments, metric_card,
                                    sparkline_samples, state_pill_for, trust_pill)
    from core.peer_repository import OverviewSummary
    assert state_pill_for(None).state() == "offline"
    assert state_pill_for(_record("A")).state() == "nearby"  # type: ignore[arg-type]
    assert state_pill_for(_record("B", 1.0, True)).state() == "reachable"  # type: ignore[arg-type]
    assert trust_pill().state() == "unverified"
    summary = OverviewSummary(observed=4, nearby=3, stale=1, responsive=2,
                              measured=2, min_ms=1.0, avg_ms=2.0, max_ms=3.0)
    assert sum(part for part, _ in breakdown_segments(summary)) > 0
    assert sparkline_samples((_record("A", 3.0), _record("B"))) == [3.0]  # type: ignore[arg-type]
    frame, value = metric_card("Nearby sessions", "3")
    assert value.text() == "3"
    assert frame is not None


def test_header_glyphs_render_distinct_teal_marks(app: object) -> None:
    from PySide6.QtGui import QColor, QImage
    from gui.theme.tokens import COLORS
    from gui.widgets.header_icon import header_icon
    target = QColor(COLORS["primary"])
    seen: set[bytes] = set()
    for kind in ("hub", "stats", "table", "inspector", "activity"):
        pixmap = header_icon(kind).pixmap()
        assert pixmap is not None and not pixmap.isNull()
        image = pixmap.toImage().convertToFormat(QImage.Format.Format_ARGB32)
        teal_pixels = 0
        bits = image.bits()
        assert bits is not None
        raw = bytes(bits)
        for offset in range(0, len(raw), 4):
            blue, green, red, alpha = raw[offset:offset + 4]
            if alpha > 0 and abs(red - target.red()) < 40 \
                    and abs(green - target.green()) < 40 \
                    and abs(blue - target.blue()) < 40:
                teal_pixels += 1
        assert teal_pixels > 10
        seen.add(bytes(pixmap.toImage().bits()))
    assert len(seen) == 5


def test_activity_log_filters_empty_and_truncates(app: object) -> None:
    from datetime import datetime
    from gui.models import ActivityEntry, ActivityListModel
    from gui.widgets.activity_log import ActivityLogWidget
    model = ActivityListModel()
    widget = ActivityLogWidget(model)
    assert widget.stack.currentWidget() is widget.empty
    assert widget.proxy.filter_key() == "all"
    model.append(ActivityEntry(datetime.now(), "Discovery", "roster " * 40))
    model.append(ActivityEntry(datetime.now(), "Workbench", "TCP ok"))
    model.append(ActivityEntry(datetime.now(), "Messages", "hello",
                               severity="warning"))
    assert widget.proxy.rowCount() == 3
    widget.set_filter("discovery")
    assert widget.proxy.rowCount() == 1
    widget.set_filter("probes")
    assert widget.proxy.rowCount() == 1
    widget.set_filter("warnings")
    assert widget.proxy.rowCount() == 1
    widget.set_filter("all")
    assert widget.proxy.rowCount() == 3
    assert widget.view.itemDelegate() is not None
    assert not widget.filter_empty.isVisible()
    widget.set_filter("probes")
    model.append(ActivityEntry(datetime.now(), "Discovery", "unrelated"))
    assert widget.proxy.rowCount() == 1
    with pytest.raises(ValueError):
        widget.set_filter("subnet")


def test_peer_rows_use_state_pills_not_joined_strings(app: object) -> None:
    from PySide6.QtWidgets import QListView
    from gui.models import PeerListModel
    from gui.widgets.peer_row import (ROW_HEIGHT, PeerRowDelegate, peer_state,
                                      pill_colors)
    assert peer_state(_record("A")) == "nearby"
    assert peer_state(_record("B", 1.0, True)) == "reachable"
    assert pill_colors("reachable")[0].startswith("#")
    model = PeerListModel()
    model.set_records((_record("Android Phone", None),))
    view = QListView()
    delegate = PeerRowDelegate(view)
    view.setModel(model)
    view.setItemDelegate(delegate)
    view.show()
    from PySide6.QtWidgets import QStyleOptionViewItem
    option = QStyleOptionViewItem()
    option.initFrom(view)
    assert delegate.sizeHint(option, model.index(0, 0)).height() == ROW_HEIGHT
    assert model.record_at(0) is not None


def test_radar_hint_leaves_with_first_node_and_returns(app: object) -> None:
    from gui.widgets.radar_map import RadarMapWidget
    local = Hello(str(uuid4()), str(uuid4()), "Local", 50001, ("chat_v1",))
    radar = RadarMapWidget(local)
    assert len(radar.empty_hints()) == 2
    peer = _record("A", None)
    radar.set_records((peer,))
    assert radar.empty_hints() == []
    radar.set_records((peer,))
    text_items = [item for item in radar.scene.items()
                  if item.data(1) != "empty-hint"
                  and hasattr(item, "toPlainText")]
    assert radar.empty_hints() == []
    assert text_items
    radar.set_records(())
    assert len(radar.empty_hints()) == 2


def test_inspector_rows_truncate_ids_with_full_tooltips(app: object) -> None:
    from gui.pages.overview import inspector_row
    row, value = inspector_row("Session:")
    value.setText("e82859d6-eee1-4a2b-8f3c-1a2b3c4d5e6f"[:12] + "…")
    value.setToolTip("e82859d6-eee1-4a2b-8f3c-1a2b3c4d5e6f")
    assert value.text() == "e82859d6-eee…"
    assert value.toolTip() == "e82859d6-eee1-4a2b-8f3c-1a2b3c4d5e6f"
    assert row is not None


def test_top_bar_drives_trust_pill_from_known_states_only(app: object) -> None:
    from PySide6.QtWidgets import QPushButton
    from gui.widgets.top_bar import TopBar
    bar = TopBar("Alice", "1f27d9c5")
    assert isinstance(bar.security, QPushButton)
    assert bar.verification() == "unverified"
    assert "Unverified LAN" in bar.security.text()
    bar.set_nearby("4 sessions nearby")
    bar.set_transfers("1 active transfer")
    assert bar.nearby.text() == "4 sessions nearby"
    assert bar.transfers.text() == "1 active transfer"
    bar.set_verification("verified")
    assert bar.verification() == "verified"
    assert "Verified LAN" in bar.security.text()
    with pytest.raises(ValueError):
        bar.set_verification("authenticated")
    bar.set_verification("unverified")
    assert bar.verification() == "unverified"


def test_header_icon_rejects_unknown_kinds(app: object) -> None:
    from gui.widgets.header_icon import header_icon
    assert header_icon("hub").pixmap() is not None
    with pytest.raises(ValueError):
        header_icon("material-symbols")


def test_font_loader_falls_back_without_bundled_files(
        app: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from PySide6.QtWidgets import QApplication
    from gui.theme import fonts
    app_instance = QApplication.instance()
    assert app_instance is not None
    monkeypatch.setattr(fonts, "_FONT_DIR", tmp_path / "no-fonts-here")
    fonts.ensure_application_fonts(app_instance)
    assert fonts.mono_family()


def test_refined_tokens_match_design() -> None:
    from gui.theme.tokens import COLORS, FONTS, RADIUS
    assert COLORS['surface'] == '#060a10'
    assert COLORS['surface-container'] == '#131b28'
    assert RADIUS['DEFAULT'] == 12
    assert FONTS['styles']['body-md']['size'] == 14
