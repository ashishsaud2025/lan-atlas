"""LAN Atlas desktop shell; all core events are consumed on the Qt thread."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, ip_address
from pathlib import Path
from queue import Empty
import time
from typing import Any

from PySide6.QtCore import QModelIndex, QSettings, Qt, QTimer, QUrl, Slot
from PySide6.QtGui import (QCloseEvent, QDesktopServices, QKeySequence,
                           QResizeEvent, QShortcut, QTextCursor)
from PySide6.QtWidgets import (
    QAbstractButton, QApplication, QCheckBox, QComboBox, QDoubleSpinBox,
    QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QListView, QListWidget, QListWidgetItem, QMainWindow,
    QMessageBox, QProgressBar, QPushButton, QScrollArea, QSpinBox, QSplitter,
    QStackedWidget, QTableView, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)

from core.chat import ChatService
from core.diagnostics import Neighbor, NeighborSnapshot, ProbeResult
from core.discovery import local_ipv4_addresses, local_ipv6_addresses
from core.message_journal import MessageRecord
from core.peer_repository import (
    CompatibilityState, DiscoveryState, PeerRecord, PeerRepositoryEvent,
    ReachabilityState, TrustState,
)
from core.post_signatures import verify_post
from core.forwarding import ForwardingService
from core.portal import PORTAL_PORT, PortalServer
from core.protocol import envelope
from core.roster import Peer
from core.secure_transport import PairingCandidate, SecureTransportError
from core.services import (DirectoryEntry, DirectoryKind, LocalServiceDirectory,
                           browser_url)
from gui.components import NavigationRail, action_button, page_header
from gui.pages.devices import FILTER_TABS, filter_tabs, identity_block, tab_counts
from gui.pages.network import hud_selected_block, metric_value, toolbar_title
from gui.pages.overview import (activity_log, inspector_row, metric_card,
                                radar_map, refresh_distribution,
                                state_pill_for, trust_pill)
from gui.widgets.header_icon import header_icon
from gui.widgets.mono_label import MonoLabel
from gui.widgets.peer_row import (PeerRowDelegate, PeerTableDelegate,
                                  pill_display_text)
from gui.widgets.segmented_bar import SegmentedBar
from gui.widgets.sparkline import SparklineWidget
from gui.widgets.status_pill import StatusPill
from gui.widgets.top_bar import TopBar
from gui.models import (
    ActivityEntry, ActivityListModel, AdminDevice, AdminDeviceListModel,
    DirectoryListModel, MessageEntry, MessageListModel, PeerListModel,
    PeerTableModel, PostListModel, TerminalTransferProxy, TransferListModel,
    capability_label, endpoint_label, format_eta, human_bytes,
    peer_trust_label, transfer_pace,
)
from gui.peer_selection import PeerSelection
from gui.theme import GEOMETRY, SPACING, apply_theme

PAGE_OVERVIEW = 0
PAGE_NETWORK = 1
PAGE_DEVICES = 2
PAGE_WORKBENCH = 3
PAGE_FILES = 4
PAGE_TRANSFERS = 5
PAGE_MESSAGES = 6
PAGE_FEED = 7
PAGE_GAMES = 8
PAGE_ACTIVITY = 9
PAGE_SETTINGS = 10
TERMINAL_TRANSFERS = {"failed", "cancelled", "declined", "saved", "verified"}
INTERNET_ACTIONS = {
    "send": ("chat_v1", "Messages"),
    "file": ("file_v1", "Transfers"),
    "feed": ("posts_v1", "Feed"),
    "directory": ("directory_v1", "Services"),
}


@dataclass(frozen=True)
class _PendingInternet:
    peer_id: str
    action: str
    text: str
    draft_revision: int


def _has_ipv4_endpoint(record: PeerRecord) -> bool:
    """Return whether any observed candidate can use IPv4 application paths."""
    candidates = ([item.ip for item in record.endpoint_candidates]
                  if record.endpoint_candidates else [record.ip])
    for address in candidates:
        try:
            if isinstance(ip_address(address.partition("%")[0]), IPv4Address):
                return True
        except ValueError:
            continue
    return False


class MainWindow(QMainWindow):
    """Present peer-to-peer state without implying central trust or connectivity."""

    def __init__(self, service: ChatService,
                 portal: PortalServer | None = None,
                 directory: LocalServiceDirectory | None = None,
                 forwarder: ForwardingService | None = None) -> None:
        super().__init__()
        self.settings = QSettings("LAN Manager", "LAN Atlas")
        self.theme_mode = str(self.settings.value("appearance/theme", "observatory"))
        app = QApplication.instance()
        if app is not None:
            self.theme_mode = apply_theme(app, self.theme_mode)
        self.service = service
        if portal is not None:
            content = portal.content
            if (content.hello != service.hello
                    or content.peers is not service.peer_repository
                    or content.posts is not service.post_store
                    or content.messages_store is not service.message_journal):
                raise ValueError("portal must share the desktop core repositories")
            if directory is None:
                directory = content.directory_store
            elif content.directory_store is not directory:
                raise ValueError("portal must share the desktop service directory")
        self.directory = directory or service.directory
        if self.directory.owner is not service.hello:
            raise ValueError("directory must belong to the local session")
        self.portal = portal or PortalServer(
            service.hello, service.peer_repository, service.post_store,
            service.message_journal, self.directory)
        self.forwarder = forwarder or ForwardingService()
        self.peer_records: tuple[PeerRecord, ...] = service.peer_repository.snapshot()
        self._peer_revision = 0
        self.peer_selection = PeerSelection()
        self.neighbors: tuple[Neighbor, ...] = ()
        self.transfer_rows: dict[str, dict[str, Any]] = {}
        self.selected_transfer_id: str | None = None
        self._message_revision = -1
        self.active_probe_id: str | None = None
        self.inventory_request_id: str | None = None
        self._next_presence_refresh = 0.0
        self._rv_registered = False
        self._pending_internet: dict[str, _PendingInternet] = {}
        self._draft_revision = 0
        self.peer_model = PeerListModel()
        self.peer_table_model = PeerTableModel()
        self.message_model = MessageListModel()
        self.game_model = DirectoryListModel(DirectoryKind.GAME)
        self.service_model = DirectoryListModel(DirectoryKind.SERVICE)
        self.transfer_model = TransferListModel()
        self.post_model = PostListModel()
        self.activity_model = ActivityListModel()
        self.admin_device_model = AdminDeviceListModel()
        self.page_names = ("Overview", "Network", "Devices", "Workbench", "Files",
                           "Transfers", "Messages", "Feed", "Games", "Activity",
                           "Settings")
        self.navigation_groups = (
            ("Control", (("Overview", PAGE_OVERVIEW), ("Network", PAGE_NETWORK),
                         ("Devices", PAGE_DEVICES), ("Workbench", PAGE_WORKBENCH))),
            ("Share", (("Files", PAGE_FILES), ("Transfers", PAGE_TRANSFERS))),
            ("Community", (("Messages", PAGE_MESSAGES), ("Feed", PAGE_FEED),
                           ("Games", PAGE_GAMES))),
            ("System", (("Activity", PAGE_ACTIVITY), ("Settings", PAGE_SETTINGS))),
        )
        self.setWindowTitle(f"LAN Atlas · {service.hello.name}")
        self.setMinimumSize(GEOMETRY["minimum_width"], GEOMETRY["minimum_height"])
        screen = QApplication.primaryScreen()
        available = screen.availableGeometry() if screen is not None else None
        width = min(1440, available.width()) if available is not None else 1440
        height = min(900, available.height()) if available is not None else 900
        self.resize(width, height)
        self._build_shell()
        self.input.textChanged.connect(self._mark_draft_changed)
        self.peer_selection.changed.connect(self._sync_peer_selection)
        self._apply_responsive_layout(self.width())
        self._install_shortcuts()
        self._refresh_messages()
        self._refresh_directory()
        self.refresh_feed()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.drain)
        self.timer.start(50)

    def _build_shell(self) -> None:
        root = QWidget(self)
        root.setObjectName("AppRoot")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_status_strip())
        middle = QWidget()
        middle_layout = QHBoxLayout(middle)
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.setSpacing(0)
        self.navigation = NavigationRail(self.navigation_groups)
        self.navigation.selected.connect(self.select_page)
        middle_layout.addWidget(self.navigation)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        workspace = QWidget()
        workspace_layout = QVBoxLayout(workspace)
        workspace_layout.setContentsMargins(SPACING["md"], SPACING["md"],
                                            SPACING["md"], SPACING["md"])
        workspace_layout.setSpacing(SPACING["md"])
        self.stack = QStackedWidget()
        self.responsive_pages: list[tuple[QWidget, int]] = []
        self._add_page(self._build_overview_page(), 820)
        self._add_page(self._build_network_page(), 560)
        self._add_page(self._build_peers_page(), 680)
        self._add_page(self._build_admin_page(), 800)
        self._add_page(self._build_files_page(), 420)
        self._add_page(self._build_transfers_page(), 560)
        self._add_page(self._build_messages_page(), 560)
        self._add_page(self._build_feed_page(), 560)
        self._add_page(self._build_directory_page(), 520)
        self._add_page(self._build_activity_page(), 560)
        self._add_page(self._build_settings_page(), 640)
        workspace_layout.addWidget(self.stack, 1)
        self.transfer_drawer = QFrame()
        self.transfer_drawer.setProperty("card", True)
        drawer_layout = QHBoxLayout(self.transfer_drawer)
        self.transfer_drawer_label = QLabel("Transfer activity")
        drawer_layout.addWidget(self.transfer_drawer_label)
        drawer_layout.addStretch(1)
        drawer_layout.addWidget(action_button(
            "Open transfers", lambda: self.navigation.select(PAGE_TRANSFERS)))
        self.transfer_drawer.setVisible(False)
        workspace_layout.addWidget(self.transfer_drawer)
        right_layout.addWidget(workspace, 1)
        right_layout.addWidget(self._build_footer())
        middle_layout.addWidget(right, 1)
        outer.addWidget(middle, 1)
        self.setCentralWidget(root)

    def _add_page(self, page: QWidget, compact_height: int) -> None:
        scroll = QScrollArea()
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setWidget(page)
        self.responsive_pages.append((page, compact_height))
        self.stack.addWidget(scroll)

    def _build_status_strip(self) -> TopBar:
        bar = TopBar(self.service.hello.name, self.service.hello.peer_id[:8])
        self.identity_status = bar.identity
        self.nearby_status = bar.nearby
        self.network_status = bar.network
        self.transfer_status = bar.transfers
        self.command_button = bar.command
        self.security_status = bar.security
        self.security_status.clicked.connect(lambda: self.navigation.select(PAGE_SETTINGS))
        return bar

    def _build_footer(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("ApplicationFooter")
        frame.setFixedHeight(29)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(10, 3, 10, 3)
        self.footer_left = QLabel(
            f"● Discovery UDP 50000  ·  Application TCP {self.service.hello.tcp_port}")
        self.footer_left.setProperty("technical", True)
        self.footer_right = QLabel("0 observed sessions  ·  Unverified LAN")
        self.footer_right.setProperty("technical", True)
        layout.addWidget(self.footer_left)
        layout.addStretch(1)
        layout.addWidget(self.footer_right)
        return frame

    def _page(self, title: str, subtitle: str,
              dense: bool = False) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(SPACING["md"])
        if dense:
            toolbar = QFrame()
            toolbar.setObjectName("OperationalToolbar")
            toolbar_layout = QHBoxLayout(toolbar)
            toolbar_layout.setContentsMargins(14, 9, 14, 9)
            heading = QLabel(title)
            heading.setObjectName("PanelTitle")
            detail = QLabel(subtitle)
            detail.setObjectName("PageSubtitle")
            detail.setWordWrap(True)
            toolbar_layout.addWidget(heading)
            toolbar_layout.addSpacing(SPACING["md"])
            toolbar_layout.addWidget(detail, 1)
            layout.addWidget(toolbar)
        else:
            layout.addWidget(page_header(title, subtitle))
        return page, layout

    def _build_overview_page(self) -> QWidget:
        page, layout = self._page(
            "Local network overview",
            "Live observations from this LAN Manager session.", True)
        self.overview_metrics = QGridLayout()
        nearby_card, self.nearby_value = metric_card("Nearby sessions", "Searching...")
        capability_card, self.capability_value = metric_card(
            "Advertised features", "Waiting")
        transfer_card, self.transfer_value = metric_card("Active transfers", "None")
        identity_card, self.identity_value = metric_card(
            "This device", self.service.hello.name)
        self.overview_metric_cards = (
            nearby_card, capability_card, transfer_card, identity_card)
        self.identity_detail = MonoLabel(f"ID {self.service.hello.peer_id[:8]}")
        self.identity_detail.setObjectName("TechnicalDetail")
        identity_card.layout().addWidget(self.identity_detail)
        for index, metric_frame in enumerate(self.overview_metric_cards):
            self.overview_metrics.addWidget(metric_frame, index // 2, index % 2)

        self.overview_splitter = QSplitter(Qt.Orientation.Horizontal)
        network = QFrame()
        network.setProperty("panel", True)
        network_layout = QVBoxLayout(network)
        network_heading = QLabel("LATENCY MAP (OBSERVED RTT)")
        network_heading.setObjectName("SectionLabel")
        network_title = QHBoxLayout()
        network_title.addWidget(header_icon("hub"))
        network_title.addWidget(network_heading, 1)
        network_layout.addLayout(network_title)
        self.overview_topology = radar_map(self.service.hello, self.theme_mode)
        self.overview_topology.device_selected.connect(self._overview_map_selected)
        network_layout.addWidget(self.overview_topology, 1)
        self.overview_splitter.addWidget(network)

        metrics_panel = QFrame()
        metrics_panel.setProperty("panel", True)
        metrics_layout = QVBoxLayout(metrics_panel)
        metrics_heading = QLabel("LATENCY & METRICS")
        metrics_heading.setObjectName("PanelTitle")
        metrics_title = QHBoxLayout()
        metrics_title.addWidget(header_icon("stats"))
        metrics_title.addWidget(metrics_heading, 1)
        metrics_layout.addLayout(metrics_title)
        metrics_layout.addLayout(self.overview_metrics)
        self.overview_breakdown = SegmentedBar()
        metrics_layout.addWidget(self.overview_breakdown)
        self.overview_sparkline = SparklineWidget()
        metrics_layout.addWidget(self.overview_sparkline)
        self.overview_summary = MonoLabel("Searching your LAN for observed hosts...")
        self.overview_summary.setObjectName("TechnicalDetail")
        self.overview_summary.setWordWrap(True)
        metrics_layout.addWidget(self.overview_summary)
        self.overview_rtt = MonoLabel("Measured latency: none yet")
        self.overview_rtt.setObjectName("TechnicalDetail")
        self.overview_rtt.setWordWrap(True)
        metrics_layout.addWidget(self.overview_rtt)
        metrics_note = QLabel(
            "Counts come from the canonical repository. "
            "Radial distance uses measured latency only "
            "(ping RTT, TCP handshake, or ECHO round-trip); "
            "unmeasured peers use a grey ring. "
            "No physical topology is inferred.")
        metrics_note.setObjectName("PageSubtitle")
        metrics_note.setWordWrap(True)
        metrics_layout.addWidget(metrics_note)
        metrics_layout.addStretch(1)
        self.overview_splitter.addWidget(metrics_panel)
        self.overview_splitter.setSizes([820, 360])
        layout.addWidget(self.overview_splitter, 3)

        self.overview_detail_splitter = QSplitter(Qt.Orientation.Horizontal)
        nearby = QFrame()
        nearby.setProperty("panel", True)
        nearby_layout = QVBoxLayout(nearby)
        nearby_heading = QLabel("NEARBY")
        nearby_heading.setObjectName("SectionLabel")
        nearby_title = QHBoxLayout()
        nearby_title.addWidget(header_icon("table"))
        nearby_title.addWidget(nearby_heading, 1)
        nearby_layout.addLayout(nearby_title)
        self.overview_nearby_stack = QStackedWidget()
        self.overview_nearby_empty = QLabel(
            "Searching your LAN...\nNearby sessions will appear after a HELLO announcement.")
        self.overview_nearby_empty.setObjectName("PageSubtitle")
        self.overview_nearby_empty.setWordWrap(True)
        self.overview_nearby_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.overview_peer_list = QListView()
        self.overview_peer_list.setModel(self.peer_model)
        self.overview_peer_list.setItemDelegate(PeerRowDelegate(self))
        self.overview_peer_list.setAccessibleName("Overview nearby sessions")
        self.overview_peer_list.setWordWrap(True)
        self.overview_peer_list.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.overview_peer_list.clicked.connect(self._overview_peer_previewed)
        self.overview_peer_list.activated.connect(self._overview_peer_selected)
        self.overview_nearby_stack.addWidget(self.overview_nearby_empty)
        self.overview_nearby_stack.addWidget(self.overview_peer_list)
        nearby_layout.addWidget(self.overview_nearby_stack, 1)
        self.overview_detail_splitter.addWidget(nearby)

        overview_inspector = QFrame()
        overview_inspector.setProperty("panel", True)
        inspector_layout = QVBoxLayout(overview_inspector)
        inspector_heading = QLabel("SELECTED SESSION")
        inspector_heading.setObjectName("SectionLabel")
        inspector_title = QHBoxLayout()
        inspector_title.addWidget(header_icon("inspector"))
        inspector_title.addWidget(inspector_heading, 1)
        self.overview_peer_name = QLabel("No session selected")
        self.overview_peer_name.setObjectName("PanelTitle")
        endpoint_row, self.overview_peer_endpoint = inspector_row("IP Endpoint:")
        installation_row, self.overview_peer_installation = inspector_row(
            "Installation:")
        session_row, self.overview_peer_session = inspector_row("Session:")
        state_row, self.overview_peer_state = inspector_row("State:")
        self.overview_peer_caps = QLabel("Presence only")
        self.overview_peer_caps.setProperty("chip", True)
        self.overview_peer_rtt = MonoLabel("Measured latency: none yet")
        self.overview_peer_rtt.setObjectName("TechnicalDetail")
        self.overview_peer_rtt.setWordWrap(True)
        self.overview_state_pill = state_pill_for(None)
        self.overview_state_pill.setText("No selection")
        self.overview_trust_pill = trust_pill()
        self.overview_trust_pill.setText("◇  Unverified")
        self.overview_trust_pill.setToolTip(
            "No authenticated device identity has been established.")
        pill_row = QHBoxLayout()
        pill_row.addWidget(self.overview_state_pill)
        pill_row.addWidget(self.overview_trust_pill)
        pill_row.addStretch(1)
        inspector_layout.addLayout(inspector_title)
        inspector_layout.addWidget(self.overview_peer_name)
        inspector_layout.addWidget(endpoint_row)
        inspector_layout.addWidget(installation_row)
        inspector_layout.addWidget(session_row)
        inspector_layout.addWidget(state_row)
        inspector_layout.addWidget(self.overview_peer_caps)
        inspector_layout.addWidget(self.overview_peer_rtt)
        inspector_layout.addLayout(pill_row)
        inspector_layout.addStretch(1)
        inspector_layout.addWidget(action_button(
            "Open full device inspector", lambda: self.navigation.select(PAGE_DEVICES), True))
        self.overview_detail_splitter.addWidget(overview_inspector)
        self.overview_detail_splitter.setSizes([700, 480])
        self.overview_detail_splitter.setMaximumHeight(300)
        layout.addWidget(self.overview_detail_splitter, 2)

        activity = QFrame()
        activity.setProperty("panel", True)
        activity_layout = QVBoxLayout(activity)
        self.overview_activity_log = activity_log(self.activity_model)
        self.overview_activity_stack = self.overview_activity_log.stack
        self.overview_activity_empty = self.overview_activity_log.empty
        self.overview_activity_view = self.overview_activity_log.view
        activity_layout.addWidget(self.overview_activity_log)
        layout.addWidget(activity)

        self.status_help_button = QPushButton("How status works")
        self.status_help_button.setCheckable(True)
        self.status_help_button.setFlat(True)
        self.status_help_button.setMaximumWidth(150)
        self.status_help = QLabel(
            "Nearby means a UDP HELLO was observed recently. Reachable will mean a TCP "
            "probe succeeded. Compatible will mean a versioned protocol exchange worked. "
            "Paired key means a certificate was explicitly pinned; authenticated applies "
            "only to an individual connection that proves that key over TLS.")
        self.status_help.setObjectName("PageSubtitle")
        self.status_help.setWordWrap(True)
        self.status_help.setVisible(False)
        self.status_help_button.toggled.connect(self.status_help.setVisible)
        help_row = QHBoxLayout()
        help_row.addWidget(self.status_help_button)
        help_row.addWidget(self.status_help, 1)
        help_row.addStretch(1)
        layout.addLayout(help_row)
        return page

    def _build_network_page(self) -> QWidget:
        page, layout = self._page(
            "Observed network",
            "Discovery observations from this instance, not inferred physical topology.",
            True)
        controls = QFrame()
        controls.setObjectName("OperationalToolbar")
        control_layout = QHBoxLayout(controls)
        self.network_toolbar_evidence = MonoLabel(
            "HELLO edges  ·  Visual positions")
        self.network_toolbar_evidence.setObjectName("TechnicalDetail")
        fit_button = action_button("Fit", self._fit_topology)
        devices_button = action_button(
            "Devices", lambda: self.navigation.select(PAGE_DEVICES), True)
        control_layout.addWidget(toolbar_title())
        control_layout.addSpacing(SPACING["md"])
        control_layout.addWidget(self.network_toolbar_evidence, 1)
        control_layout.addWidget(fit_button)
        control_layout.addWidget(devices_button)
        layout.addWidget(controls)

        self.network_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.topology = radar_map(self.service.hello, self.theme_mode)
        self.topology.device_selected.connect(self._network_peer_selected)
        self.network_splitter.addWidget(self.topology)

        hud = QFrame()
        hud.setProperty("panel", True)
        hud_layout = QVBoxLayout(hud)
        hud_title = QLabel("OBSERVATION HUD")
        hud_title.setObjectName("PanelTitle")
        hud_layout.addWidget(hud_title)
        summary = QFrame()
        summary.setProperty("subpanel", True)
        summary_layout = QGridLayout(summary)
        summary_layout.addWidget(QLabel("Observed sessions"), 0, 0)
        summary_layout.addWidget(QLabel("Advertised features"), 0, 1)
        self.network_observed_value = metric_value("0")
        self.network_capability_value = metric_value("0")
        summary_layout.addWidget(self.network_observed_value, 1, 0)
        summary_layout.addWidget(self.network_capability_value, 1, 1)
        hud_layout.addWidget(summary)
        selected_title = QLabel("SELECTED NODE")
        selected_title.setObjectName("SectionLabel")
        self.network_selected_name = QLabel("No session selected")
        self.network_selected_name.setObjectName("PanelTitle")
        hud_rows, self.network_selected_endpoint, self.network_selected_session, \
            self.network_selected_state, self.network_state_pill = hud_selected_block()
        self.network_selected_caps = QLabel("Presence only")
        self.network_selected_caps.setProperty("chip", True)
        hud_layout.addWidget(selected_title)
        hud_layout.addWidget(self.network_selected_name)
        for hud_row in hud_rows:
            hud_layout.addWidget(hud_row)
        hud_pill_row = QHBoxLayout()
        hud_pill_row.addWidget(self.network_state_pill)
        hud_pill_row.addStretch(1)
        hud_layout.addLayout(hud_pill_row)
        hud_layout.addWidget(self.network_selected_caps)
        legend_title = QLabel("EVIDENCE LEGEND")
        legend_title.setObjectName("SectionLabel")
        legend = QLabel(
            "● Nearby\n  Recent UDP HELLO observed\n\n"
            "○ Reachable\n  Requires an explicit successful check\n\n"
            "◇ Trust\n  Per-device certificate pairing; discovery stays self-reported")
        legend.setObjectName("TechnicalDetail")
        legend.setWordWrap(True)
        hud_layout.addWidget(legend_title)
        hud_layout.addWidget(legend)
        hud_layout.addStretch(1)
        hud_layout.addWidget(action_button(
            "Inspect in Devices", self._open_network_peer, True))
        self.network_splitter.addWidget(hud)
        self.network_splitter.setSizes([900, 310])
        layout.addWidget(self.network_splitter, 1)
        return page

    def _build_peers_page(self) -> QWidget:
        page, layout = self._page(
            "Devices", "Active sessions discovered through bounded UDP announcements.",
            True)
        toolbar = QFrame()
        toolbar.setObjectName("OperationalToolbar")
        toolbar_layout = QHBoxLayout(toolbar)
        self.device_search = QLineEdit()
        self.device_search.setPlaceholderText("Filter by name, endpoint, session, capability...")
        self.device_search.setAccessibleName("Filter observed sessions")
        self.device_search.textChanged.connect(self._filter_devices)
        self.device_scope = QLabel("No subnet scan · no inferred offline devices")
        self.device_scope.setObjectName("TechnicalDetail")
        toolbar_layout.addWidget(self.device_search, 1)
        toolbar_layout.addWidget(self.device_scope)
        layout.addWidget(toolbar)
        tab_row, self.device_tabs, self.device_tab_group = filter_tabs()
        self._device_tab_key = "all"
        self.device_tab_group.buttonToggled.connect(self._device_tab_toggled)
        self._refresh_device_tab_counts(())
        layout.addWidget(tab_row)

        self.peer_splitter = QSplitter(Qt.Orientation.Horizontal)
        table_panel = QFrame()
        table_panel.setProperty("panel", True)
        table_layout = QVBoxLayout(table_panel)
        table_heading = QLabel("OBSERVED SESSIONS")
        table_heading.setObjectName("PanelTitle")
        table_layout.addWidget(table_heading)
        self.peer_list = QTableView()
        self.peer_list.setModel(self.peer_table_model)
        self.peer_list.setItemDelegateForColumn(
            0, PeerTableDelegate(self.peer_list))
        self.peer_list.setAccessibleName("Nearby peer sessions")
        self.peer_list.setAlternatingRowColors(True)
        self.peer_list.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.peer_list.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.peer_list.setShowGrid(False)
        self.peer_list.verticalHeader().setVisible(False)
        self.peer_list.verticalHeader().setDefaultSectionSize(62)
        header = self.peer_list.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.peer_list.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.peer_list.selectionModel().currentChanged.connect(self._peer_selected)
        table_layout.addWidget(self.peer_list, 1)
        table_footer = QLabel(
            "● HELLO active  ·  Sessions expire on timeout")
        table_footer.setObjectName("TechnicalDetail")
        table_layout.addWidget(table_footer)
        self.peer_splitter.addWidget(table_panel)

        inspector = QFrame()
        inspector.setProperty("panel", True)
        details = QVBoxLayout(inspector)
        self.peer_name = QLabel("Select a nearby session")
        self.peer_name.setObjectName("PanelTitle")
        self.peer_presence = QLabel("No peer selected")
        self.peer_presence.setObjectName("PageSubtitle")
        self.peer_state_pill = state_pill_for(None)
        self.peer_state_pill.setText("No selection")
        self.peer_endpoint = QLabel("Endpoint: —")
        self.peer_endpoint.setProperty("technical", True)
        self.peer_endpoint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        identity_rows, self.peer_installation, self.peer_session = identity_block()
        self.peer_host = QLabel("Hostname: Not advertised")
        self.peer_platform = QLabel("Platform / architecture: Not advertised")
        self.peer_mac = QLabel("MAC address: Not observed")
        self.peer_latency = QLabel("Latency: Not measured")
        for item in (self.peer_host, self.peer_platform, self.peer_mac,
                     self.peer_latency):
            item.setProperty("technical", True)
            item.setWordWrap(True)
        self.peer_capabilities = QLabel("Presence only")
        self.peer_capabilities.setProperty("chip", True)
        self.peer_services = QLabel("Advertised / detected services: None observed")
        self.peer_services.setProperty("technical", True)
        self.peer_services.setWordWrap(True)
        self.peer_warning = QLabel(
            "Cryptographic Trust: Unverified\n"
            "No authenticated device identity has been established.")
        self.peer_warning.setProperty("warning", True)
        self.peer_warning.setWordWrap(True)
        self.peer_warning.setToolTip(
            "Names and identifiers are self-reported. Nearby does not mean trusted or reachable.")
        self.peer_message_button = action_button("Message", self._message_selected_peer, True)
        self.peer_file_button = action_button("Send file", self._file_selected_peer)
        self.peer_sync_button = action_button("Sync posts", self._sync_selected_peer)
        self.peer_ping_button = action_button(
            "Ping", lambda: self._probe_selected_peer("ping"))
        self.peer_tcp_button = action_button(
            "TCP test", lambda: self._probe_selected_peer("tcp"))
        self.peer_copy_button = action_button("Copy address", self._copy_peer_address)
        self.peer_pair_button = action_button(
            "Pair device", self._pair_selected_peer, True)
        self.peer_forget_button = action_button(
            "Forget pairing", self._forget_selected_peer)
        self.peer_probe_button = QPushButton("Open in Workbench")
        self.peer_probe_button.setToolTip(
            "Use this observed endpoint for an explicit ping or TCP check.")
        self.peer_probe_button.clicked.connect(self._open_peer_admin)
        for button in (self.peer_message_button, self.peer_file_button,
                       self.peer_sync_button, self.peer_ping_button,
                       self.peer_tcp_button, self.peer_copy_button,
                       self.peer_probe_button, self.peer_pair_button,
                       self.peer_forget_button):
            button.setEnabled(False)
        details.addWidget(self.peer_name)
        details.addWidget(self.peer_presence)
        peer_pill_row = QHBoxLayout()
        peer_pill_row.addWidget(self.peer_state_pill)
        peer_pill_row.addStretch(1)
        details.addLayout(peer_pill_row)
        details.addSpacing(8)
        identity_panel = QFrame()
        identity_panel.setProperty("subpanel", True)
        self.device_identity_panel = identity_panel
        identity_layout = QVBoxLayout(identity_panel)
        identity_title = QLabel("NETWORK & REPORTED IDENTITY")
        identity_title.setObjectName("SectionLabel")
        identity_layout.addWidget(identity_title)
        identity_layout.addWidget(self.peer_endpoint)
        for identity_row in identity_rows:
            identity_layout.addWidget(identity_row)
        identity_layout.addWidget(self.peer_host)
        identity_layout.addWidget(self.peer_platform)
        identity_layout.addWidget(self.peer_mac)
        identity_layout.addWidget(self.peer_latency)
        details.addWidget(identity_panel)
        details.addWidget(self.peer_capabilities)
        details.addWidget(self.peer_services)
        evidence_panel = QFrame()
        evidence_panel.setProperty("subpanel", True)
        self.device_evidence_panel = evidence_panel
        evidence_layout = QVBoxLayout(evidence_panel)
        evidence_title = QLabel("CONNECTION EVIDENCE")
        evidence_title.setObjectName("SectionLabel")
        self.peer_nearby_evidence = QLabel("● Nearby        Recent HELLO observed")
        self.peer_reachable_evidence = QLabel("○ Reachable     Not tested")
        self.peer_compatible_evidence = QLabel("○ Compatible    Not tested")
        self.peer_trust_evidence = QLabel("◇ Paired key    Not established")
        for item in (self.peer_nearby_evidence, self.peer_reachable_evidence,
                     self.peer_compatible_evidence, self.peer_trust_evidence):
            item.setObjectName("TechnicalDetail")
            evidence_layout.addWidget(item)
        details.addWidget(evidence_panel)
        details.addWidget(self.peer_warning)
        details.addStretch(1)
        detail_actions = QGridLayout()
        detail_actions.addWidget(self.peer_message_button, 0, 0)
        detail_actions.addWidget(self.peer_file_button, 0, 1)
        detail_actions.addWidget(self.peer_sync_button, 1, 0)
        detail_actions.addWidget(self.peer_probe_button, 1, 1)
        detail_actions.addWidget(self.peer_ping_button, 2, 0)
        detail_actions.addWidget(self.peer_tcp_button, 2, 1)
        detail_actions.addWidget(self.peer_copy_button, 3, 0, 1, 2)
        detail_actions.addWidget(self.peer_pair_button, 4, 0)
        detail_actions.addWidget(self.peer_forget_button, 4, 1)
        details.addLayout(detail_actions)
        self.peer_splitter.addWidget(inspector)
        self.peer_splitter.setSizes([720, 500])
        layout.addWidget(self.peer_splitter, 1)
        self._show_peer(None)
        return page

    def _build_messages_page(self) -> QWidget:
        page, layout = self._page(
            "Messages", "The nearby room is TCP fan-out; acknowledgements mean application acceptance.")
        controls = QFrame()
        controls.setProperty("card", True)
        control_layout = QVBoxLayout(controls)
        self.recipient = QComboBox()
        self.recipient.setAccessibleName("Message recipient")
        self.recipient.addItem("Nearby room · all discovered chat sessions", None)
        self.room_explainer = QLabel(
            "Nearby room sends one TCP message to each currently discovered chat-capable session.")
        self.room_explainer.setObjectName("PageSubtitle")
        self.room_explainer.setWordWrap(True)
        control_layout.addWidget(self.recipient)
        control_layout.addWidget(self.room_explainer)
        layout.addWidget(controls)
        self.message_view = QListView()
        self.message_view.setModel(self.message_model)
        self.message_view.setAccessibleName("Message history")
        self.message_view.setWordWrap(True)
        self.message_view.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(self.message_view, 1)
        compose = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setMaxLength(4096)
        self.input.setPlaceholderText("Write a plain-text message")
        self.input.setAccessibleName("Message text")
        self.send_button = action_button("Send", self.send, True)
        self.input.returnPressed.connect(self.send)
        compose.addWidget(self.input, 1)
        compose.addWidget(self.send_button)
        layout.addLayout(compose)
        return page

    def _build_files_page(self) -> QWidget:
        page, layout = self._page(
            "Files", "Finished transfers kept on this device. Browsing peers' "
            "files needs a request flow that is not implemented.")
        self.files_proxy = TerminalTransferProxy(TERMINAL_TRANSFERS, self)
        self.files_proxy.setSourceModel(self.transfer_model)
        self.files_view = QListView()
        self.files_view.setModel(self.files_proxy)
        self.files_view.setAccessibleName("Finished transfer history")
        self.files_view.setWordWrap(True)
        self.files_view.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(self.files_view, 1)
        self.files_count = QLabel("No finished transfers yet")
        self.files_count.setObjectName("PageSubtitle")
        layout.addWidget(self.files_count)
        self.files_proxy.rowsInserted.connect(self._refresh_files_count)
        self.files_proxy.rowsRemoved.connect(self._refresh_files_count)
        self.files_proxy.modelReset.connect(self._refresh_files_count)
        return page

    @Slot()
    def _refresh_files_count(self) -> None:
        """Update the finished-transfer count from the live proxy."""
        count = self.files_proxy.rowCount()
        self.files_count.setText(
            "No finished transfers yet" if count == 0 else
            f"{count} finished transfer{'s' if count != 1 else ''} kept locally")

    def _build_transfers_page(self) -> QWidget:
        page, layout = self._page(
            "Transfers", "Byte progress and verification are separate phases.")
        toolbar = QHBoxLayout()
        self.file_button = action_button("Send file to selected message peer",
                                         self.send_file, True)
        toolbar.addWidget(self.file_button)
        toolbar.addStretch(1)
        self.transfer_slots = QLabel("0 of 4 transfer slots in use")
        toolbar.addWidget(self.transfer_slots)
        layout.addLayout(toolbar)
        self.transfer_view = QListView()
        self.transfer_view.setModel(self.transfer_model)
        self.transfer_view.setAccessibleName("Transfer records")
        self.transfer_view.setWordWrap(True)
        self.transfer_view.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.transfer_view.selectionModel().currentChanged.connect(
            self._transfer_selected)
        layout.addWidget(self.transfer_view, 1)
        self.transfer_progress = QProgressBar()
        self.transfer_progress.setRange(0, 100)
        self.transfer_progress.setValue(0)
        self.transfer_progress.setFormat("Select a transfer for phase details")
        layout.addWidget(self.transfer_progress)
        self.transfer_rate = MonoLabel("Rate not measured")
        self.transfer_rate.setObjectName("TechnicalDetail")
        self.transfer_rate.setAccessibleName("Measured transfer rate")
        layout.addWidget(self.transfer_rate)
        actions = QHBoxLayout()
        self.accept_file = action_button("Accept and choose location", self.accept_offer, True)
        self.decline_file = action_button("Decline offer", self.decline_offer)
        self.cancel_file = action_button("Cancel selected transfer", self.cancel_transfer)
        for button in (self.accept_file, self.decline_file, self.cancel_file):
            button.setEnabled(False)
        actions.addWidget(self.accept_file)
        actions.addWidget(self.decline_file)
        actions.addWidget(self.cancel_file)
        actions.addStretch(1)
        layout.addLayout(actions)
        # Retained as a non-primary compatibility selector for existing callers/tests.
        self.transfer_list = QComboBox()
        self.transfer_list.setVisible(False)
        layout.addWidget(self.transfer_list)
        return page

    def _build_feed_page(self) -> QWidget:
        page, layout = self._page(
            "Local commons", "Posts are local or cached; reported wall time is not global order.")
        sync = QHBoxLayout()
        self.feed_peer = QComboBox()
        self.feed_peer.setAccessibleName("Feed synchronization source")
        self.feed_peer.addItem("Select one posts-capable peer", None)
        self.sync_button = action_button("Sync selected peer", self.sync_feed)
        sync.addWidget(self.feed_peer, 1)
        sync.addWidget(self.sync_button)
        layout.addLayout(sync)
        self.feed_view = QListView()
        self.feed_view.setModel(self.post_model)
        self.feed_view.setAccessibleName("Local and cached posts")
        self.feed_view.setWordWrap(True)
        self.feed_view.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(self.feed_view, 1)
        compose = QHBoxLayout()
        self.post_input = QLineEdit()
        self.post_input.setMaxLength(4096)
        self.post_input.setPlaceholderText("Publish plain text to your local feed")
        self.post_input.setAccessibleName("Post text")
        self.publish_button = action_button("Publish locally", self.publish_post, True)
        self.post_input.returnPressed.connect(self.publish_post)
        compose.addWidget(self.post_input, 1)
        compose.addWidget(self.publish_button)
        layout.addLayout(compose)
        note = QLabel(
            "Publishing stores the post locally. Other peers receive it only when they synchronize.")
        note.setObjectName("PageSubtitle")
        note.setWordWrap(True)
        layout.addWidget(note)
        # Plain-text compatibility surface used by existing tests and accessibility fallback.
        self.feed_log = QTextEdit()
        self.feed_log.setReadOnly(True)
        self.feed_log.setVisible(False)
        layout.addWidget(self.feed_log)
        return page

    def _build_directory_page(self) -> QWidget:
        page, layout = self._page(
            "Games and services",
            "Explicit local publications only; reachability and health are not inferred.")
        self.directory_tabs = QTabWidget()
        self.game_view = QListView()
        self.game_view.setModel(self.game_model)
        self.game_view.setAccessibleName("Published game sessions")
        self.game_view.setWordWrap(True)
        self.game_view.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.service_view = QListView()
        self.service_view.setModel(self.service_model)
        self.service_view.setAccessibleName("Published LAN services")
        self.service_view.setWordWrap(True)
        self.service_view.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.directory_tabs.addTab(self.game_view, "Games")
        self.directory_tabs.addTab(self.service_view, "Services")
        self.directory_tabs.currentChanged.connect(
            lambda _index: self._update_directory_open())
        self.game_view.selectionModel().currentChanged.connect(
            lambda _current, _previous: self._update_directory_open())
        self.service_view.selectionModel().currentChanged.connect(
            lambda _current, _previous: self._update_directory_open())
        layout.addWidget(self.directory_tabs, 1)
        sync_row = QHBoxLayout()
        self.directory_peer = QComboBox()
        self.directory_peer.setAccessibleName("Directory synchronization source")
        self.directory_peer.addItem("Select one directory-capable peer", None)
        self.directory_sync = action_button(
            "Sync selected peer", self._sync_directory)
        sync_row.addWidget(self.directory_peer, 1)
        sync_row.addWidget(self.directory_sync)
        layout.addLayout(sync_row)
        actions = QHBoxLayout()
        self.directory_open = action_button(
            "Open selected HTTP service", self._open_directory_entry, True)
        self.directory_open.setEnabled(False)
        actions.addWidget(self.directory_open)
        actions.addStretch(1)
        layout.addLayout(actions)
        note = QLabel(
            "Open hands a validated HTTP or HTTPS URL to the platform browser. It does "
            "not prove the endpoint is reachable, healthy, trusted, or multiplayer-capable.")
        note.setObjectName("PageSubtitle")
        note.setWordWrap(True)
        layout.addWidget(note)
        return page

    def _build_placeholder_page(self, title: str, subtitle: str, body: str) -> QWidget:
        page, layout = self._page(title, subtitle)
        frame = QFrame()
        frame.setProperty("card", True)
        frame_layout = QVBoxLayout(frame)
        label = QLabel(body)
        label.setWordWrap(True)
        label.setObjectName("BodyText")
        frame_layout.addWidget(label)
        frame_layout.addStretch(1)
        layout.addWidget(frame, 1)
        return page

    def _stat_rows(self, parent: QVBoxLayout,
                   titles: tuple[str, ...]) -> dict[str, MonoLabel]:
        """Build muted-key plus mono-value rows for one tool result."""
        stats: dict[str, MonoLabel] = {}
        for title in titles:
            row, value = inspector_row(title)
            parent.addWidget(row)
            stats[title] = value
        return stats

    def _build_ping_tab(self) -> tuple[QWidget, dict[str, QSpinBox | QDoubleSpinBox],
                                       dict[str, MonoLabel], SparklineWidget,
                                       StatusPill, QPushButton]:
        """Build ping parameters, stats rows, and a sample sparkline."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        count = QSpinBox()
        count.setRange(1, 10)
        count.setValue(4)
        count.setAccessibleName("Ping packet count")
        timeout = QDoubleSpinBox()
        timeout.setRange(0.5, 10.0)
        timeout.setSingleStep(0.5)
        timeout.setValue(3.0)
        timeout.setSuffix(" s")
        timeout.setAccessibleName("Ping per-packet timeout")
        payload = QSpinBox()
        payload.setRange(0, 1400)
        payload.setValue(32)
        payload.setSuffix(" B")
        payload.setAccessibleName("Ping payload size")
        for label, widget in (("Packets", count), ("Timeout", timeout),
                              ("Payload", payload)):
            row = QHBoxLayout()
            name = QLabel(label)
            name.setObjectName("MetricLabel")
            row.addWidget(name)
            row.addWidget(widget, 1)
            layout.addLayout(row)
        run = action_button("Ping selected", self._ping_admin_target, True)
        layout.addWidget(run)
        pill = StatusPill("Idle", "nearby")
        layout.addWidget(pill)
        stats = self._stat_rows(layout, ("Replies:", "Loss:", "Min RTT:",
                                         "Avg RTT:", "Max RTT:", "Jitter:",
                                         "TTL:"))
        sparkline = SparklineWidget()
        layout.addWidget(sparkline)
        layout.addStretch(1)
        return tab, {"count": count, "timeout": timeout,
                     "payload": payload}, stats, sparkline, pill, run

    def _build_tcp_tab(self) -> tuple[QWidget, dict[str, QSpinBox | QDoubleSpinBox],
                                      dict[str, MonoLabel], StatusPill,
                                      QPushButton]:
        """Build TCP parameters and handshake result rows."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        timeout = QDoubleSpinBox()
        timeout.setRange(0.5, 10.0)
        timeout.setSingleStep(0.5)
        timeout.setValue(3.0)
        timeout.setSuffix(" s")
        timeout.setAccessibleName("TCP per-attempt timeout")
        attempts = QSpinBox()
        attempts.setRange(1, 5)
        attempts.setValue(1)
        attempts.setAccessibleName("TCP attempts")
        for label, widget in (("Timeout", timeout), ("Attempts", attempts)):
            row = QHBoxLayout()
            name = QLabel(label)
            name.setObjectName("MetricLabel")
            row.addWidget(name)
            row.addWidget(widget, 1)
            layout.addLayout(row)
        run = action_button("Check TCP port", self._tcp_admin_target)
        layout.addWidget(run)
        pill = StatusPill("Idle", "nearby")
        layout.addWidget(pill)
        stats = self._stat_rows(layout, ("Connect time:", "Attempts:"))
        layout.addStretch(1)
        return tab, {"timeout": timeout, "attempts": attempts}, stats, pill, run

    def _build_echo_tab(self) -> tuple[QWidget, dict[str, MonoLabel],
                                       StatusPill, QPushButton]:
        """Build ECHO identity, timing, and correlation rows."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        run = action_button("Check LAN Manager ECHO", self._echo_admin_target)
        run.setToolTip("Available only for the selected session advertising echo_v1.")
        run.setEnabled(False)
        layout.addWidget(run)
        pill = StatusPill("Idle", "nearby")
        layout.addWidget(pill)
        stats = self._stat_rows(layout, ("Correlation ID:", "Timing:",
                                         "Reply:"))
        layout.addStretch(1)
        return tab, stats, pill, run

    def _build_admin_page(self) -> QWidget:
        page, layout = self._page(
            "Workbench",
            "Observe local evidence and run bounded checks against one selected endpoint.",
            True)
        scope = QLabel(
            "Local operator view · no elevated authority. Neighbor-cache rows can be stale "
            "or incomplete; checks do not establish identity or trust.")
        scope.setProperty("warning", True)
        scope.setWordWrap(True)
        layout.addWidget(scope)

        tools = QFrame()
        tools.setObjectName("OperationalToolbar")
        tools_layout = QHBoxLayout(tools)
        tools_title = QLabel("IMPLEMENTED TOOLS")
        tools_title.setObjectName("SectionLabel")
        for text in ("PING / ICMP", "TCP HANDSHAKE", "LAN ATLAS ECHO"):
            chip = QLabel(text)
            chip.setProperty("chip", True)
            tools_layout.addWidget(chip)
        tools_layout.addStretch(1)
        self.workbench_limit = QLabel("One bounded worker · finite timeout · cancellable")
        self.workbench_limit.setObjectName("TechnicalDetail")
        tools_layout.addWidget(self.workbench_limit)
        layout.addWidget(tools)

        self.workbench_splitter = QSplitter(Qt.Orientation.Horizontal)
        inventory = QFrame()
        inventory.setProperty("panel", True)
        inventory_layout = QVBoxLayout(inventory)
        inventory_header = QHBoxLayout()
        inventory_title = QLabel("OBSERVED DEVICES")
        inventory_title.setObjectName("SectionLabel")
        self.refresh_neighbors_button = action_button(
            "Refresh neighbor cache", self._refresh_neighbors)
        inventory_header.addWidget(inventory_title)
        inventory_header.addStretch(1)
        inventory_header.addWidget(self.refresh_neighbors_button)
        inventory_layout.addLayout(inventory_header)
        self.inventory_status = QLabel(
            "LAN Atlas sessions appear automatically. Refresh to read the OS neighbor cache.")
        self.inventory_status.setObjectName("PageSubtitle")
        self.inventory_status.setWordWrap(True)
        inventory_layout.addWidget(self.inventory_status)
        self.admin_device_list = QListView()
        self.admin_device_list.setModel(self.admin_device_model)
        self.admin_device_list.setAccessibleName("Observed LAN endpoints")
        self.admin_device_list.setWordWrap(True)
        self.admin_device_list.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.admin_device_list.selectionModel().currentChanged.connect(
            self._admin_device_selected)
        inventory_layout.addWidget(self.admin_device_list, 1)
        inventory_note = QLabel(
            "This is not a complete device census. Sleeping, isolated, and previously unseen "
            "hosts may be absent. LAN Atlas sessions and neighbor rows remain separate evidence.")
        inventory_note.setObjectName("PageSubtitle")
        inventory_note.setWordWrap(True)
        inventory_layout.addWidget(inventory_note)
        self.workbench_splitter.addWidget(inventory)

        controls = QFrame()
        controls.setProperty("panel", True)
        control_layout = QVBoxLayout(controls)
        control_title = QLabel("PROBE PARAMETERS & RESULT")
        control_title.setObjectName("PanelTitle")
        control_layout.addWidget(control_title)
        self.admin_selection = QLabel("Enter an IPv4 address or select an observation")
        self.admin_selection.setObjectName("PageSubtitle")
        self.admin_selection.setWordWrap(True)
        control_layout.addWidget(self.admin_selection)
        address_label = QLabel("Numeric IPv4 address")
        address_label.setObjectName("MetricLabel")
        self.admin_address = QLineEdit()
        self.admin_address.setProperty("technical", True)
        self.admin_address.setPlaceholderText("192.168.1.20")
        self.admin_address.setAccessibleName("Diagnostic IPv4 address")
        port_label = QLabel("TCP port")
        port_label.setObjectName("MetricLabel")
        self.admin_port = QSpinBox()
        self.admin_port.setProperty("technical", True)
        self.admin_port.setRange(1, 65535)
        self.admin_port.setValue(80)
        self.admin_port.setAccessibleName("Diagnostic TCP port")
        control_layout.addWidget(address_label)
        control_layout.addWidget(self.admin_address)
        control_layout.addWidget(port_label)
        control_layout.addWidget(self.admin_port)
        self.admin_tabs = QTabWidget()
        self.admin_tabs.setAccessibleName("Diagnostic tools")
        ping_tab, self.ping_params, self.ping_stats, self.ping_sparkline, \
            self.ping_pill, self.admin_ping_button = self._build_ping_tab()
        self.admin_tabs.addTab(ping_tab, "Ping")
        tcp_tab, self.tcp_params, self.tcp_stats, self.tcp_pill, \
            self.admin_tcp_button = self._build_tcp_tab()
        self.admin_tabs.addTab(tcp_tab, "TCP")
        echo_tab, self.echo_stats, self.echo_pill, \
            self.admin_echo_button = self._build_echo_tab()
        self.admin_tabs.addTab(echo_tab, "ECHO")
        for label in ("Raw TCP", "Traceroute", "Port Scan"):
            planned = QLabel("Not implemented in this build.")
            planned.setObjectName("PageSubtitle")
            planned.setWordWrap(True)
            planned.setAlignment(Qt.AlignmentFlag.AlignCenter)
            tab_index = self.admin_tabs.addTab(planned, label)
            self.admin_tabs.setTabEnabled(tab_index, False)
            self.admin_tabs.setTabToolTip(tab_index, "Not implemented in this build")
        control_layout.addWidget(self.admin_tabs, 1)
        self.admin_cancel_button = action_button("Cancel current check", self._cancel_admin_probe)
        self.admin_cancel_button.setEnabled(False)
        control_layout.addWidget(self.admin_cancel_button)
        self.admin_result = QLabel(
            "No check has run. Ping and TCP are separate evidence; failed ping does not prove "
            "that a TCP service is unavailable.")
        self.admin_result.setWordWrap(True)
        self.admin_result.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.admin_result.setProperty("chip", True)
        control_layout.addWidget(self.admin_result)
        self.admin_address.textChanged.connect(self._update_admin_probe_buttons)
        self.admin_port.valueChanged.connect(self._update_admin_probe_buttons)
        self.workbench_splitter.addWidget(controls)
        self.workbench_splitter.setSizes([560, 420])
        layout.addWidget(self.workbench_splitter, 1)

        console = QFrame()
        console.setProperty("well", True)
        console_layout = QVBoxLayout(console)
        console_title = QLabel("WORKBENCH ACTIVITY")
        console_title.setObjectName("SectionLabel")
        self.workbench_log = QTextEdit()
        self.workbench_log.setReadOnly(True)
        self.workbench_log.setProperty("technical", True)
        self.workbench_log.document().setMaximumBlockCount(200)
        self.workbench_log.setPlaceholderText(
            "Bounded diagnostic events will appear here. No packet details are inferred.")
        console_layout.addWidget(console_title)
        console_layout.addWidget(self.workbench_log)
        console.setMaximumHeight(220)
        layout.addWidget(console)
        return page

    def _build_activity_page(self) -> QWidget:
        page, layout = self._page(
            "Activity", "Operational events stay separate from human conversations.")
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.activity_view = QListView()
        self.activity_view.setModel(self.activity_model)
        self.activity_view.setAccessibleName("Operational activity")
        self.activity_view.setWordWrap(True)
        self.activity_view.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        splitter.addWidget(self.activity_view)
        self.log = QTextEdit()
        self.log.setProperty("technical", True)
        self.log.setReadOnly(True)
        self.log.document().setMaximumBlockCount(1000)
        self.log.setAccessibleName("Plain-text activity transcript")
        splitter.addWidget(self.log)
        splitter.setSizes([420, 170])
        layout.addWidget(splitter, 1)
        return page

    def _build_settings_page(self) -> QWidget:
        page, layout = self._page(
            "Settings", "Local identity, appearance, and explicitly bound portal access.")
        identity = QFrame()
        identity.setProperty("card", True)
        form = QGridLayout(identity)
        transport = self.service.secure_transport
        fingerprint = (transport.identity.fingerprint if transport is not None
                       else "Not configured")
        paired_count = (len(transport.trust_store.snapshot().records)
                        if transport is not None else 0)
        values = (
            ("Display name", self.service.hello.name),
            ("Installation ID", self.service.hello.peer_id),
            ("Session ID", self.service.hello.session_id),
            ("Application port", str(self.service.hello.tcp_port)),
            ("Secure application port",
             str(self.service.hello.secure_port or "Not configured")),
            ("Capabilities", ", ".join(self.service.hello.capabilities) or "presence only"),
            ("Identity certificate SHA-256", fingerprint),
            ("Paired devices", f"{paired_count} pinned certificate(s)"),
        )
        for row, (name, value) in enumerate(values):
            label = QLabel(name)
            label.setObjectName("MetricLabel")
            content = QLabel(value)
            if name in {"Installation ID", "Session ID", "Application port",
                        "Secure application port", "Identity certificate SHA-256"}:
                content.setProperty("technical", True)
            content.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            content.setWordWrap(True)
            form.addWidget(label, row, 0)
            form.addWidget(content, row, 1)
            if name == "Paired devices":
                self.settings_trust = content
        appearance_row = len(values)
        appearance_label = QLabel("Appearance")
        appearance_label.setObjectName("MetricLabel")
        self.theme_selector = QComboBox()
        self.theme_selector.addItem("Observatory Dark", "observatory")
        self.theme_selector.addItem("Atlas Light", "atlas")
        theme_index = self.theme_selector.findData(self.theme_mode)
        self.theme_selector.setCurrentIndex(max(0, theme_index))
        self.theme_selector.currentIndexChanged.connect(self._theme_changed)
        form.addWidget(appearance_label, appearance_row, 0)
        form.addWidget(self.theme_selector, appearance_row, 1)
        layout.addWidget(identity)
        network = QFrame()
        network.setProperty("card", True)
        network_layout = QVBoxLayout(network)
        network_heading = QLabel("Discovery Network")
        network_heading.setObjectName("PanelTitle")
        network_layout.addWidget(network_heading)
        network_detail = QLabel(
            "Choose which local address carries announcements over IPv4 "
            "broadcast and IPv6 link local multicast. Inbound discovery and "
            "TCP listeners remain on all interfaces.")
        network_detail.setObjectName("PageSubtitle")
        network_detail.setWordWrap(True)
        network_layout.addWidget(network_detail)
        network_form = QGridLayout()
        network_form.addWidget(QLabel("Announcement address"), 0, 0)
        self.discovery_address = QComboBox()
        self.discovery_address.setAccessibleName("Discovery announcement address")
        network_form.addWidget(self.discovery_address, 0, 1)
        self.discovery_fallback = QCheckBox("Also announce through OS default route")
        self.discovery_fallback.setAccessibleName("Discovery fallback route")
        network_form.addWidget(self.discovery_fallback, 1, 1)
        network_layout.addLayout(network_form)
        self.discovery_status = QLabel("Discovery egress not configured")
        self.discovery_status.setObjectName("PageSubtitle")
        self.discovery_status.setWordWrap(True)
        network_layout.addWidget(self.discovery_status)
        network_actions = QHBoxLayout()
        self.discovery_refresh = action_button(
            "Refresh", self._refresh_discovery_addresses)
        self.discovery_apply = action_button(
            "Apply", self._apply_discovery_selection, True)
        network_actions.addWidget(self.discovery_refresh)
        network_actions.addWidget(self.discovery_apply)
        network_actions.addStretch(1)
        network_layout.addLayout(network_actions)
        layout.addWidget(network)
        self._refresh_discovery_addresses()
        portal = QFrame()
        portal.setProperty("card", True)
        portal_layout = QVBoxLayout(portal)
        portal_header = QHBoxLayout()
        portal_heading = QLabel("LAN Atlas Portal")
        portal_heading.setObjectName("PanelTitle")
        self.portal_status = StatusPill("Stopped", "offline")
        portal_header.addWidget(portal_heading)
        portal_header.addStretch(1)
        portal_header.addWidget(self.portal_status)
        portal_layout.addLayout(portal_header)
        portal_detail = QLabel(
            "Serve selected read-only LAN Atlas pages to a normal browser. Choose one "
            "concrete LAN address; the portal never binds every interface implicitly.")
        portal_detail.setObjectName("PageSubtitle")
        portal_detail.setWordWrap(True)
        portal_layout.addWidget(portal_detail)
        portal_form = QGridLayout()
        portal_form.addWidget(QLabel("Interface address"), 0, 0)
        self.portal_address = QComboBox()
        self.portal_address.setEditable(True)
        self.portal_address.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.portal_address.setPlaceholderText("Enter a concrete IPv4 address")
        addresses = local_ipv4_addresses()
        for address in addresses:
            self.portal_address.addItem(address, address)
        if addresses:
            self.portal_address.setCurrentIndex(0)
        self.portal_address.setAccessibleName("Portal interface address")
        portal_form.addWidget(self.portal_address, 0, 1)
        portal_form.addWidget(QLabel("Port"), 1, 0)
        self.portal_port = QSpinBox()
        self.portal_port.setRange(1, 65535)
        self.portal_port.setValue(PORTAL_PORT)
        self.portal_port.setAccessibleName("Portal TCP port")
        portal_form.addWidget(self.portal_port, 1, 1)
        portal_layout.addLayout(portal_form)
        self.portal_url = MonoLabel("Portal stopped")
        self.portal_url.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        portal_layout.addWidget(self.portal_url)
        portal_actions = QHBoxLayout()
        self.portal_start = action_button(
            "Start portal", self._start_portal, True)
        self.portal_stop = action_button("Stop", self._stop_portal)
        self.portal_open = action_button("Open", self._open_portal)
        self.portal_copy = action_button("Copy address", self._copy_portal_address)
        for button in (self.portal_start, self.portal_stop,
                       self.portal_open, self.portal_copy):
            portal_actions.addWidget(button)
        self.portal_address.currentTextChanged.connect(
            lambda _text: self._refresh_portal_state())
        portal_actions.addStretch(1)
        portal_layout.addLayout(portal_actions)
        portal_warning = QLabel(
            "Portal traffic is plaintext and unauthenticated. Browser writes, diagnostics, "
            "settings, uploads, and shell access are not exposed.")
        portal_warning.setObjectName("PageSubtitle")
        portal_warning.setWordWrap(True)
        portal_layout.addWidget(portal_warning)
        layout.addWidget(portal)
        self._refresh_portal_state()
        forward = QFrame()
        forward.setProperty("card", True)
        forward_layout = QVBoxLayout(forward)
        forward_header = QHBoxLayout()
        forward_heading = QLabel("Loopback sharing")
        forward_heading.setObjectName("PanelTitle")
        self.forward_status = StatusPill("Stopped", "offline")
        forward_header.addWidget(forward_heading)
        forward_header.addStretch(1)
        forward_header.addWidget(self.forward_status)
        forward_layout.addLayout(forward_header)
        forward_detail = QLabel(
            "Expose one loopback-only project to the LAN through raw byte "
            "forwarding. The listener binds one concrete LAN address; the "
            "target must stay loopback. Stopping withdraws reachability.")
        forward_detail.setObjectName("PageSubtitle")
        forward_detail.setWordWrap(True)
        forward_layout.addWidget(forward_detail)
        forward_form = QGridLayout()
        forward_form.addWidget(QLabel("Target host"), 0, 0)
        self.forward_target_host = QLineEdit("127.0.0.1")
        self.forward_target_host.setMaxLength(255)
        self.forward_target_host.setAccessibleName("Forward target host")
        forward_form.addWidget(self.forward_target_host, 0, 1)
        forward_form.addWidget(QLabel("Target port"), 1, 0)
        self.forward_target_port = QSpinBox()
        self.forward_target_port.setRange(1, 65535)
        self.forward_target_port.setValue(8000)
        self.forward_target_port.setAccessibleName("Forward target port")
        forward_form.addWidget(self.forward_target_port, 1, 1)
        forward_form.addWidget(QLabel("Listener address"), 2, 0)
        self.forward_address = QComboBox()
        self.forward_address.setEditable(True)
        self.forward_address.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.forward_address.setPlaceholderText("Enter a concrete IPv4 address")
        forward_addresses = local_ipv4_addresses()
        for address in forward_addresses:
            self.forward_address.addItem(address, address)
        if forward_addresses:
            self.forward_address.setCurrentIndex(0)
        self.forward_address.setAccessibleName("Forward listener address")
        forward_form.addWidget(self.forward_address, 2, 1)
        forward_form.addWidget(QLabel("Listener port"), 3, 0)
        self.forward_port = QSpinBox()
        self.forward_port.setRange(0, 65535)
        self.forward_port.setValue(9000)
        self.forward_port.setAccessibleName("Forward listener port")
        forward_form.addWidget(self.forward_port, 3, 1)
        forward_layout.addLayout(forward_form)
        self.forward_stats = MonoLabel("Forwarder stopped")
        self.forward_stats.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        forward_layout.addWidget(self.forward_stats)
        forward_actions = QHBoxLayout()
        self.forward_start = action_button(
            "Start sharing", self._start_forwarding, True)
        self.forward_stop = action_button("Stop", self._stop_forwarding)
        self.forward_publish = action_button(
            "Use in publication", self._use_forwarder_in_publication)
        for button in (self.forward_start, self.forward_stop,
                       self.forward_publish):
            forward_actions.addWidget(button)
        self.forward_address.currentTextChanged.connect(
            lambda _text: self._refresh_forwarder_state())
        forward_actions.addStretch(1)
        forward_layout.addLayout(forward_actions)
        forward_warning = QLabel(
            "Forwarding copies raw bytes and does not repair application "
            "assumptions: Host validation, absolute localhost URLs, redirects, "
            "CORS, cookies, TLS names, and WebSocket URL configuration.")
        forward_warning.setObjectName("PageSubtitle")
        forward_warning.setWordWrap(True)
        forward_layout.addWidget(forward_warning)
        layout.addWidget(forward)
        self._refresh_forwarder_state()
        internet = QFrame()
        internet.setProperty("card", True)
        internet_layout = QVBoxLayout(internet)
        internet_heading = QLabel("Internet peers")
        internet_heading.setObjectName("PanelTitle")
        internet_layout.addWidget(internet_heading)
        internet_detail = QLabel(
            "Dial paired peers outside the LAN by explicit address. Pairing "
            "happens on the LAN first; unpaired Internet dials are refused. "
            "No discovery runs over the Internet.")
        internet_detail.setObjectName("PageSubtitle")
        internet_detail.setWordWrap(True)
        internet_layout.addWidget(internet_detail)
        self.internet_list = QListWidget()
        self.internet_list.setAccessibleName("Internet peer entries")
        self.internet_list.setMaximumHeight(110)
        internet_layout.addWidget(self.internet_list)
        internet_form = QGridLayout()
        internet_form.addWidget(QLabel("Paired session"), 0, 0)
        self.internet_session = QComboBox()
        self.internet_session.setAccessibleName("Paired session for entry")
        internet_form.addWidget(self.internet_session, 0, 1)
        internet_form.addWidget(QLabel("Label"), 1, 0)
        self.internet_label = QLineEdit()
        self.internet_label.setMaxLength(80)
        internet_form.addWidget(self.internet_label, 1, 1)
        internet_form.addWidget(QLabel("Host"), 2, 0)
        self.internet_host = QLineEdit()
        self.internet_host.setMaxLength(255)
        self.internet_host.setPlaceholderText("Public host or address")
        internet_form.addWidget(self.internet_host, 2, 1)
        internet_form.addWidget(QLabel("Port"), 3, 0)
        self.internet_port = QSpinBox()
        self.internet_port.setRange(1, 65535)
        self.internet_port.setValue(50003)
        internet_form.addWidget(self.internet_port, 3, 1)
        internet_layout.addLayout(internet_form)
        internet_actions = QHBoxLayout()
        self.internet_add = action_button(
            "Add entry", self._add_internet_peer, True)
        self.internet_remove = action_button(
            "Remove entry", self._remove_internet_peer)
        internet_actions.addWidget(self.internet_add)
        internet_actions.addWidget(self.internet_remove)
        internet_actions.addStretch(1)
        internet_layout.addLayout(internet_actions)
        rv_form = QGridLayout()
        rv_form.addWidget(QLabel("Rendezvous server"), 0, 0)
        self.rv_host = QLineEdit()
        self.rv_host.setMaxLength(255)
        self.rv_host.setPlaceholderText("Rendezvous host (untrusted directory)")
        rv_form.addWidget(self.rv_host, 0, 1)
        rv_form.addWidget(QLabel("Server port"), 1, 0)
        self.rv_port = QSpinBox()
        self.rv_port.setRange(1, 65535)
        self.rv_port.setValue(50004)
        rv_form.addWidget(self.rv_port, 1, 1)
        rv_form.addWidget(QLabel("Announced secure port"), 2, 0)
        self.rv_secure_port = QSpinBox()
        self.rv_secure_port.setRange(1, 65535)
        announced_secure = self.service.hello.secure_port or 50003
        self.rv_secure_port.setValue(announced_secure)
        rv_form.addWidget(self.rv_secure_port, 2, 1)
        internet_layout.addLayout(rv_form)
        self.rv_results = QListWidget()
        self.rv_results.setAccessibleName("Rendezvous lookup results")
        self.rv_results.setMaximumHeight(90)
        internet_layout.addWidget(self.rv_results)
        rv_actions = QHBoxLayout()
        self.rv_register = action_button(
            "Register", self._toggle_rendezvous, True)
        self.rv_lookup = action_button(
            "Look up peers", self._lookup_rendezvous)
        self.rv_add_result = action_button(
            "Add selected result", self._add_rendezvous_result)
        for button in (self.rv_register, self.rv_lookup,
                       self.rv_add_result):
            rv_actions.addWidget(button)
        rv_actions.addStretch(1)
        internet_layout.addLayout(rv_actions)
        relay_form = QGridLayout()
        relay_form.addWidget(QLabel("Relay server"), 0, 0)
        self.relay_host = QLineEdit()
        self.relay_host.setMaxLength(255)
        self.relay_host.setPlaceholderText("Relay host for NAT'd peers")
        relay_form.addWidget(self.relay_host, 0, 1)
        relay_form.addWidget(QLabel("Relay port"), 1, 0)
        self.relay_port = QSpinBox()
        self.relay_port.setRange(1, 65535)
        self.relay_port.setValue(50005)
        relay_form.addWidget(self.relay_port, 1, 1)
        relay_form.addWidget(QLabel("Relay token"), 2, 0)
        self.relay_token = QLineEdit()
        self.relay_token.setMaxLength(32)
        self.relay_token.setPlaceholderText("Paste a token or reserve one")
        relay_form.addWidget(self.relay_token, 2, 1)
        internet_layout.addLayout(relay_form)
        relay_actions = QHBoxLayout()
        self.relay_reserve = action_button(
            "Reserve relay slot", self._reserve_relay, True)
        self.relay_send = action_button(
            "Send via relay", self._send_via_relay)
        for button in (self.relay_reserve, self.relay_send):
            relay_actions.addWidget(button)
        relay_actions.addStretch(1)
        internet_layout.addLayout(relay_actions)
        relay_note = QLabel(
            "The relay splices raw bytes without reading them; TLS still runs "
            "end to end with the paired peer. Tokens are single use bearer "
            "secrets: share them over a verified channel only. Reserve one "
            "per message. Relay chat carries direct messages only and blocks "
            "the interface briefly with finite timeouts.")
        relay_note.setObjectName("PageSubtitle")
        relay_note.setWordWrap(True)
        internet_layout.addWidget(relay_note)
        rv_note = QLabel(
            "Register announces the address above, signed by this device, "
            "every two minutes over plaintext TCP framing. Eavesdroppers see "
            "contact details plus certificates. The server is untrusted: "
            "entries are verified against paired keys before display, and "
            "pairing still needs the LAN or a verified second channel.")
        rv_note.setObjectName("PageSubtitle")
        rv_note.setWordWrap(True)
        internet_layout.addWidget(rv_note)
        layout.addWidget(internet)
        self._refresh_internet_list()
        publications = QFrame()
        publications.setProperty("card", True)
        publication_layout = QVBoxLayout(publications)
        publication_heading = QLabel("Published services and games")
        publication_heading.setObjectName("PanelTitle")
        publication_layout.addWidget(publication_heading)
        publication_detail = QLabel(
            "Session-local entries appear on this desktop and its portal. They are not "
            "advertised through discovery and are not checked for reachability or health.")
        publication_detail.setObjectName("PageSubtitle")
        publication_detail.setWordWrap(True)
        publication_layout.addWidget(publication_detail)
        publication_form = QGridLayout()
        self.directory_selector = QComboBox()
        self.directory_selector.addItem("New publication", None)
        publication_form.addWidget(QLabel("Entry"), 0, 0)
        publication_form.addWidget(self.directory_selector, 0, 1)
        self.directory_kind = QComboBox()
        self.directory_kind.addItem("Service", DirectoryKind.SERVICE.value)
        self.directory_kind.addItem("Game", DirectoryKind.GAME.value)
        publication_form.addWidget(QLabel("Kind"), 1, 0)
        publication_form.addWidget(self.directory_kind, 1, 1)
        self.directory_name = QLineEdit()
        self.directory_name.setMaxLength(80)
        publication_form.addWidget(QLabel("Name"), 2, 0)
        publication_form.addWidget(self.directory_name, 2, 1)
        self.directory_description = QLineEdit()
        self.directory_description.setMaxLength(500)
        publication_form.addWidget(QLabel("Description"), 3, 0)
        publication_form.addWidget(self.directory_description, 3, 1)
        self.directory_scheme = QComboBox()
        self.directory_scheme.addItem("HTTP", "http")
        self.directory_scheme.addItem("HTTPS", "https")
        publication_form.addWidget(QLabel("Scheme"), 4, 0)
        publication_form.addWidget(self.directory_scheme, 4, 1)
        self.directory_host = QComboBox()
        self.directory_host.setEditable(True)
        self.directory_host.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.directory_host.setPlaceholderText("Concrete LAN IPv4 address")
        directory_addresses = local_ipv4_addresses()
        for address in directory_addresses:
            self.directory_host.addItem(address, address)
        if directory_addresses:
            self.directory_host.setCurrentIndex(0)
        publication_form.addWidget(QLabel("Host"), 5, 0)
        publication_form.addWidget(self.directory_host, 5, 1)
        self.directory_port = QSpinBox()
        self.directory_port.setRange(1, 65535)
        self.directory_port.setValue(8000)
        publication_form.addWidget(QLabel("Port"), 6, 0)
        publication_form.addWidget(self.directory_port, 6, 1)
        self.directory_path = QLineEdit("/")
        self.directory_path.setMaxLength(255)
        publication_form.addWidget(QLabel("Path"), 7, 0)
        publication_form.addWidget(self.directory_path, 7, 1)
        publication_layout.addLayout(publication_form)
        publication_actions = QHBoxLayout()
        self.directory_publish = action_button(
            "Publish locally", self._publish_directory_entry, True)
        self.directory_withdraw = action_button(
            "Withdraw", self._withdraw_directory_entry)
        self.directory_withdraw.setEnabled(False)
        publication_actions.addWidget(self.directory_publish)
        publication_actions.addWidget(self.directory_withdraw)
        publication_actions.addStretch(1)
        publication_layout.addLayout(publication_actions)
        self.directory_selector.currentIndexChanged.connect(
            self._load_directory_entry)
        layout.addWidget(publications)
        security = QFrame()
        security.setProperty("card", True)
        security_layout = QVBoxLayout(security)
        self.settings_security_heading = QLabel("Per-device trust")
        self.settings_security_heading.setObjectName("SecurityHeading")
        self.settings_security_detail = QLabel(
            "Discovery remains self-reported. Unpaired peers use visibly labeled legacy "
            "plaintext. Paired chat, feed, and file connections require the pinned device "
            "certificate over TLS; the browser portal remains plaintext and unauthenticated.")
        self.settings_security_detail.setWordWrap(True)
        security_layout.addWidget(self.settings_security_heading)
        security_layout.addWidget(self.settings_security_detail)
        layout.addWidget(security)
        layout.addStretch(1)
        return page

    def _install_shortcuts(self) -> None:
        self.shortcuts: list[QShortcut] = []
        shortcut_pages = (PAGE_OVERVIEW, PAGE_NETWORK, PAGE_DEVICES, PAGE_WORKBENCH,
                          PAGE_FILES, PAGE_TRANSFERS, PAGE_MESSAGES, PAGE_FEED,
                          PAGE_GAMES)
        for key, page_index in enumerate(shortcut_pages, 1):
            shortcut = QShortcut(QKeySequence(f"Ctrl+{key}"), self)
            shortcut.activated.connect(
                lambda page=page_index: self.navigation.select(page))
            self.shortcuts.append(shortcut)
        self.settings_shortcut = QShortcut(QKeySequence("Ctrl+,"), self)
        self.settings_shortcut.activated.connect(
            lambda: self.navigation.select(PAGE_SETTINGS))
        self.command_shortcut = QShortcut(QKeySequence("Ctrl+K"), self)
        self.command_shortcut.activated.connect(
            lambda: self.append("Command palette is reserved for a later phase.", "System"))

    @Slot(int)
    def select_page(self, index: int) -> None:
        """Switch one primary workspace and preserve all model selections."""
        if 0 <= index < self.stack.count():
            self.stack.setCurrentIndex(index)

    def resizeEvent(self, event: QResizeEvent) -> None:
        """Adapt dense shell regions to the available logical width."""
        super().resizeEvent(event)
        if hasattr(self, "workbench_splitter"):
            self._apply_responsive_layout(event.size().width())

    def _apply_responsive_layout(self, width: int) -> None:
        compact = width < GEOMETRY["responsive_breakpoint"]
        self.navigation.set_compact(compact)
        self.identity_status.setVisible(not compact)
        self.network_status.setVisible(not compact)
        self.command_button.setVisible(not compact)
        self.network_toolbar_evidence.setVisible(not compact)
        self.device_scope.setVisible(not compact)
        self.workbench_limit.setVisible(not compact)
        orientation = (Qt.Orientation.Vertical if compact
                       else Qt.Orientation.Horizontal)
        for splitter in (self.overview_splitter, self.overview_detail_splitter,
                         self.network_splitter, self.peer_splitter,
                         self.workbench_splitter):
            splitter.setOrientation(orientation)
        for page, compact_height in self.responsive_pages:
            page.setMinimumHeight(compact_height if compact else 0)
            if page.layout() is not None:
                page.layout().invalidate()
            page.updateGeometry()

    @Slot(int)
    def _theme_changed(self, index: int) -> None:
        """Apply and persist one user-selected appearance mode."""
        mode = self.theme_selector.itemData(index)
        if not isinstance(mode, str):
            return
        self.theme_mode = mode
        app = QApplication.instance()
        if app is not None:
            self.theme_mode = apply_theme(app, mode)
        self.settings.setValue("appearance/theme", self.theme_mode)
        self.topology.set_theme(self.theme_mode)
        self.overview_topology.set_theme(self.theme_mode)
        self.topology.select_session(self.peer_selection.session_id)
        self.overview_topology.select_session(self.peer_selection.session_id)

    @Slot()
    def _refresh_discovery_addresses(self) -> None:
        """Re-enumerate local addresses without changing egress selection."""
        try:
            current_sources, current_fallback, _ = self.service.discovery_selection()
        except (AttributeError, ValueError):
            current_sources, current_fallback = None, True
        addresses = local_ipv4_addresses() + local_ipv6_addresses()
        self.discovery_address.blockSignals(True)
        self.discovery_address.clear()
        self.discovery_address.addItem("Automatic: all detected addresses", None)
        for address in addresses:
            self.discovery_address.addItem(address, address)
        if current_sources is None:
            self.discovery_address.setCurrentIndex(0)
        elif len(current_sources) == 1 and current_sources[0] in addresses:
            self.discovery_address.setCurrentIndex(
                self.discovery_address.findData(current_sources[0]))
        elif len(current_sources) == 1:
            self.discovery_address.addItem(
                f"{current_sources[0]} (unavailable)", current_sources[0])
            self.discovery_address.setCurrentIndex(
                self.discovery_address.count() - 1)
        else:
            self.discovery_address.addItem(
                f"Custom selection ({len(current_sources)} addresses)",
                tuple(current_sources))
            self.discovery_address.setCurrentIndex(
                self.discovery_address.count() - 1)
        self.discovery_address.blockSignals(False)
        self.discovery_fallback.setChecked(bool(current_fallback))
        self._render_discovery_status(current_sources, bool(current_fallback))

    def _render_discovery_status(
            self, sources: tuple[str, ...] | None, fallback: bool) -> None:
        """Describe announcement scope without claiming route selection."""
        if sources is None:
            selected = "Automatic: all detected addresses"
        elif len(sources) == 1:
            selected = sources[0]
        elif not sources:
            selected = "No bound address"
        else:
            selected = f"Custom selection ({len(sources)} addresses)"
        route = "with OS default route" if fallback else "without OS default route"
        self.discovery_status.setText(
            f"Announces from {selected} {route}. Applies live. "
            "Inbound discovery and TCP listeners remain on all interfaces.")

    @Slot()
    def _apply_discovery_selection(self) -> None:
        """Apply announcement egress live and persist the selection."""
        data = self.discovery_address.currentData()
        if data is None:
            sources: tuple[str, ...] | None = None
        elif isinstance(data, str):
            sources = (data,)
        elif isinstance(data, tuple):
            sources = tuple(data)
        else:
            sources = None
        fallback = self.discovery_fallback.isChecked()
        try:
            self.service.set_discovery_source_addresses(sources, fallback)
        except ValueError as error:
            self.append(f"Discovery selection rejected: {error}",
                        "Network", "warning")
            return
        try:
            if sources is None:
                self.settings.setValue("network/discovery_address", "auto")
            else:
                self.settings.setValue("network/discovery_address",
                                       ",".join(sources) if sources else "auto")
            self.settings.setValue("network/discovery_include_fallback", fallback)
        except (OSError, RuntimeError, ValueError) as error:
            self.append(f"Could not persist discovery selection: {error}",
                        "Network", "warning")
        self._render_discovery_status(sources, fallback)
        self.append("Discovery announcement selection applied live.",
                    "Network")

    @Slot()
    def _start_portal(self) -> None:
        """Start the browser portal on the explicitly selected address."""
        address = self.portal_address.currentText().strip()
        if not address:
            self.append("Select a concrete LAN interface before starting the portal.",
                        "Portal", "warning")
            return
        try:
            state = self.portal.start(address, self.portal_port.value())
        except (OSError, RuntimeError, ValueError) as error:
            self.append(f"Portal start failed: {error}", "Portal", "warning")
            self._refresh_portal_state()
            return
        self.append(f"Portal listening at {state.url}", "Portal")
        self._refresh_portal_state()

    @Slot()
    def _stop_portal(self) -> None:
        """Request portal shutdown without waiting in the Qt event loop."""
        self.portal.stop()
        self.append("Portal stop requested.", "Portal")
        self._refresh_portal_state()

    @Slot()
    def _open_portal(self) -> None:
        """Open the current concrete portal URL in the platform browser."""
        url = self.portal.state().url
        if url is None:
            return
        if not QDesktopServices.openUrl(QUrl(url)):
            self.append("The platform browser did not accept the portal URL.",
                        "Portal", "warning")

    @Slot()
    def _copy_portal_address(self) -> None:
        """Copy the current concrete portal URL to the system clipboard."""
        url = self.portal.state().url
        if url is not None:
            QApplication.clipboard().setText(url)

    @Slot()
    def _start_forwarding(self) -> None:
        """Expose one loopback target on the selected LAN listener."""
        address = self.forward_address.currentText().strip()
        if not address:
            self.append("Select a concrete LAN interface before sharing.",
                        "Services", "warning")
            return
        try:
            state = self.forwarder.start(
                address, self.forward_port.value(),
                self.forward_target_host.text(),
                self.forward_target_port.value())
        except (OSError, RuntimeError, ValueError) as error:
            self.append(f"Sharing start failed: {error}", "Services", "warning")
            self._refresh_forwarder_state()
            return
        self.append(f"Sharing loopback {state.target_host}:{state.target_port} "
                    f"at {state.listen_host}:{state.listen_port}.", "Services")
        self._refresh_forwarder_state()

    @Slot()
    def _stop_forwarding(self) -> None:
        """Withdraw the LAN endpoint without waiting in the Qt event loop."""
        previous = self.forwarder.state()
        self.forwarder.stop()
        self.append("Sharing stop requested; the endpoint is withdrawn.",
                    "Services")
        if (previous.phase == "running" and previous.listen_host is not None
                and previous.listen_port is not None):
            stale = [entry for entry in self.directory.snapshot().entries
                     if entry.host == previous.listen_host
                     and entry.port == previous.listen_port]
            if stale:
                names = ", ".join(entry.name for entry in stale[:3])
                self.append(f"Withdraw {names} separately; publications "
                            "do not follow the forwarder automatically.",
                            "Services", "warning")
        self._refresh_forwarder_state()

    @Slot()
    def _use_forwarder_in_publication(self) -> None:
        """Prefill the publication form with the live forwarding endpoint."""
        state = self.forwarder.state()
        if state.phase != "running" or state.listen_host is None:
            self.append("Start sharing before using it in a publication.",
                        "Services", "warning")
            return
        self.directory_selector.setCurrentIndex(0)
        self.directory_host.setEditText(state.listen_host)
        self.directory_port.setValue(state.listen_port or 9000)
        self.append("Publication form now points at the shared endpoint. "
                    "Name it and publish locally.", "Services")

    def _refresh_forwarder_state(self) -> None:
        """Render one thread-safe forwarding lifecycle snapshot."""
        state = self.forwarder.state()
        running = state.phase == "running"
        if running:
            self.forward_status.setText("Sharing")
            self.forward_status.set_state("reachable")
        elif state.phase == "stopping":
            self.forward_status.setText("Stopping")
            self.forward_status.set_state("unverified")
        elif state.phase == "failed":
            self.forward_status.setText("Failed")
            self.forward_status.set_state("unverified")
        else:
            self.forward_status.setText("Stopped")
            self.forward_status.set_state("offline")
        if running and state.listen_host is not None:
            self.forward_stats.setText(
                f"{state.target_host}:{state.target_port} available at "
                f"{state.listen_host}:{state.listen_port} · "
                f"{state.active} active · {state.total_connections} total · "
                f"{human_bytes(float(state.bytes_relayed))} relayed")
        elif state.phase == "failed":
            self.forward_stats.setText(f"Sharing failed: {state.error}")
        else:
            self.forward_stats.setText("Forwarder stopped")
        self.forward_start.setEnabled(state.phase in ("stopped", "failed"))
        self.forward_stop.setEnabled(running)

    def _refresh_portal_state(self) -> None:
        """Render one thread-safe portal lifecycle snapshot."""
        state = self.portal.state()
        running = state.phase == "running"
        stopping = state.phase == "stopping"
        if running:
            self.portal_status.setText("Running")
            self.portal_status.set_state("reachable")
            self.portal_url.setText(state.url or "Portal running")
        elif stopping:
            self.portal_status.setText("Stopping")
            self.portal_status.set_state("unverified")
            self.portal_url.setText(state.url or "Portal stopping")
        elif state.phase == "failed":
            self.portal_status.setText("Failed")
            self.portal_status.set_state("unverified")
            self.portal_url.setText(f"Portal failed: {state.error}")
        else:
            self.portal_status.setText("Stopped")
            self.portal_status.set_state("offline")
            self.portal_url.setText("Portal stopped")
        selectable = bool(self.portal_address.currentText().strip())
        self.portal_start.setEnabled(not running and not stopping and selectable)
        self.portal_stop.setEnabled(running)
        self.portal_open.setEnabled(running and state.url is not None)
        self.portal_copy.setEnabled(running and state.url is not None)
        self.portal_address.setEnabled(not running and not stopping)
        self.portal_port.setEnabled(not running and not stopping)

    @Slot(int)
    def _load_directory_entry(self, index: int) -> None:
        """Load one local publication into desktop-only editing controls."""
        identifier = self.directory_selector.itemData(index)
        entry = self.directory.get(identifier if isinstance(identifier, str) else None)
        if entry is None:
            self.directory_publish.setText("Publish locally")
            self.directory_withdraw.setEnabled(False)
            self.directory_name.clear()
            self.directory_description.clear()
            self.directory_path.setText("/")
            return
        self.directory_kind.setCurrentIndex(
            self.directory_kind.findData(entry.kind.value))
        self.directory_name.setText(entry.name)
        self.directory_description.setText(entry.description)
        self.directory_scheme.setCurrentIndex(
            self.directory_scheme.findData(entry.scheme))
        self.directory_host.setCurrentText(entry.host)
        self.directory_port.setValue(entry.port)
        self.directory_path.setText(entry.path)
        self.directory_publish.setText("Update publication")
        self.directory_withdraw.setEnabled(True)

    @Slot()
    def _publish_directory_entry(self) -> None:
        """Register or update one validated session-local publication."""
        identifier = self.directory_selector.currentData()
        values = (
            str(self.directory_kind.currentData()),
            self.directory_name.text(),
            self.directory_description.text(),
            str(self.directory_scheme.currentData()),
            self.directory_host.currentText(),
            self.directory_port.value(),
            self.directory_path.text(),
        )
        try:
            if isinstance(identifier, str):
                entry = self.directory.update(identifier, *values)
                action = "Updated"
            else:
                entry = self.directory.register(*values)
                action = "Published"
        except (KeyError, RuntimeError, ValueError) as error:
            self.append(f"Directory publication failed: {error}",
                        "Services", "warning")
            return
        self._refresh_directory(entry.service_id)
        self.append(f"{action} {entry.kind.value} {entry.name!r} locally; "
                    "reachability was not checked.", "Services")

    @Slot()
    def _withdraw_directory_entry(self) -> None:
        """Withdraw one selected session-local publication."""
        identifier = self.directory_selector.currentData()
        if not isinstance(identifier, str):
            return
        try:
            entry = self.directory.withdraw(identifier)
        except KeyError as error:
            self.append(str(error), "Services", "warning")
            self._refresh_directory()
            return
        self._refresh_directory()
        self.append(f"Withdrew {entry.kind.value} {entry.name!r}.", "Services")

    def _refresh_directory(self, selected_id: str | None = None) -> None:
        """Project local plus cached catalog snapshots into desktop models."""
        snapshot = self.directory.snapshot()
        cached = self.service.remote_catalog.snapshot()
        local_ids = {entry.service_id for entry in snapshot.entries}
        extra = tuple(entry for entry in cached
                      if entry.service_id not in local_ids)
        combined = tuple(sorted(snapshot.entries + extra,
                                key=lambda entry: (
                                    entry.kind.value, entry.name.casefold(),
                                    entry.service_id)))
        cached_ids = frozenset((entry.owner_peer_id, entry.service_id)
                               for entry in extra)
        self.game_model.set_entries(combined, cached_ids)
        self.service_model.set_entries(combined, cached_ids)
        if selected_id is None:
            current = self.directory_selector.currentData()
            selected_id = current if isinstance(current, str) else None
        self.directory_selector.blockSignals(True)
        self.directory_selector.clear()
        self.directory_selector.addItem("New publication", None)
        for entry in snapshot.entries:
            self.directory_selector.addItem(
                f"{entry.kind.value.title()} · {entry.name}", entry.service_id)
        index = self.directory_selector.findData(selected_id)
        self.directory_selector.setCurrentIndex(max(0, index))
        self.directory_selector.blockSignals(False)
        self._load_directory_entry(self.directory_selector.currentIndex())
        self._update_directory_open()

    def _selected_directory_entry(self) -> DirectoryEntry | None:
        view = self.game_view if self.directory_tabs.currentIndex() == 0 else self.service_view
        model = self.game_model if view is self.game_view else self.service_model
        return model.entry_at(view.currentIndex().row())

    @Slot()
    def _update_directory_open(self) -> None:
        """Enable browser handoff only for a currently selected publication."""
        self.directory_open.setEnabled(self._selected_directory_entry() is not None)

    @Slot()
    def _open_directory_entry(self) -> None:
        """Open one validated URL without claiming endpoint availability."""
        entry = self._selected_directory_entry()
        if entry is None:
            return
        try:
            url = browser_url(entry)
        except ValueError as error:
            self.append(f"Service URL rejected: {error}", "Services", "warning")
            return
        if not QDesktopServices.openUrl(QUrl(url)):
            self.append("The platform browser did not accept the service URL.",
                        "Services", "warning")

    def _refresh_messages(self) -> None:
        """Project one canonical journal revision into the Qt message model."""
        snapshot = self.service.message_journal.snapshot()
        if snapshot.revision == self._message_revision:
            return
        current_row = self.message_view.currentIndex().row()
        selected_id = (self.message_model.entries[current_row].identifier
                       if 0 <= current_row < len(self.message_model.entries) else None)
        scroll = self.message_view.verticalScrollBar()
        old_scroll = scroll.value()
        follow_latest = old_scroll >= scroll.maximum() - 1
        self._message_revision = snapshot.revision
        entries = [MessageEntry(
            record.message_id,
            record.sender_name,
            record.text,
            "Nearby room" if record.scope == "room" else "Direct",
            self._message_state(record),
            record.direction == "outgoing",
            record.recorded_ms,
        ) for record in snapshot.entries]
        self.message_model.set_entries(entries)
        if selected_id is not None:
            row = next((index for index, entry in enumerate(entries)
                        if entry.identifier == selected_id), -1)
            if row >= 0:
                self.message_view.setCurrentIndex(self.message_model.index(row, 0))
        if entries and follow_latest:
            self.message_view.scrollToBottom()
        elif entries:
            scroll.setValue(min(old_scroll, scroll.maximum()))

    @staticmethod
    def _message_state(record: MessageRecord) -> str:
        """Summarize only locally observed delivery evidence."""
        if record.direction == "incoming":
            security = ("authenticated TLS" if record.authenticated
                        else "unverified plaintext")
            return f"Accepted by this application over {security}"
        counts = {state: sum(delivery.state == state
                             for delivery in record.deliveries)
                  for state in ("queued", "accepted", "failed", "uncertain")}
        parts = []
        if counts["accepted"]:
            authenticated = sum(
                delivery.state == "accepted" and delivery.authenticated
                for delivery in record.deliveries)
            plaintext = counts["accepted"] - authenticated
            if authenticated:
                parts.append(
                    f"{authenticated} accepted by receiving application over "
                    "authenticated TLS")
            if plaintext:
                parts.append(
                    f"{plaintext} accepted by receiving application over "
                    "unverified plaintext")
        if counts["failed"]:
            parts.append(f"{counts['failed']} failed")
        if counts["uncertain"]:
            parts.append(f"{counts['uncertain']} uncertain")
        if counts["queued"]:
            parts.append(f"{counts['queued']} queued")
        return "; ".join(parts) or "No recipient evidence"

    def append(self, text: str, category: str = "System",
               severity: str = "info") -> None:
        """Retain plain-text operational output and a structured Activity row."""
        cursor = self.log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text + "\n")
        self.log.setTextCursor(cursor)
        self.activity_model.append(ActivityEntry(datetime.now(), category, text,
                                                  severity=severity))
        if category == "Workbench" and hasattr(self, "workbench_log"):
            self.workbench_log.append(text)
        self.activity_view.scrollToBottom()
        self.overview_activity_stack.setCurrentWidget(self.overview_activity_view)
        self.overview_activity_view.scrollToBottom()

    @Slot()
    def _refresh_neighbors(self) -> None:
        try:
            self.inventory_request_id = self.service.diagnostics.refresh_neighbors()
        except RuntimeError as error:
            self.append(str(error), "Workbench", "warning")
            return
        self.refresh_neighbors_button.setEnabled(False)
        self.inventory_status.setText("Reading the operating system neighbor cache...")

    @Slot()
    def _ping_admin_target(self) -> None:
        self._queue_admin_probe("ping")

    @Slot()
    def _tcp_admin_target(self) -> None:
        self._queue_admin_probe("tcp")

    @Slot()
    def _echo_admin_target(self) -> None:
        self._queue_admin_probe("echo")

    def _probe_pill(self, kind: str, state: str, text: str) -> None:
        """Reflect one probe state on its tab pill without new states."""
        pill = {"ping": self.ping_pill, "tcp": self.tcp_pill,
                "echo": self.echo_pill}[kind]
        if state in {"reachable", "compatible", "refused"}:
            pill_state = "reachable" if state != "compatible" else "compatible"
        elif state == "running":
            pill_state = "nearby"
        else:
            pill_state = "offline"
        pill.set_state(pill_state)
        pill.setText(text)

    def _queue_admin_probe(self, kind: str) -> None:
        address = self.admin_address.text().strip()
        try:
            if kind == "ping":
                identifier = self.service.diagnostics.ping(
                    address, count=self.ping_params["count"].value(),
                    timeout=self.ping_params["timeout"].value(),
                    payload_size=self.ping_params["payload"].value())
            elif kind == "tcp":
                identifier = self.service.diagnostics.tcp_connect(
                    address, self.admin_port.value(),
                    timeout=self.tcp_params["timeout"].value(),
                    attempts=self.tcp_params["attempts"].value())
            else:
                device = self._selected_admin_device()
                record = self.service.peer_repository.get(
                    device.session_id if device is not None else None)
                if (device is None or "echo_v1" not in device.capabilities
                        or device.peer_id is None or device.session_id is None
                        or device.address != address
                        or device.port != self.admin_port.value()
                        or record is None or not record.nearby
                        or address not in record.candidate_ips()
                        or record.hello.tcp_port != self.admin_port.value()
                        or record.hello.peer_id != device.peer_id
                        or record.session_id != device.session_id
                        or "echo_v1" not in record.hello.capabilities):
                    raise ValueError(
                        "select an unchanged LAN Atlas session advertising echo_v1")
                identifier = self.service.diagnostics.echo(
                    address, self.admin_port.value(),
                    device.peer_id, device.session_id)
        except (RuntimeError, ValueError) as error:
            self.admin_address.setFocus()
            self.admin_result.setText(str(error))
            self.append(str(error), "Workbench", "warning")
            return
        device = self._selected_admin_device()
        if (device is not None and device.session_id is not None
                and device.address == address
                and (kind == "ping" or device.port == self.admin_port.value())):
            self.service.peer_repository.register_probe(
                identifier, device.session_id, address,
                None if kind == "ping" else self.admin_port.value(), kind)
        self.active_probe_id = identifier
        self.admin_ping_button.setEnabled(False)
        self.admin_tcp_button.setEnabled(False)
        self.admin_echo_button.setEnabled(False)
        self._probe_pill(kind, "running", "Running")
        self.admin_result.setText(f"{kind.upper()} check queued for {address}")

    @Slot()
    def _cancel_admin_probe(self) -> None:
        self.service.diagnostics.cancel()
        self.admin_cancel_button.setEnabled(False)
        self.admin_result.setText("Cancellation requested")

    @Slot(QModelIndex, QModelIndex)
    def _admin_device_selected(self, current: QModelIndex,
                               previous: QModelIndex = QModelIndex()) -> None:
        del previous
        device = self.admin_device_model.device_at(current.row())
        if device is None:
            return
        self.admin_address.setText(device.address)
        if device.port is not None:
            self.admin_port.setValue(device.port)
        self.admin_selection.setText(
            f"{device.label} · {device.source}\n{device.detail}")
        self._update_admin_probe_buttons()

    def _selected_admin_device(self) -> AdminDevice | None:
        return self.admin_device_model.device_at(
            self.admin_device_list.currentIndex().row())

    @Slot()
    def _update_admin_probe_buttons(self) -> None:
        idle = self.active_probe_id is None
        self.admin_ping_button.setEnabled(idle)
        self.admin_tcp_button.setEnabled(idle)
        device = self._selected_admin_device()
        self.admin_echo_button.setEnabled(
            idle and device is not None
            and "echo_v1" in device.capabilities
            and device.peer_id is not None and device.session_id is not None
            and device.address == self.admin_address.text().strip()
            and device.port == self.admin_port.value())

    def _rebuild_admin_devices(self) -> None:
        selected = self.admin_device_model.device_at(
            self.admin_device_list.currentIndex().row())
        selected_key = selected.key if selected is not None else None
        devices: list[AdminDevice] = []
        for record in self.peer_records:
            if not record.nearby:
                continue
            candidates = ([item.ip for item in record.endpoint_candidates]
                          if record.endpoint_candidates else [record.ip])
            for address in candidates:
                marker = "" if address == record.ip else " · alternate"
                devices.append(AdminDevice(
                    key=f"peer:{record.session_id}:{address}",
                    label=f"{record.hello.name} · {address}",
                    address=address, source="LAN Atlas HELLO",
                    detail=(f"Recent session; {peer_trust_label(record)}; "
                            "discovery not authenticated · "
                            f"{', '.join(record.hello.capabilities) or 'presence only'}"
                            f"{marker}"),
                    port=record.hello.tcp_port,
                    capabilities=record.hello.capabilities,
                    peer_id=record.hello.peer_id, session_id=record.session_id))
        devices.extend(AdminDevice(
            f"neighbor:{neighbor.interface or ''}:{neighbor.address}",
            f"Neighbor {neighbor.address}", neighbor.address, "OS neighbor cache",
            " · ".join(part for part in (
                f"MAC {neighbor.mac_address}" if neighbor.mac_address else "MAC unavailable",
                f"interface {neighbor.interface}" if neighbor.interface else "interface unavailable",
                f"state {neighbor.state}" if neighbor.state else "state unavailable") if part))
            for neighbor in self.neighbors)
        devices.sort(key=lambda item: (item.source != "LAN Atlas HELLO", item.label.lower(),
                                       item.address))
        self.admin_device_model.set_devices(tuple(devices))
        row = next((index for index, device in enumerate(devices)
                    if device.key == selected_key), -1)
        if row >= 0:
            self.admin_device_list.setCurrentIndex(
                self.admin_device_model.index(row, 0))
        elif selected_key is not None:
            self.admin_device_list.setCurrentIndex(QModelIndex())
        self._update_admin_probe_buttons()

    def _show_neighbor_snapshot(self, snapshot: NeighborSnapshot) -> None:
        if (self.inventory_request_id is not None
                and snapshot.request_id != self.inventory_request_id):
            return
        self.inventory_request_id = None
        self.refresh_neighbors_button.setEnabled(True)
        if snapshot.error:
            self.inventory_status.setText(f"Neighbor refresh unavailable: {snapshot.error}")
            self.append(f"Neighbor refresh unavailable: {snapshot.error}",
                        "Workbench", "warning")
            return
        self.neighbors = snapshot.entries
        event = self.service.peer_repository.apply_neighbor_snapshot(snapshot)
        if event is not None:
            self._apply_repository_event(event)
        self.inventory_status.setText(
            f"{len(snapshot.entries)} neighbor-cache entr"
            f"{'y' if len(snapshot.entries) == 1 else 'ies'} observed. "
            "Rows may be stale or incomplete.")
        self._rebuild_admin_devices()
        self.append(f"Observed {len(snapshot.entries)} OS neighbor-cache entries.",
                    "Workbench")

    def _show_probe_started(self, result: ProbeResult) -> None:
        if result.request_id != self.active_probe_id:
            return
        endpoint = (f"{result.address}:{result.port}"
                    if result.port is not None else result.address)
        self.admin_result.setText(f"Running {result.kind.upper()} check for {endpoint}...")
        self._probe_pill(result.kind, "running", "Running")
        self.admin_cancel_button.setEnabled(True)

    def _show_ping_stats(self, result: ProbeResult) -> None:
        """Fill ping rows and sparkline from measured samples only."""
        samples = result.rtt_samples
        replies = len(samples)
        self.ping_stats["Replies:"].setText(f"{replies}")
        self.ping_stats["Loss:"].setText(
            f"{result.loss_pct:.1f} %" if result.loss_pct is not None else "—")
        self.ping_stats["Min RTT:"].setText(
            f"{min(samples):.1f} ms" if samples else "—")
        self.ping_stats["Avg RTT:"].setText(
            f"{result.rtt_ms:.1f} ms" if result.rtt_ms is not None else "—")
        self.ping_stats["Max RTT:"].setText(
            f"{max(samples):.1f} ms" if samples else "—")
        self.ping_stats["Jitter:"].setText(
            f"{result.jitter_ms:.1f} ms" if result.jitter_ms is not None else "—")
        self.ping_stats["TTL:"].setText(
            str(result.ttl) if result.ttl is not None else "—")
        self.ping_sparkline.set_samples(list(samples))

    def _show_tcp_stats(self, result: ProbeResult) -> None:
        """Fill TCP handshake rows without claiming packet captures."""
        self.tcp_stats["Connect time:"].setText(
            f"{result.rtt_ms:.1f} ms" if result.rtt_ms is not None else "—")
        self.tcp_stats["Attempts:"].setText(result.detail or "—")

    def _show_echo_stats(self, result: ProbeResult) -> None:
        """Fill ECHO correlation rows from the validated exchange."""
        self.echo_stats["Correlation ID:"].setText(result.request_id[:12] + "…")
        self.echo_stats["Correlation ID:"].setToolTip(result.request_id)
        timing = ""
        if result.duration_ms is not None:
            timing = f"{result.duration_ms:.1f} ms operation"
        if result.rtt_ms is not None:
            timing += f" · {result.rtt_ms:.1f} ms round-trip"
        self.echo_stats["Timing:"].setText(timing or "—")
        self.echo_stats["Reply:"].setText(result.detail or "—")

    def _show_probe_result(self, result: ProbeResult) -> None:
        endpoint = (f"{result.address}:{result.port}"
                    if result.port is not None else result.address)
        duration = (f" · {result.duration_ms:.1f} ms local operation time"
                    if result.duration_ms is not None else "")
        rtt = (f" · measured latency {result.rtt_ms:.1f} ms via {result.kind}"
               if result.rtt_ms is not None else "")
        detail = f"\n{result.detail}" if result.detail else ""
        text = f"{result.kind.upper()} {endpoint}: {result.state}{duration}{rtt}{detail}"
        self.append(text.replace("\n", " · "), "Workbench",
                    "warning" if result.state not in {"reachable", "compatible"} else "info")
        if result.request_id != self.active_probe_id:
            return
        self.active_probe_id = None
        self.admin_result.setText(text)
        self._probe_pill(result.kind, result.state, result.state.title())
        if result.kind == "ping":
            self._show_ping_stats(result)
        elif result.kind == "tcp":
            self._show_tcp_stats(result)
        else:
            self._show_echo_stats(result)
        self.admin_cancel_button.setEnabled(False)
        self._update_admin_probe_buttons()

    @Slot()
    def send(self) -> None:
        """Queue a room or direct message without blocking the GUI."""
        text = self.input.text()
        selected = self.recipient.currentData()
        if self._queue_internet_action(selected, "send", text):
            return
        peers = tuple(record.as_peer()
                      for record in self.service.peer_repository.supporting("chat_v1")
                      if selected is None or record.session_id == selected)
        direct = selected is not None
        try:
            self.service.send(text, peers, direct)
        except (ValueError, RuntimeError) as error:
            self.append(str(error), "Messages", "warning")
            return
        self._refresh_messages()
        self.input.clear()

    @Slot()
    def drain(self) -> None:
        """Consume a bounded event batch so network load cannot starve Qt."""
        for _ in range(64):
            try:
                kind, value = self.service.events.get_nowait()
            except Empty:
                break
            if kind == "peer_repository":
                self._apply_repository_event(value)
            elif kind == "roster":
                self._update_roster(tuple(value))
            elif kind in {"transfer", "file_offer"}:
                if kind == "file_offer":
                    value = {**value, "state": "offer_pending", "total": value["size"]}
                    security = ("authenticated TLS" if value.get("authenticated")
                                else "unverified plaintext")
                    self.append(
                        f"Incoming file offer {value['name']!r}, {value['size']} bytes "
                        f"from peer {value['peer_id'][:8]}… over {security}",
                        "Transfers", "info" if value.get("authenticated") else "warning")
                self.update_transfer(value)
            elif kind == "pair_request":
                self._show_pair_request(value)
            elif kind == "pair_outbound":
                self._show_pair_outbound(value)
            elif kind == "feed_updated":
                suffix = "; more pages available" if value.get("partial") else ""
                self.append(f"Feed sync: {value['added']} added, "
                            f"{value['duplicates']} duplicates{suffix}", "Feed")
                self.refresh_feed()
            elif kind == "post_published":
                self.refresh_feed()
            elif kind == "directory_updated":
                suffix = "; more pages available" if value.get("partial") else ""
                security = ("authenticated TLS" if value.get("authenticated")
                            else "unverified plaintext")
                self.append(f"Directory sync: {value['added']} added, "
                            f"{value['duplicates']} duplicates over {security}"
                            f"{suffix}", "Services")
                self._refresh_directory()
            elif kind == "neighbor_snapshot":
                self._show_neighbor_snapshot(value)
            elif kind == "diagnostic_started":
                self._show_probe_started(value)
            elif kind == "diagnostic_result":
                event = self.service.peer_repository.apply_probe_result(value)
                if event is not None:
                    self._apply_repository_event(event)
                self._show_probe_result(value)
            else:
                text = str(value)
                if text.startswith("TCP listener stopped"):
                    self.network_status.setText("Network stopped")
                elif text.startswith("Discovery stopped"):
                    self.network_status.setText("Discovery unavailable")
                self.append(text, "Network",
                            "warning" if any(word in text.lower()
                                             for word in ("failed", "stopped")) else "info")
        self.service.flush_repository_events()
        self._drain_internet_actions()
        self._refresh_messages()
        now = time.monotonic()
        if now >= self._next_presence_refresh:
            self._next_presence_refresh = now + 1.0
            self._refresh_portal_state()
            self._refresh_forwarder_state()
            self.peer_model.refresh_ages()
            self.peer_table_model.refresh_ages()
            record = self._selected_record()
            if record is not None:
                self._show_peer(record)

    def _update_roster(self, peers: tuple[Peer, ...]) -> None:
        """Adapt legacy active-roster events into the canonical repository."""
        event = self.service.peer_repository.reconcile_presence(peers, time.monotonic())
        if event is not None:
            self._apply_repository_event(event)

    def _apply_repository_event(self, event: PeerRepositoryEvent) -> None:
        """Ignore delayed revisions so older evidence cannot replace newer state."""
        if event.revision <= self._peer_revision:
            return
        self._peer_revision = event.revision
        self._update_peer_records(event.snapshot)

    def _update_peer_records(self, records: tuple[PeerRecord, ...]) -> None:
        """Render one immutable repository snapshot across all peer surfaces."""
        previous_count = sum(record.nearby for record in self.peer_records)
        previous_trust = {
            record.hello.peer_id: record.trust_state
            for record in self.peer_records}
        message_selected = self.recipient.currentData()
        feed_selected = self.feed_peer.currentData()
        directory_selected = self.directory_peer.currentData()
        self.peer_records = records
        nearby = tuple(record for record in records if record.nearby)
        self.peer_model.set_records(nearby)
        self.peer_table_model.set_records(records)
        self._rebuild_admin_devices()
        self.topology.set_records(nearby)
        self.overview_topology.set_records(nearby)
        self.overview_nearby_stack.setCurrentWidget(
            self.overview_peer_list if nearby else self.overview_nearby_empty)
        self._rebuild_message_recipients(message_selected)
        self._rebuild_feed_peers(feed_selected)
        self._rebuild_directory_peers(directory_selected)
        self.peer_selection.reconcile({record.session_id for record in records})
        if self.peer_selection.session_id is None and records:
            self.peer_selection.select(records[0].session_id)
        else:
            self._sync_peer_selection(self.peer_selection.session_id)
        self._filter_devices(self.device_search.text())
        self._refresh_device_tab_counts(records)
        self._show_peer(self._record_in_snapshot(self.peer_selection.session_id))
        self.nearby_status.setText(f"{len(nearby)} sessions nearby")
        self.network_status.setText("Discovery active · application listener configured")
        stale_count = len(records) - len(nearby)
        paired_count = sum(
            record.trust_state is TrustState.PAIRED for record in records)
        self.footer_right.setText(
            f"{len(nearby)} nearby · {stale_count} stale · "
            f"{paired_count} paired key(s) · Unverified LAN")
        self._refresh_trust_summary()
        self.nearby_value.setText(str(len(nearby)) if nearby else "Searching...")
        capabilities = {item for record in nearby for item in record.hello.capabilities}
        self.capability_value.setText(str(len(capabilities)) if nearby else "Waiting")
        self.network_observed_value.setText(str(len(nearby)))
        self.network_capability_value.setText(str(len(capabilities)))
        summary = self.service.peer_repository.overview_summary()
        if not records:
            self.overview_summary.setText("Searching your LAN for observed hosts...")
            self.overview_rtt.setText("Measured latency: none yet")
        else:
            self.overview_summary.setText(
                f"{summary.observed} observed hosts · "
                f"{summary.responsive} responsive · "
                f"{summary.stale} offline")
            if summary.measured and summary.min_ms is not None:
                self.overview_rtt.setText(
                    f"Measured latency: min {summary.min_ms:.1f} ms · "
                    f"avg {summary.avg_ms:.1f} ms · "
                    f"max {summary.max_ms:.1f} ms "
                    f"({summary.measured} of {summary.nearby} nearby)")
            else:
                self.overview_rtt.setText(
                    "Measured latency: none yet — run Ping, TCP, or ECHO")
        refresh_distribution(self.overview_sparkline, self.overview_breakdown,
                             nearby, summary)
        if len(nearby) != previous_count:
            self.append(f"Nearby roster now contains {len(nearby)} active session(s).",
                        "Discovery")
        names = {record.hello.peer_id: record.hello.name for record in records}
        names[self.service.hello.peer_id] = self.service.hello.name
        self.post_model.set_author_names(names)
        current_trust = {
            record.hello.peer_id: record.trust_state for record in records}
        if current_trust != previous_trust:
            self.refresh_feed()

    def _rebuild_internet_entries(self, combo: QComboBox, capability: str,
                                  selected: object) -> None:
        """Append address book entries advertising one capability."""
        for entry in self.service.address_book.snapshot():
            if capability not in entry.capabilities:
                continue
            combo.addItem(f"Internet · {entry.label} · {entry.host}",
                          ("inet", entry.peer_id))
        if selected is not None:
            index = combo.findData(selected)
            if index >= 0:
                combo.setCurrentIndex(index)

    def _rebuild_message_recipients(self, selected: object) -> None:
        self.recipient.blockSignals(True)
        self.recipient.clear()
        self.recipient.addItem("Nearby room · all discovered chat sessions", None)
        for record in self.peer_records:
            if not record.nearby or "chat_v1" not in record.hello.capabilities:
                continue
            security = ("Paired TLS" if record.trust_state is TrustState.PAIRED
                        else "Key changed; blocked"
                        if record.trust_state is TrustState.KEY_CHANGED
                        else "Legacy plaintext")
            self.recipient.addItem(
                f"Direct · {record.hello.name} · {record.ip} · {security}",
                record.session_id)
        self._rebuild_internet_entries(self.recipient, "chat_v1", selected)
        index = self.recipient.findData(selected)
        if selected is not None and index < 0:
            self.recipient.addItem("Selected session is no longer nearby", selected)
            index = self.recipient.count() - 1
        self.recipient.setCurrentIndex(max(0, index))
        self.recipient.blockSignals(False)

    def _rebuild_directory_peers(self, selected: object) -> None:
        self.directory_peer.clear()
        self.directory_peer.addItem("Select one directory-capable peer", None)
        for record in self.peer_records:
            if not record.nearby or "directory_v1" not in record.hello.capabilities:
                continue
            self.directory_peer.addItem(
                f"{record.hello.name} · {record.ip}", record.session_id)
        self._rebuild_internet_entries(
            self.directory_peer, "directory_v1", selected)
        index = self.directory_peer.findData(selected)
        self.directory_peer.setCurrentIndex(max(0, index))

    @Slot(str)
    def _mark_draft_changed(self, text: str) -> None:
        self._draft_revision += 1

    def _queue_internet_action(self, data: object, action: str,
                               text: str = "") -> bool:
        """Capture an Internet action; return False only for LAN selections."""
        if (not isinstance(data, tuple) or len(data) != 2
                or data[0] != "inet" or not isinstance(data[1], str)):
            return False
        capability, category = INTERNET_ACTIONS[action]
        if any(item.peer_id == data[1] and item.action == action
               for item in self._pending_internet.values()):
            self.append("Internet action already resolving; wait for its result.",
                        category)
            return True
        try:
            entry = self.service.address_book.get(data[1])
            if entry is None:
                raise ValueError("no address book entry for peer")
            if capability not in entry.capabilities:
                raise ValueError(f"Selected entry does not advertise {capability}.")
            if action == "send":
                envelope("CHAT", self.service.hello.peer_id,
                         self.service.hello.session_id,
                         {"scope": "room", "text": text})
            token = self.service.dial_peer_async(data[1])
        except (ValueError, RuntimeError) as error:
            self.append(str(error), category, "warning")
            return True
        self._pending_internet[token] = _PendingInternet(
            data[1], action, text, self._draft_revision)
        self.append(f"Resolving {entry.label} for {category.lower()}...", category)
        return True

    def _drain_internet_actions(self) -> None:
        for token, pending in tuple(self._pending_internet.items()):
            if token not in self._pending_internet:
                continue
            category = INTERNET_ACTIONS[pending.action][1]
            try:
                peer = self.service.take_dial_result(token)
                if peer is None:
                    continue
                del self._pending_internet[token]
                if pending.action == "send":
                    self.service.send(pending.text, (peer,), True)
                    if (self._draft_revision == pending.draft_revision
                            and self.recipient.currentData()
                            == ("inet", pending.peer_id)):
                        self.input.clear()
                elif pending.action == "file":
                    self._send_file_to_peer(peer)
                elif pending.action == "feed":
                    identifier = self.service.sync_posts(peer)
                    self.append(f"Feed sync {identifier[:8]}… queued from "
                                f"{peer.hello.name}.", category)
                elif pending.action == "directory":
                    identifier = self.service.sync_directory(peer)
                    self.append(f"Directory sync {identifier[:8]}… queued from "
                                f"{peer.hello.name}.", category)
            except (OSError, ValueError, RuntimeError) as error:
                self._pending_internet.pop(token, None)
                self.append(str(error), category, "warning")

    def _refresh_internet_list(self) -> None:
        """Render address book entries with live paired state."""
        transport = self.service.secure_transport
        self.internet_session.blockSignals(True)
        self.internet_session.clear()
        self.internet_session.addItem("Select one paired session", None)
        for record in self.peer_records:
            if not record.nearby or record.trust_state is not TrustState.PAIRED:
                continue
            self.internet_session.addItem(
                f"{record.hello.name} · {record.ip}", record.hello.peer_id)
        self.internet_session.blockSignals(False)
        self.internet_list.clear()
        for entry in self.service.address_book.snapshot():
            record = (transport.trust_store.get(entry.peer_id)
                      if transport is not None else None)
            if record is None:
                state = "Unpaired · dial blocked"
            elif record.fingerprint != entry.fingerprint:
                state = "Key changed · re-add entry"
            else:
                state = "Paired"
            item = QListWidgetItem(
                f"{entry.label} · {entry.host}:{entry.port} · {state}")
            item.setData(Qt.ItemDataRole.UserRole, entry.peer_id)
            self.internet_list.addItem(item)

    @Slot()
    def _add_internet_peer(self) -> None:
        """Bind one paired session to an explicit Internet dial target."""
        transport = self.service.secure_transport
        peer_id = self.internet_session.currentData()
        if not isinstance(peer_id, str) or transport is None:
            self.append("Select one paired session before adding an entry.",
                        "Network", "warning")
            return
        record = next((item for item in self.peer_records
                       if item.hello.peer_id == peer_id and item.nearby), None)
        trust = transport.trust_store.get(peer_id)
        if record is None or trust is None:
            self.append("Entry peers must be paired; pair on LAN first.",
                        "Network", "warning")
            return
        host = self.internet_host.text().strip()
        label = self.internet_label.text().strip() or record.hello.name
        self._add_internet_entry(peer_id, label, host,
                                 self.internet_port.value(),
                                 record.hello.capabilities,
                                 trust.fingerprint)

    def _add_internet_entry(self, peer_id: str, label: str, host: str,
                            port: int, capabilities: tuple[str, ...],
                            fingerprint: str) -> None:
        """Persist one dial entry and refresh every peer surface."""
        try:
            self.service.address_book.add(
                peer_id, label, host, port, capabilities, fingerprint)
        except ValueError as error:
            self.append(f"Entry rejected: {error}", "Network", "warning")
            return
        self._refresh_internet_list()
        self._update_peer_records(self.peer_records)
        self.append(f"Internet entry {label!r} added.", "Network")

    @Slot()
    def _toggle_rendezvous(self) -> None:
        """Publish or withdraw this session's signed rendezvous entry."""
        if self._rv_registered:
            self.service.rendezvous_stop()
            self._rv_registered = False
            self.rv_register.setText("Register")
            self.append("Rendezvous registration withdrawn.", "Network")
            return
        server = self.rv_host.text().strip()
        ext_host = self.internet_host.text().strip()
        if not server or not ext_host:
            self.append("Enter a rendezvous server and the address to announce.",
                        "Network", "warning")
            return
        try:
            self.service.rendezvous_register(
                server, self.rv_port.value(), ext_host,
                self.internet_port.value(), self.rv_secure_port.value())
        except (ValueError, RuntimeError) as error:
            self.append(f"Registration failed: {error}", "Network", "warning")
            return
        self._rv_registered = True
        self.rv_register.setText("Withdraw")
        self.append(f"Announcing {ext_host} to rendezvous {server}.",
                    "Network")

    @Slot()
    def _reserve_relay(self) -> None:
        """Hold one relay allocation and show its single-use token."""
        host = self.relay_host.text().strip()
        if not host:
            self.append("Enter a relay server before reserving a slot.",
                        "Network", "warning")
            return
        try:
            token = self.service.relay_reserve(host, self.relay_port.value())
        except (ValueError, RuntimeError, OSError) as error:
            self.append(f"Reservation failed: {error}", "Network", "warning")
            return
        self.relay_token.setText(token)
        self.append("Relay slot reserved; share the token like a code. "
                    "One token carries one message.", "Network")

    @Slot()
    def _send_via_relay(self) -> None:
        """Send the message input as one DM through a relay token."""
        selected = self.recipient.currentData()
        if (not isinstance(selected, tuple) or len(selected) != 2
                or selected[0] != "inet"):
            self.append("Select one Internet peer before sending via relay.",
                        "Transfers", "warning")
            return
        token = self.relay_token.text().strip()
        host = self.relay_host.text().strip()
        if not token or not host:
            self.append("Enter a relay server and token first.",
                        "Transfers", "warning")
            return
        try:
            identifier = self.service.relay_send(
                selected[1], host, self.relay_port.value(), token,
                self.input.text())
        except (ValueError, RuntimeError) as error:
            self.append(str(error), "Transfers", "warning")
            return
        self._refresh_messages()
        self.input.clear()
        self.append(f"Relay DM {identifier[:8]}… queued.", "Transfers")

    @Slot()
    def _lookup_rendezvous(self) -> None:
        """Fetch one rendezvous page with per-entry trust verification."""
        server = self.rv_host.text().strip()
        if not server:
            self.append("Enter a rendezvous server before looking up peers.",
                        "Network", "warning")
            return
        try:
            results = self.service.rendezvous_lookup(
                server, self.rv_port.value())
        except (ValueError, RuntimeError) as error:
            self.append(f"Lookup failed: {error}", "Network", "warning")
            return
        self.rv_results.clear()
        for entry, trusted in results:
            state = "Verified paired peer" if trusted else "Unverified hint"
            item = QListWidgetItem(
                f"{entry.get('name')} · {entry.get('host')}:"
                f"{entry.get('secure_port')} · {state}")
            item.setData(Qt.ItemDataRole.UserRole, (entry, trusted))
            self.rv_results.addItem(item)
        self.append(f"Rendezvous lookup returned {len(results)} entries.",
                    "Network")

    @Slot()
    def _add_rendezvous_result(self) -> None:
        """Add one verified lookup result as a dial entry."""
        item = self.rv_results.currentItem()
        data = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if not isinstance(data, tuple) or len(data) != 2:
            return
        entry, trusted = data
        if not trusted:
            self.append("Result is unverified; pair on LAN first.",
                        "Network", "warning")
            return
        from core.rendezvous import verify_announcement
        transport = self.service.secure_transport
        record = (transport.trust_store.get(entry["peer_id"])
                  if transport is not None else None)
        try:
            fresh, _reason = verify_announcement(
                entry, record.fingerprint if record is not None else None)
        except (ValueError, TypeError, AttributeError):
            fresh = False
        if not fresh or record is None:
            self.append("Result no longer verifies; look up again.",
                        "Network", "warning")
            return
        self._add_internet_entry(
            entry["peer_id"], str(entry.get("name") or "Peer"),
            str(entry["host"]), int(entry["secure_port"]),
            tuple(entry.get("capabilities") or ()), record.fingerprint)

    @Slot()
    def _remove_internet_peer(self) -> None:
        """Forget one explicit dial entry without touching paired trust."""
        item = self.internet_list.currentItem()
        peer_id = (item.data(Qt.ItemDataRole.UserRole)
                   if item is not None else None)
        if not isinstance(peer_id, str):
            return
        if self.service.address_book.remove(peer_id):
            self._refresh_internet_list()
            self._update_peer_records(self.peer_records)
            self.append("Internet entry removed.", "Network", "warning")

    @Slot()
    def _sync_directory(self) -> None:
        """Queue a catalog sync from the explicitly selected capable peer."""
        selected = self.directory_peer.currentData()
        if self._queue_internet_action(selected, "directory"):
            return
        record = self.service.peer_repository.get(
            selected if isinstance(selected, str) else None)
        if (record is None or not record.nearby
                or "directory_v1" not in record.hello.capabilities):
            self.append("Select one directory-capable peer before syncing.",
                        "Services", "warning")
            return
        peer = record.as_peer()
        name = record.hello.name
        try:
            identifier = self.service.sync_directory(peer)
        except (ValueError, RuntimeError) as error:
            self.append(str(error), "Services", "warning")
            return
        self.append(f"Directory sync {identifier[:8]}… queued from "
                    f"{name}.", "Services")

    def _rebuild_feed_peers(self, selected: object) -> None:
        self.feed_peer.clear()
        self.feed_peer.addItem("Select one posts-capable peer", None)
        for record in self.peer_records:
            if not record.nearby or "posts_v1" not in record.hello.capabilities:
                continue
            security = ("Paired TLS" if record.trust_state is TrustState.PAIRED
                        else "Key changed; blocked"
                        if record.trust_state is TrustState.KEY_CHANGED
                        else "Legacy plaintext")
            self.feed_peer.addItem(
                f"{record.hello.name} · {record.ip} · {security}",
                record.session_id)
        self._rebuild_internet_entries(self.feed_peer, "posts_v1", selected)
        index = self.feed_peer.findData(selected)
        self.feed_peer.setCurrentIndex(max(0, index))

    @Slot(object)
    def _sync_peer_selection(self, session_id: object) -> None:
        """Render one shared selected session across every peer surface."""
        selected = session_id if isinstance(session_id, str) else None
        record = self._record_in_snapshot(selected)
        row = next((index for index, item in enumerate(self.peer_records)
                    if item.session_id == selected), -1)
        index = self.peer_table_model.index(row, 0) if row >= 0 else QModelIndex()
        self.peer_list.setCurrentIndex(index)
        overview_row = next(
            (index for index, item in enumerate(self.peer_model.records)
             if item.session_id == selected), -1)
        overview_index = (self.peer_model.index(overview_row, 0)
                          if overview_row >= 0 else QModelIndex())
        self.overview_peer_list.setCurrentIndex(overview_index)
        self._show_peer(record)
        self.topology.select_session(selected)
        self.overview_topology.select_session(selected)
        pill = state_pill_for(record)
        self.overview_state_pill.set_state(pill.state())
        trust = trust_pill(record)
        self.overview_trust_pill.set_state(trust.state())
        self.overview_trust_pill.setText(trust.text())
        if record is None:
            self.overview_peer_name.setText("No session selected")
            for value in (self.overview_peer_endpoint,
                          self.overview_peer_installation,
                          self.overview_peer_session):
                value.setText("—")
                value.setToolTip("")
            self.overview_peer_state.setText("No session selected")
            self.overview_peer_caps.setText("Presence only")
            self.overview_peer_rtt.setText("Measured latency: none yet")
            self.overview_state_pill.setText("No selection")
            self.overview_trust_pill.setToolTip(
                "Select one session to inspect its stored key evidence.")
            self.network_selected_name.setText("No session selected")
            for value in (self.network_selected_endpoint,
                          self.network_selected_session):
                value.setText("—")
                value.setToolTip("")
            self.network_selected_state.setText("No session selected")
            self.network_state_pill.set_state("offline")
            self.network_state_pill.setText("No selection")
            self.network_selected_caps.setText("Presence only")
            return
        labels = [capability_label(item) for item in record.hello.capabilities]
        self.overview_peer_name.setText(record.hello.name)
        self.overview_peer_endpoint.setText(endpoint_label(record))
        self.overview_peer_endpoint.setToolTip(
            ", ".join(record.candidate_ips()))
        self.overview_peer_installation.setText(f"{record.hello.peer_id[:12]}…")
        self.overview_peer_installation.setToolTip(record.hello.peer_id)
        self.overview_peer_session.setText(f"{record.session_id[:12]}…")
        self.overview_peer_session.setToolTip(record.session_id)
        trust_text = peer_trust_label(record)
        self.overview_peer_state.setText(
            f"{pill_display_text(pill.state())} · {trust_text}")
        self.overview_trust_pill.setToolTip(self._trust_explanation(record))
        self.overview_peer_caps.setText("  ·  ".join(labels) or "Presence only")
        self.overview_state_pill.setText(pill.text())
        if record.latency_ms is None:
            self.overview_peer_rtt.setText("Measured latency: none yet")
        else:
            source = f" via {record.latency_source}" if record.latency_source else ""
            self.overview_peer_rtt.setText(
                f"Measured latency: {record.latency_ms:.1f} ms{source}")
        self.network_selected_name.setText(record.hello.name)
        self.network_selected_endpoint.setText(endpoint_label(record))
        self.network_selected_endpoint.setToolTip(
            ", ".join(record.candidate_ips()))
        self.network_selected_session.setText(f"{record.session_id[:12]}…")
        self.network_selected_session.setToolTip(record.session_id)
        self.network_selected_state.setText(
            f"{pill_display_text(pill.state())} · {trust_text}")
        self.network_state_pill.set_state(pill.state())
        self.network_state_pill.setText(pill.text())
        self.network_selected_caps.setText("  ·  ".join(labels) or "Presence only")

    @Slot(QModelIndex, QModelIndex)
    def _peer_selected(self, current: QModelIndex,
                       previous: QModelIndex = QModelIndex()) -> None:
        del previous
        record = self.peer_table_model.record_at(current.row())
        if record is not None:
            self.peer_selection.select(record.session_id)

    def _show_peer(self, record: PeerRecord | None) -> None:
        if record is None:
            self.peer_name.setText("Select a nearby session")
            self.peer_presence.setText("No peer selected")
            self.peer_state_pill.set_state("offline")
            self.peer_state_pill.setText("No selection")
            self.peer_endpoint.setText("Endpoint: —")
            for value in (self.peer_installation, self.peer_session):
                value.setText("—")
                value.setToolTip("")
            for widget in (self.device_identity_panel,
                           self.device_evidence_panel,
                           self.peer_capabilities, self.peer_services,
                           self.peer_warning):
                widget.setVisible(False)
            self.peer_host.setText("Hostname: Not advertised")
            self.peer_platform.setText("Platform / architecture: Not advertised")
            self.peer_mac.setText("MAC address: Not observed")
            self.peer_latency.setText("Latency: Not measured")
            self.peer_capabilities.setText("Presence only")
            self.peer_services.setText("Advertised / detected services: None observed")
            self.peer_nearby_evidence.setText("○ Nearby        No session selected")
            self.peer_reachable_evidence.setText("○ Reachable     Not tested")
            self.peer_compatible_evidence.setText("○ Compatible    Not tested")
            self.peer_trust_evidence.setText("◇ Paired key    Not established")
            for button in (self.peer_message_button, self.peer_file_button,
                           self.peer_sync_button, self.peer_ping_button,
                           self.peer_tcp_button, self.peer_copy_button,
                           self.peer_probe_button, self.peer_pair_button,
                           self.peer_forget_button):
                button.setEnabled(False)
            return
        age = max(0.0, time.monotonic() - record.last_seen)
        state = "Nearby" if record.nearby else "Offline / stale"
        self.peer_name.setText(record.hello.name)
        self.peer_presence.setText(f"{state} · last announcement {age:.1f} seconds ago")
        self.peer_endpoint.setText(
            f"Observed endpoint: {endpoint_label(record)}")
        self.peer_installation.setText(f"{record.hello.peer_id[:12]}…")
        self.peer_installation.setToolTip(record.hello.peer_id)
        self.peer_session.setText(f"{record.session_id[:12]}…")
        self.peer_session.setToolTip(record.session_id)
        device_pill = state_pill_for(record)
        self.peer_state_pill.set_state(device_pill.state())
        self.peer_state_pill.setText(device_pill.text())
        for widget in (self.device_identity_panel,
                       self.device_evidence_panel,
                       self.peer_capabilities, self.peer_services,
                       self.peer_warning):
            widget.setVisible(True)
        self.peer_host.setText(f"Hostname: {record.hostname or 'Not advertised'}")
        platform = " / ".join(part for part in (record.platform, record.architecture)
                              if part)
        self.peer_platform.setText(
            f"Platform / architecture: {platform or 'Not advertised'}")
        mac = record.mac_address or "Not observed"
        source = f" · {record.mac_source}" if record.mac_source else ""
        self.peer_mac.setText(f"MAC address: {mac}{source}")
        if record.latency_ms is None:
            latency = "Not measured"
        else:
            source = f" via {record.latency_source}" if record.latency_source else ""
            latency = f"{record.latency_ms:.1f} ms{source}"
        self.peer_latency.setText(f"Latency: {latency}")
        labels = [capability_label(item) for item in record.hello.capabilities]
        self.peer_capabilities.setText("  ·  ".join(labels) or "Presence only")
        self.peer_services.setText(
            "Advertised / detected services: "
            + (", ".join(record.services) if record.services else "None observed"))
        self.peer_nearby_evidence.setText(
            "● Nearby        Recent HELLO observed" if record.nearby
            else "○ Nearby        HELLO expired; retained as stale")
        reachable = record.reachability_state.value.replace("_", " ").title()
        compatible = record.compatibility_state.value.replace("_", " ").title()
        self.peer_reachable_evidence.setText(f"○ Reachable     {reachable}")
        self.peer_compatible_evidence.setText(f"○ Compatible    {compatible}")
        trust_text = peer_trust_label(record)
        self.peer_trust_evidence.setText(f"◇ Paired key    {trust_text}")
        fingerprint = record.hello.certificate_sha256
        fingerprint_line = (
            f"\nAdvertised certificate: {fingerprint}" if fingerprint is not None
            else "\nNo certificate fingerprint advertised by this session.")
        has_ipv4 = _has_ipv4_endpoint(record)
        transport_note = (
            "" if has_ipv4 else
            "\nApplication messaging, files, and probes need an IPv4 endpoint "
            "on this build; this session is IPv6 discovery only.")
        self.peer_warning.setText(
            f"Cryptographic Trust: {trust_text}\n"
            f"{self._trust_explanation(record)}{transport_note}"
            f"{fingerprint_line}")
        live = record.nearby
        secure_capable = "secure_transport_v1" in record.hello.capabilities
        transport_allowed = (
            record.trust_state is not TrustState.KEY_CHANGED
            and (record.trust_state is not TrustState.PAIRED or secure_capable))
        self.peer_message_button.setEnabled(
            live and has_ipv4 and transport_allowed
            and "chat_v1" in record.hello.capabilities)
        self.peer_file_button.setEnabled(
            live and has_ipv4 and transport_allowed
            and "file_v1" in record.hello.capabilities)
        self.peer_sync_button.setEnabled(
            live and has_ipv4 and transport_allowed
            and "posts_v1" in record.hello.capabilities)
        self.peer_ping_button.setEnabled(live and has_ipv4)
        self.peer_tcp_button.setEnabled(live and has_ipv4)
        self.peer_copy_button.setEnabled(True)
        self.peer_probe_button.setEnabled(live and has_ipv4)
        self.peer_pair_button.setEnabled(
            live and has_ipv4 and self.service.secure_transport is not None
            and secure_capable
            and record.trust_state is TrustState.UNVERIFIED)
        self.peer_forget_button.setEnabled(
            self.service.secure_transport is not None
            and record.trust_state is not TrustState.UNVERIFIED)

    def _selected_record(self) -> PeerRecord | None:
        return self._record_in_snapshot(self.peer_selection.session_id)

    def _record_in_snapshot(self, session_id: str | None) -> PeerRecord | None:
        """Return one record from the latest revision accepted by the UI."""
        return next((record for record in self.peer_records
                     if record.session_id == session_id), None)

    def _selected_peer(self) -> Peer | None:
        record = self.service.peer_repository.get(self.peer_selection.session_id)
        return record.as_peer() if record is not None and record.nearby else None

    @staticmethod
    def _trust_explanation(record: PeerRecord) -> str:
        """Describe stored trust separately from current connection evidence."""
        secure_capable = "secure_transport_v1" in record.hello.capabilities
        if record.trust_state is TrustState.KEY_CHANGED:
            return (
                "The advertised certificate differs from the pinned key. "
                "Application connections are blocked; verify the device out-of-band "
                "before forgetting the old key.")
        if record.trust_state is TrustState.PAIRED:
            if not secure_capable:
                return (
                    "A certificate is pinned, but this session does not advertise secure "
                    "transport. Application connections are blocked without downgrade.")
            return (
                "A certificate is pinned. Each chat, feed, or file connection must still "
                "authenticate that key over TLS; discovery is not authenticated.")
        if secure_capable:
            return (
                "No authenticated device identity has been established. Until explicitly "
                "paired, chat, feed, and file connections use legacy plaintext.")
        return (
            "No authenticated device identity has been established. This legacy session's "
            "chat, feed, and file connections are plaintext.")

    def _refresh_trust_summary(self) -> None:
        transport = self.service.secure_transport
        count = (len(transport.trust_store.snapshot().records)
                 if transport is not None else 0)
        self.settings_trust.setText(f"{count} pinned certificate(s)")

    def _pair_selected_peer(self) -> None:
        peer = self._selected_peer()
        record = self._selected_record()
        if (peer is None or record is None
                or record.trust_state is not TrustState.UNVERIFIED
                or "secure_transport_v1" not in record.hello.capabilities):
            return
        try:
            queued = self.service.request_pair(peer)
        except (RuntimeError, ValueError) as error:
            self.append(f"Pairing request failed: {error}", "Security", "warning")
            return
        if queued:
            self.append(
                f"Pairing request queued for {record.hello.name}. Compare the code "
                "shown on both devices before the remote user accepts.", "Security")

    def _forget_selected_peer(self) -> None:
        record = self._selected_record()
        if (record is None
                or record.trust_state is TrustState.UNVERIFIED):
            return
        answer = QMessageBox.question(
            self, "Forget paired key",
            f"Forget the pinned certificate for {record.hello.name}?\n\n"
            "Future connections will be allowed over legacy plaintext until the device "
            "is paired again.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            forgotten = self.service.forget_pair(record.hello.peer_id)
        except (RuntimeError, ValueError) as error:
            self.append(f"Could not forget paired key: {error}",
                        "Security", "warning")
            return
        if forgotten:
            self._refresh_trust_summary()
            self.append(f"Forgot the pinned key for {record.hello.name}.",
                        "Security", "warning")

    def _show_pair_request(self, candidate: PairingCandidate) -> None:
        source = (f"Source endpoint: {candidate.source_ip}\n\n"
                  if candidate.source_ip else "")
        answer = QMessageBox.question(
            self, "Incoming pairing request",
            f"{candidate.name} requests certificate pairing.\n\n"
            f"{source}"
            f"Comparison code: {candidate.comparison_code}\n\n"
            "Accept only after the same code is confirmed on the other device.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        try:
            if answer == QMessageBox.StandardButton.Yes:
                accepted = self.service.accept_pair(candidate.request_id)
                self._refresh_trust_summary()
                self.append(
                    f"Pinned {accepted.name}'s certificate after explicit approval.",
                    "Security")
            else:
                declined = self.service.decline_pair(candidate.request_id)
                self.append(f"Declined pairing from {declined.name}.",
                            "Security", "warning")
        except (RuntimeError, SecureTransportError, ValueError) as error:
            self.append(f"Pairing decision failed: {error}",
                        "Security", "warning")

    def _show_pair_outbound(self, candidate: PairingCandidate) -> None:
        answer = QMessageBox.question(
            self, "Pairing request sent",
            f"Comparison code for {candidate.name}:\n\n"
            f"{candidate.comparison_code}\n\n"
            "Pin this certificate only after confirming the same code on the other "
            "device. Its user must also accept.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        try:
            if answer == QMessageBox.StandardButton.Yes:
                accepted = self.service.accept_outbound_pair(
                    candidate.request_id)
                self._refresh_trust_summary()
                self.append(
                    f"Pinned the selected certificate for {accepted.name}; remote "
                    "approval is also required.", "Security")
            else:
                declined = self.service.decline_outbound_pair(
                    candidate.request_id)
                self.append(
                    f"Did not pin the certificate for {declined.name}.",
                    "Security", "warning")
        except (RuntimeError, SecureTransportError, ValueError) as error:
            self.append(f"Pairing approval failed: {error}",
                        "Security", "warning")

    @Slot(str)
    @Slot(QAbstractButton, bool)
    def _device_tab_toggled(self, button: QAbstractButton,
                            checked: bool) -> None:
        """Apply the checked status tab through the shared filter path."""
        for other in self.device_tab_group.buttons():
            other.setProperty("active",
                              "true" if other.isChecked() else "false")
            other.style().unpolish(other)
            other.style().polish(other)
            other.update()
        if checked:
            self._device_tab_key = str(button.property("tab_key"))
            self._filter_devices(self.device_search.text())

    def _refresh_device_tab_counts(self,
                                   records: tuple[PeerRecord, ...]) -> None:
        """Update tab counts from the snapshot the table already shows."""
        counts = tab_counts(records)
        labels = dict(FILTER_TABS)
        for key, button in self.device_tabs.items():
            button.setText(f"{labels[key]} ({counts[key]})")

    def _filter_devices(self, text: str) -> None:
        """Filter only fields present in the HELLO observation."""
        query = text.strip().casefold()
        evidence_filter = self._device_tab_key
        for row, peer in enumerate(self.peer_table_model.records):
            labels = tuple(capability_label(item) for item in peer.hello.capabilities)
            candidates = ([item.ip for item in peer.endpoint_candidates]
                          if peer.endpoint_candidates else [peer.ip])
            values = " ".join((peer.hello.name, peer.ip, str(peer.hello.tcp_port),
                               f"{peer.ip}:{peer.hello.tcp_port}", peer.session_id,
                               peer.hello.peer_id, peer.mac_address or "",
                               *candidates,
                               *peer.hello.capabilities, *labels)).casefold()
            matches_state = (
                evidence_filter == "all"
                or evidence_filter == "nearby" and peer.nearby
                or evidence_filter == "reachable"
                and peer.reachability_state is ReachabilityState.REACHABLE
                or evidence_filter == "compatible"
                and peer.compatibility_state is CompatibilityState.COMPATIBLE
                or evidence_filter == "stale"
                and peer.discovery_state is DiscoveryState.STALE)
            hidden = not matches_state or bool(query and query not in values)
            self.peer_list.setRowHidden(row, hidden)

    @Slot(str)
    def _topology_device_selected(self, session_id: str) -> None:
        """Open the exact observed session selected in the topology."""
        if self._record_in_snapshot(session_id) is not None:
            self.peer_selection.select(session_id)
            self.navigation.select(PAGE_DEVICES)

    @Slot(str)
    def _network_peer_selected(self, session_id: str) -> None:
        """Update the Network HUD without claiming probe or trust evidence."""
        if self._record_in_snapshot(session_id) is not None:
            self.peer_selection.select(session_id)

    def _open_network_peer(self) -> None:
        if self.peer_selection.session_id is not None:
            self._topology_device_selected(self.peer_selection.session_id)

    def _fit_topology(self) -> None:
        self.topology.view.fitInView(
            self.topology.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    @Slot(QModelIndex)
    def _overview_peer_previewed(self, index: QModelIndex) -> None:
        """Show one observed session without implying additional evidence."""
        record = self.peer_model.record_at(index.row())
        if record is not None:
            self.peer_selection.select(record.session_id)

    @Slot(str)
    def _overview_map_selected(self, session_id: str) -> None:
        """Preview one latency-map session without leaving Overview."""
        if self._record_in_snapshot(session_id) is not None:
            self.peer_selection.select(session_id)

    @Slot(QModelIndex)
    def _overview_peer_selected(self, index: QModelIndex) -> None:
        """Open the selected overview session in the full device inspector."""
        record = self.peer_model.record_at(index.row())
        if record is not None:
            self._topology_device_selected(record.session_id)

    def _peer_name(self, peer_id: str, session_id: str) -> str:
        record = self._record_in_snapshot(session_id)
        return record.hello.name if record is not None else f"Peer {peer_id[:8]}…"

    def _message_selected_peer(self) -> None:
        peer = self._selected_peer()
        if peer is None:
            return
        index = self.recipient.findData(peer.hello.session_id)
        if index >= 0:
            self.recipient.setCurrentIndex(index)
            self.navigation.select(PAGE_MESSAGES)

    def _probe_selected_peer(self, kind: str) -> None:
        """Queue an explicit diagnostic for the canonical live selection."""
        if self._selected_peer() is None:
            return
        self._open_peer_admin()
        self._queue_admin_probe(kind)

    def _copy_peer_address(self) -> None:
        """Copy the selected observed IPv4 address to the system clipboard."""
        record = self._selected_record()
        if record is not None:
            QApplication.clipboard().setText(record.ip)

    def _open_peer_admin(self) -> None:
        peer = self._selected_peer()
        record = self._selected_record()
        if peer is None or record is None:
            return
        self.admin_address.setText(peer.ip)
        self.admin_port.setValue(peer.hello.tcp_port)
        self.admin_selection.setText(
            f"{peer.hello.name} · LAN Atlas HELLO\n"
            f"Endpoint is observed and advertised · {peer_trust_label(record)}. "
            "The discovery observation itself is not authenticated.")
        key = f"peer:{peer.hello.session_id}:{peer.ip}"
        row = next((index for index, device in enumerate(self.admin_device_model.devices)
                    if device.key == key), -1)
        if row < 0:
            row = next((index for index, device in enumerate(
                self.admin_device_model.devices)
                if device.session_id == peer.hello.session_id), -1)
        if row >= 0:
            self.admin_device_list.setCurrentIndex(
                self.admin_device_model.index(row, 0))
        self.navigation.select(PAGE_WORKBENCH)

    def _file_selected_peer(self) -> None:
        peer = self._selected_peer()
        if peer is None:
            return
        self._send_file_to_peer(peer)

    def _sync_selected_peer(self) -> None:
        peer = self._selected_peer()
        if peer is None:
            return
        index = self.feed_peer.findData(peer.hello.session_id)
        if index >= 0:
            self.feed_peer.setCurrentIndex(index)
            self.sync_feed()

    def update_transfer(self, value: dict[str, Any]) -> None:
        """Update both the model and compatibility selector for one transfer."""
        identifier = value["id"]
        if identifier not in self.transfer_rows:
            self.transfer_rows[identifier] = {}
            self.transfer_list.addItem(identifier, identifier)
        row = self.transfer_rows[identifier]
        row.update(value)
        if ("bytes" in value and "total" in value
                and value.get("state") not in TERMINAL_TRANSFERS):
            now = time.monotonic()
            window = [(moment, count) for moment, count
                      in row.get("_samples", []) if now - moment <= 5.0]
            window.append((now, float(value["bytes"])))
            row["_samples"] = window[-6:]
            rate, eta = transfer_pace(tuple(window), float(value["bytes"]),
                                      float(value["total"]))
            row["_rate"], row["_eta"] = rate, eta
        removed = self.transfer_model.upsert(value)
        if removed is not None:
            self.transfer_rows.pop(removed, None)
            combo_index = self.transfer_list.findData(removed)
            if combo_index >= 0:
                self.transfer_list.removeItem(combo_index)
            if self.selected_transfer_id == removed:
                self.selected_transfer_id = None
        progress = ""
        if "bytes" in row and "total" in row:
            progress = f" {row['bytes']}/{row['total']} bytes"
        text = f"{row.get('name', identifier)}: {row['state']}{progress}"
        self.transfer_list.setItemText(self.transfer_list.findData(identifier), text)
        if value["state"] in TERMINAL_TRANSFERS:
            self.append(f"Transfer {identifier[:8]}…: {value['state']} "
                        f"{value.get('message', value.get('path', ''))}", "Transfers",
                        "warning" if value["state"] == "failed" else "info")
        self._update_transfer_metrics()
        model_row = self.transfer_model.identifiers.index(identifier)
        if self.selected_transfer_id == identifier:
            self._show_transfer(identifier)
        elif self.selected_transfer_id is None:
            self.transfer_view.setCurrentIndex(self.transfer_model.index(model_row, 0))

    @Slot(QModelIndex, QModelIndex)
    def _transfer_selected(self, current: QModelIndex,
                           previous: QModelIndex = QModelIndex()) -> None:
        del previous
        if not current.isValid():
            return
        identifier = self.transfer_model.identifiers[current.row()]
        self.selected_transfer_id = identifier
        index = self.transfer_list.findData(identifier)
        self.transfer_list.setCurrentIndex(index)
        self._show_transfer(identifier)

    def _show_transfer(self, identifier: str) -> None:
        """Refresh selected transfer phase, progress, and applicable actions."""
        row = self.transfer_rows[identifier]
        count, total = row.get("bytes", 0), row.get("total", 0)
        if total:
            self.transfer_progress.setValue(min(100, int(count * 100 / total)))
        else:
            self.transfer_progress.setValue(0)
        self.transfer_progress.setFormat(f"{row.get('state', 'pending')} · %p%")
        rate = row.get("_rate")
        if rate is not None:
            self.transfer_rate.setText(
                f"{human_bytes(rate)}/s · ETA {format_eta(row.get('_eta'))}")
        else:
            self.transfer_rate.setText("Rate not measured")
        if row.get("state") not in {"preparing", "hashing"}:
            if not row.get("connected", True):
                security = "No application connection established"
            else:
                security = ("Authenticated TLS" if row.get("authenticated")
                            else "Unverified plaintext")
            self.transfer_rate.setText(
                f"{self.transfer_rate.text()} · {security}")
        pending_offer = row.get("state") == "offer_pending"
        terminal = row.get("state") in TERMINAL_TRANSFERS
        self.accept_file.setEnabled(pending_offer)
        self.decline_file.setEnabled(pending_offer)
        self.cancel_file.setEnabled(not terminal and not pending_offer)

    def _update_transfer_metrics(self) -> None:
        active = sum(1 for row in self.transfer_rows.values()
                     if row.get("state") not in TERMINAL_TRANSFERS)
        self.transfer_status.setText(f"{active} active transfers")
        self.transfer_value.setText(str(active) if active else "None")
        self.transfer_slots.setText(f"{active} of 4 transfer slots in use")
        self.transfer_drawer.setVisible(active > 0)
        self.transfer_drawer_label.setText(
            f"{active} active transfer{'s' if active != 1 else ''} · phases and verification")

    @Slot()
    def send_file(self) -> None:
        """Select a source file for one explicitly selected chat peer."""
        selected = self.recipient.currentData()
        if self._queue_internet_action(selected, "file"):
            return
        record = self.service.peer_repository.get(
            selected if isinstance(selected, str) else None)
        if record is None or not record.nearby:
            self.append("Select one direct-message peer before sending a file.",
                        "Transfers", "warning")
            return
        self._send_file_to_peer(record.as_peer())

    def _send_file_to_peer(self, peer: Peer) -> None:
        """Offer one user-selected file to an explicit file-capable peer."""
        if "file_v1" not in peer.hello.capabilities:
            self.append("Selected peer does not advertise file sharing.",
                        "Transfers", "warning")
            return
        filename, _ = QFileDialog.getOpenFileName(self, "Send file")
        if not filename:
            return
        try:
            self.service.validate_dial_peer(peer)
            identifier = self.service.transfers.send(Path(filename), peer)
            self.update_transfer({"id": identifier, "name": Path(filename).name,
                                  "state": "preparing"})
            self.navigation.select(PAGE_TRANSFERS)
        except (OSError, ValueError, RuntimeError) as error:
            self.append(str(error), "Transfers", "warning")

    @Slot()
    def accept_offer(self) -> None:
        """Choose a new destination; the remote filename never selects a path."""
        identifier = self.selected_transfer_id
        row = self.transfer_rows.get(identifier, {})
        if row.get("state") != "offer_pending":
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save received file to a new filename")
        if filename and self.service.transfers.decide(identifier, Path(filename)):
            self.update_transfer({"id": identifier, "state": "accepted"})

    @Slot()
    def decline_offer(self) -> None:
        """Decline a still-pending offer."""
        identifier = self.selected_transfer_id
        if self.transfer_rows.get(identifier, {}).get("state") == "offer_pending":
            self.service.transfers.decide(identifier, None)

    @Slot()
    def cancel_transfer(self) -> None:
        """Cancel selected work without waiting on socket I/O in the GUI."""
        identifier = self.selected_transfer_id
        if identifier is not None:
            self.service.transfers.cancel(identifier)

    @Slot()
    def publish_post(self) -> None:
        """Persist one local post and clearly describe its local publication scope."""
        try:
            identifier = self.service.publish_post(self.post_input.text())
        except (ValueError, RuntimeError, OSError) as error:
            self.append(str(error), "Feed", "warning")
            return
        self.post_input.clear()
        self.append(f"Published {identifier[:8]}… locally; peers receive it on sync.",
                    "Feed")
        self.refresh_feed()

    @Slot()
    def sync_feed(self) -> None:
        """Queue feed paging from the explicitly selected capable peer."""
        selected = self.feed_peer.currentData()
        if self._queue_internet_action(selected, "feed"):
            return
        record = self.service.peer_repository.get(
            selected if isinstance(selected, str) else None)
        if (record is None or not record.nearby
                or "posts_v1" not in record.hello.capabilities):
            self.append("Select one posts-capable peer before syncing.",
                        "Feed", "warning")
            return
        peer = record.as_peer()
        try:
            identifier = self.service.sync_posts(peer)
        except (ValueError, RuntimeError) as error:
            self.append(str(error), "Feed", "warning")
            return
        self.append(f"Feed sync {identifier[:8]}… queued from {peer.hello.name}.",
                    "Feed")

    def refresh_feed(self) -> None:
        """Render a bounded local snapshot through both model and plain-text fallback."""
        if self.service.post_store is None:
            self.post_model.set_posts([], self.service.hello.peer_id, {})
            self.feed_log.setPlainText("Post storage is not configured.")
            return
        posts, _, _ = self.service.post_store.page(50)
        names = {record.hello.peer_id: record.hello.name
                 for record in self.service.peer_repository.snapshot()}
        names[self.service.hello.peer_id] = self.service.hello.name
        security_labels = {
            post["post_id"]: self._post_security_label(post) for post in posts}
        self.post_model.set_posts(
            posts, self.service.hello.peer_id, names, security_labels)
        lines = [f"{names.get(post['author_id'], post['author_id'])} | "
                 f"{security_labels[post['post_id']]} | {post['text']}"
                 for post in posts]
        self.feed_log.setPlainText("\n\n".join(lines) if lines else "No cached posts.")

    def _post_security_label(self, post: dict[str, Any]) -> str:
        """Describe signature and pairing evidence without trusting embedded keys."""
        verification = verify_post(post)
        if verification.state == "unsigned":
            return "Unsigned legacy post"
        if verification.state == "invalid":
            return "Invalid signature"
        transport = self.service.secure_transport
        if transport is None:
            return "Valid signature · author not paired"
        if post["author_id"] == self.service.hello.peer_id:
            if verification.fingerprint == transport.identity.fingerprint:
                return "Signed by this device"
            return "Signature key differs from this device"
        record = transport.trust_store.get(post["author_id"])
        if record is None:
            return "Valid signature · author not paired"
        if verification.fingerprint == record.fingerprint:
            return "Signature matches paired key"
        return "Signature key differs from paired key"

    def closeEvent(self, event: QCloseEvent) -> None:
        """Cancel core work; the entry point joins after the Qt loop exits."""
        self.timer.stop()
        self._pending_internet.clear()
        self.portal.stop()
        self.forwarder.stop()
        self.service.stop()
        event.accept()
