from __future__ import annotations

import http.server
import socket
import threading

import pytest

from core.forwarding import ForwardingService


class _FixedHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"forward-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        del args


def _http_server() -> tuple[http.server.ThreadingHTTPServer, threading.Thread]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FixedHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    return server, worker


def _read_all(sock: socket.socket) -> bytes:
    sock.settimeout(5)
    parts: list[bytes] = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return b"".join(parts)
        parts.append(chunk)


def test_http_round_trip_through_forwarder() -> None:
    server, _worker = _http_server()
    target_port = server.server_address[1]
    forward = ForwardingService(allow_loopback=True)
    state = forward.start("127.0.0.1", 0, "127.0.0.1", target_port)
    assert state.phase == "running"
    try:
        assert state.listen_port is not None
        with socket.create_connection(
                ("127.0.0.1", state.listen_port), timeout=5) as client:
            client.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
            assert b"forward-ok" in _read_all(client)
    finally:
        forward.stop()
        assert forward.join(5)
        server.shutdown()
        server.server_close()


def test_websocket_upgrade_passes_through_unframed() -> None:
    received: list[bytes] = []
    ready = threading.Event()
    holder: dict[str, int] = {}

    def serve() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            holder["port"] = listener.getsockname()[1]
            ready.set()
            conn, _ = listener.accept()
            with conn:
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    request += chunk
                received.append(request)
                conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n"
                             b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                             b"\r\nUPGRADED")

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    assert ready.wait(5)
    forward = ForwardingService(allow_loopback=True)
    state = forward.start("127.0.0.1", 0, "127.0.0.1", holder["port"])
    try:
        assert state.listen_port is not None
        with socket.create_connection(
                ("127.0.0.1", state.listen_port), timeout=5) as client:
            client.sendall(b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
                           b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                           b"Sec-WebSocket-Version: 13\r\n\r\n")
            reply = _read_all(client)
        assert reply.startswith(b"HTTP/1.1 101")
        assert reply.endswith(b"UPGRADED")
        assert b"Sec-WebSocket-Key" in received[0]
    finally:
        forward.stop()
        assert forward.join(5)
        worker.join(5)


def test_half_close_propagates_both_directions() -> None:
    ready = threading.Event()
    holder: dict[str, int] = {}

    def serve() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            holder["port"] = listener.getsockname()[1]
            ready.set()
            conn, _ = listener.accept()
            with conn:
                data = b""
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                conn.sendall(data.upper())

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    assert ready.wait(5)
    forward = ForwardingService(allow_loopback=True)
    state = forward.start("127.0.0.1", 0, "127.0.0.1", holder["port"])
    try:
        assert state.listen_port is not None
        with socket.create_connection(
                ("127.0.0.1", state.listen_port), timeout=5) as client:
            client.sendall(b"half close me")
            client.shutdown(socket.SHUT_WR)
            assert _read_all(client) == b"HALF CLOSE ME"
    finally:
        forward.stop()
        assert forward.join(5)
        worker.join(5)


def test_stop_interrupts_idle_connection_promptly() -> None:
    ready = threading.Event()
    holder: dict[str, int] = {}
    release = threading.Event()

    def serve() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            holder["port"] = listener.getsockname()[1]
            ready.set()
            conn, _ = listener.accept()
            with conn:
                release.wait(10)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    assert ready.wait(5)
    forward = ForwardingService(allow_loopback=True)
    state = forward.start("127.0.0.1", 0, "127.0.0.1", holder["port"])
    try:
        assert state.listen_port is not None
        client = socket.create_connection(
            ("127.0.0.1", state.listen_port), timeout=5)
        try:
            forward.stop()
            assert forward.join(15)
            try:
                assert _read_all(client) == b""
            except ConnectionResetError:
                pass
        finally:
            client.close()
    finally:
        release.set()
        forward.stop()
        forward.join(5)
        worker.join(5)


def test_stop_removes_reachability() -> None:
    server, _worker = _http_server()
    forward = ForwardingService(allow_loopback=True)
    state = forward.start("127.0.0.1", 0, "127.0.0.1",
                          server.server_address[1])
    assert state.listen_port is not None
    port = state.listen_port
    forward.stop()
    assert forward.join(5)
    assert forward.state().phase == "stopped"
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2)
    server.shutdown()
    server.server_close()


def test_unreachable_target_closes_client_cleanly() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    forward = ForwardingService(allow_loopback=True)
    state = forward.start("127.0.0.1", 0, "127.0.0.1", closed_port)
    try:
        assert state.listen_port is not None
        with socket.create_connection(
                ("127.0.0.1", state.listen_port), timeout=5) as client:
            assert _read_all(client) == b""
    finally:
        forward.stop()
        assert forward.join(5)


def test_connection_limit_closes_excess() -> None:
    ready = threading.Event()
    holder: dict[str, int] = {}
    release = threading.Event()

    def serve() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            holder["port"] = listener.getsockname()[1]
            ready.set()
            while not release.is_set():
                listener.settimeout(0.2)
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                threading.Thread(
                    target=lambda c=conn: (release.wait(5), c.close()),
                    daemon=True).start()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    assert ready.wait(5)
    forward = ForwardingService(allow_loopback=True, max_connections=1)
    state = forward.start("127.0.0.1", 0, "127.0.0.1", holder["port"])
    try:
        assert state.listen_port is not None
        first = socket.create_connection(
            ("127.0.0.1", state.listen_port), timeout=5)
        try:
            with socket.create_connection(
                    ("127.0.0.1", state.listen_port), timeout=5) as second:
                assert _read_all(second) == b""
        finally:
            release.set()
            first.close()
    finally:
        forward.stop()
        assert forward.join(5)
        worker.join(5)


def test_validation_rejects_unsafe_or_bad_endpoints() -> None:
    forward = ForwardingService()
    with pytest.raises(ValueError):
        forward.start("0.0.0.0", 8080, "127.0.0.1", 8000)
    with pytest.raises(ValueError):
        forward.start("192.168.1.10", 8080, "192.168.1.20", 8000)
    with pytest.raises(ValueError):
        forward.start("192.168.1.10", 0, "127.0.0.1", 0)
    assert forward.state().phase == "stopped"


def test_desktop_forwarder_card_shares_and_prefills(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow
    from core.chat import ChatService
    from core.discovery import Hello
    from uuid import uuid4 as _uuid4

    app = QApplication.instance() or QApplication([])
    service = ChatService(Hello(str(_uuid4()), str(_uuid4()), "Local"))
    window = MainWindow(service,
                        forwarder=ForwardingService(allow_loopback=True))
    try:
        window.forward_target_host.setText("127.0.0.1")
        window.forward_target_port.setValue(8000)
        window.forward_address.setEditText("127.0.0.1")
        window.forward_port.setValue(0)
        window._start_forwarding()
        state = window.forwarder.state()
        assert state.phase == "running"
        assert "available at" in window.forward_stats.text()
        window._use_forwarder_in_publication()
        assert window.directory_host.currentText() == "127.0.0.1"
        assert window.directory_port.value() == state.listen_port
        window._stop_forwarding()
        assert window.forwarder.join(5)
        assert window.forwarder.state().phase == "stopped"
    finally:
        window.forwarder.stop()
        window.forwarder.join(5)
        window.close()
        app.processEvents()


def test_desktop_forwarder_rejects_non_loopback_target(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from gui.main_window import MainWindow
    from core.chat import ChatService
    from core.discovery import Hello
    from uuid import uuid4 as _uuid4

    app = QApplication.instance() or QApplication([])
    service = ChatService(Hello(str(_uuid4()), str(_uuid4()), "Local"))
    window = MainWindow(service,
                        forwarder=ForwardingService(allow_loopback=True))
    try:
        window.forward_target_host.setText("192.168.1.20")
        window.forward_target_port.setValue(8000)
        window.forward_address.setEditText("127.0.0.1")
        window._start_forwarding()
        assert window.forwarder.state().phase == "stopped"
        assert "Sharing start failed" in window.log.toPlainText()
    finally:
        window.close()
        app.processEvents()


def test_double_start_is_rejected() -> None:
    server, _worker = _http_server()
    forward = ForwardingService(allow_loopback=True)
    forward.start("127.0.0.1", 0, "127.0.0.1", server.server_address[1])
    try:
        with pytest.raises(RuntimeError):
            forward.start("127.0.0.1", 0, "127.0.0.1",
                          server.server_address[1])
    finally:
        forward.stop()
        assert forward.join(5)
        server.shutdown()
        server.server_close()
