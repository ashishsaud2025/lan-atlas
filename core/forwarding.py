"""Explicit loopback sharing through bounded raw TCP byte forwarding."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
import logging
import select
import socket
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

CHUNK_SIZE = 64 * 1024
MAX_CONNECTIONS = 8
CONNECT_TIMEOUT = 3.0
IO_TIMEOUT = 60.0
ACCEPT_TIMEOUT = 0.5
PIPE_POLL = 0.5


@dataclass(frozen=True)
class ForwardingState:
    """Immutable lifecycle snapshot of one explicit forwarding rule."""

    phase: str = "stopped"
    listen_host: str | None = None
    listen_port: int | None = None
    target_host: str = "127.0.0.1"
    target_port: int | None = None
    active: int = 0
    total_connections: int = 0
    bytes_relayed: int = 0
    error: str | None = None


class ForwardingService:
    """Forward one LAN listener to one loopback target without framing."""

    def __init__(self, emit: Callable[[str, Any], bool] | None = None,
                 max_connections: int = MAX_CONNECTIONS,
                 allow_loopback: bool = False) -> None:
        if (type(max_connections) is not int or isinstance(max_connections, bool)
                or max_connections <= 0):
            raise ValueError("max_connections must be a positive integer")
        self.emit = emit
        self.max_connections = max_connections
        self.allow_loopback = allow_loopback
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._relays: list[threading.Thread] = []
        self._relay_sockets: set[socket.socket] = set()
        self._generation = 0
        self._state = ForwardingState()

    def start(self, listen_host: str, listen_port: int,
              target_host: str, target_port: int) -> ForwardingState:
        """Bind synchronously, then accept from one owned daemon worker."""
        listen = _listen_host(listen_host, self.allow_loopback)
        port = _listen_port(listen_port)
        target = _target_host(target_host)
        target_port = _target_port(target_port)
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("forwarder is already running or stopping")
            self._stop.clear()
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((listen, port))
                listener.listen(self.max_connections)
                listener.settimeout(ACCEPT_TIMEOUT)
                actual_host, actual_port = listener.getsockname()[:2]
            except OSError:
                listener.close()
                raise
            self._listener = listener
            self._generation += 1
            self._state = ForwardingState(
                "running", actual_host, int(actual_port),
                target, target_port)
            thread = threading.Thread(
                target=self._accept, name="lan-atlas-forward", daemon=True)
            self._thread = thread
            try:
                thread.start()
            except RuntimeError:
                listener.close()
                self._listener = None
                self._state = ForwardingState("failed", actual_host,
                                              int(actual_port), target,
                                              target_port, error="worker did not start")
                raise
            self._notify("forwarding_started", self._state)
            return self._state

    def stop(self) -> None:
        """Request cancellation and unblock the accept loop promptly."""
        with self._lock:
            thread = self._thread
            listener = self._listener
            if thread is None or not thread.is_alive():
                if self._state.phase != "failed":
                    self._state = ForwardingState()
                return
            self._state = ForwardingState(
                "stopping", self._state.listen_host, self._state.listen_port,
                self._state.target_host, self._state.target_port,
                self._state.active, self._state.total_connections,
                self._state.bytes_relayed)
            self._stop.set()
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    logger.debug("Could not close forward listener", exc_info=True)
            live = tuple(self._relay_sockets)
        for sock in live:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                logger.debug("Could not interrupt relay socket", exc_info=True)

    def join(self, timeout: float = 3.0) -> bool:
        """Wait a finite interval for accept and relay workers to finish."""
        if timeout < 0:
            raise ValueError("timeout must not be negative")
        with self._lock:
            thread = self._thread
            relays = tuple(self._relays)
        deadline = time.monotonic() + timeout
        if thread is not None:
            thread.join(max(0.0, deadline - time.monotonic()))
        for relay in relays:
            relay.join(max(0.0, deadline - time.monotonic()))
        with self._lock:
            self._relays = [item for item in self._relays if item.is_alive()]
            relays_done = not self._relays
        return (thread is None or not thread.is_alive()) and relays_done

    def state(self) -> ForwardingState:
        """Return one immutable lifecycle snapshot."""
        with self._lock:
            return self._state

    def _notify(self, kind: str, data: Any) -> None:
        if self.emit is None:
            return
        try:
            self.emit(kind, data)
        except Exception:
            logger.exception("Forwarding callback failed")

    def _accept(self) -> None:
        with self._lock:
            listener = self._listener
        if listener is None:
            return
        failed: str | None = None
        try:
            while not self._stop.is_set():
                try:
                    client, _address = listener.accept()
                except TimeoutError:
                    continue
                except OSError as error:
                    if not self._stop.is_set():
                        failed = str(error)
                        logger.exception("Forward listener failed: %s", error)
                    break
                with self._lock:
                    full = (len(self._relays) >= self.max_connections
                            or self._stop.is_set())
                    if not full:
                        generation = self._generation
                        target_host = self._state.target_host
                        target_port = self._state.target_port
                        relay = threading.Thread(
                            target=self._relay,
                            args=(client, generation, target_host,
                                  target_port),
                            name="lan-atlas-relay", daemon=True)
                        self._relays.append(relay)
                        self._state = ForwardingState(
                            self._state.phase, self._state.listen_host,
                            self._state.listen_port, self._state.target_host,
                            self._state.target_port, self._state.active + 1,
                            self._state.total_connections + 1,
                            self._state.bytes_relayed)
                if full:
                    try:
                        client.close()
                    except OSError:
                        logger.debug("Could not close excess client", exc_info=True)
                    with self._lock:
                        self._relays = [item for item in self._relays
                                        if item.is_alive()]
                    continue
                try:
                    relay.start()
                except RuntimeError:
                    try:
                        client.close()
                    except OSError:
                        logger.debug("Could not close client", exc_info=True)
                    with self._lock:
                        if relay in self._relays:
                            self._relays.remove(relay)
                        self._state = ForwardingState(
                            self._state.phase, self._state.listen_host,
                            self._state.listen_port, self._state.target_host,
                            self._state.target_port,
                            max(0, self._state.active - 1),
                            self._state.total_connections,
                            self._state.bytes_relayed)
        finally:
            try:
                listener.close()
            except OSError:
                logger.debug("Could not close listener", exc_info=True)
            with self._lock:
                self._listener = None
                if failed is None:
                    self._state = ForwardingState()
                else:
                    self._state = ForwardingState(
                        "failed", self._state.listen_host,
                        self._state.listen_port, self._state.target_host,
                        self._state.target_port, 0,
                        self._state.total_connections,
                        self._state.bytes_relayed, failed)
                finished = self._state
            self._notify("forwarding_stopped", finished)

    def _relay(self, client: socket.socket, generation: int,
               target_host: str, target_port: int | None) -> None:
        upstream: socket.socket | None = None
        try:
            if target_port is None:
                try:
                    client.close()
                except OSError:
                    logger.debug("Could not close orphaned client", exc_info=True)
                return
            try:
                upstream = socket.create_connection(
                    (target_host, target_port), timeout=CONNECT_TIMEOUT)
            except OSError as error:
                logger.debug("Forward target unreachable: %s", error)
                return
            upstream.settimeout(IO_TIMEOUT)
            client.settimeout(IO_TIMEOUT)
            with self._lock:
                self._relay_sockets.add(client)
                self._relay_sockets.add(upstream)
                stopped = self._stop.is_set()
            if stopped:
                for sock in (client, upstream):
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        logger.debug("Could not interrupt late relay", exc_info=True)
            first = threading.Thread(
                target=self._pipe, args=(client, upstream, generation),
                daemon=True)
            second = threading.Thread(
                target=self._pipe, args=(upstream, client, generation),
                daemon=True)
            first.start()
            second.start()
            first.join()
            second.join()
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        logger.debug("Could not close relay socket", exc_info=True)
            with self._lock:
                self._relays = [item for item in self._relays
                                if item is not threading.current_thread()
                                and item.is_alive()]
                self._relay_sockets.discard(client)
                if upstream is not None:
                    self._relay_sockets.discard(upstream)
                if generation == self._generation:
                    self._state = ForwardingState(
                        self._state.phase, self._state.listen_host,
                        self._state.listen_port, self._state.target_host,
                        self._state.target_port, max(0, self._state.active - 1),
                        self._state.total_connections, self._state.bytes_relayed)

    def _pipe(self, source: socket.socket, dest: socket.socket,
              generation: int) -> None:
        try:
            while not self._stop.is_set():
                try:
                    ready, _, _ = select.select([source], [], [], PIPE_POLL)
                except (OSError, ValueError):
                    break
                if not ready:
                    continue
                try:
                    chunk = source.recv(CHUNK_SIZE)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                try:
                    dest.sendall(chunk)
                except (OSError, TimeoutError):
                    break
                with self._lock:
                    if generation == self._generation:
                        self._state = ForwardingState(
                            self._state.phase, self._state.listen_host,
                            self._state.listen_port, self._state.target_host,
                            self._state.target_port, self._state.active,
                            self._state.total_connections,
                            self._state.bytes_relayed + len(chunk))
        finally:
            try:
                dest.shutdown(socket.SHUT_WR)
            except OSError:
                logger.debug("Half close raced socket teardown", exc_info=True)


def _listen_host(value: object, allow_loopback: bool) -> str:
    """Require one concrete LAN IPv4 address for the public listener."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("listener requires a concrete LAN address")
    try:
        parsed = ip_address(value.strip())
    except ValueError as error:
        raise ValueError("listener must be a concrete IPv4 address") from error
    if (not isinstance(parsed, IPv4Address) or parsed.is_unspecified
            or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved
            or parsed.is_loopback and not allow_loopback):
        raise ValueError("select one concrete LAN interface address")
    return str(parsed)


def _listen_port(value: object) -> int:
    """Allow an explicit port or zero for one OS assigned listener port."""
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 65535:
        raise ValueError("listener port must be from 0 through 65535")
    return value


def _target_host(value: object) -> str:
    """Restrict forwarding targets to loopback so exposure stays explicit."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("target requires a loopback address")
    try:
        parsed = ip_address(value.strip())
    except ValueError as error:
        raise ValueError("target must be a loopback address") from error
    if (isinstance(parsed, IPv4Address) and str(parsed) != "127.0.0.1"
            or isinstance(parsed, IPv6Address) and str(parsed) != "::1"):
        raise ValueError("target must be a loopback address")
    return str(parsed)


def _target_port(value: object) -> int:
    """Require one concrete loopback port as the forwarding destination."""
    if (type(value) is not int or isinstance(value, bool)
            or not 1 <= value <= 65535):
        raise ValueError("target port must be from 1 through 65535")
    return value
