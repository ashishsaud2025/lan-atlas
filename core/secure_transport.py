"""Pinned TLS channels and explicit device pairing for desktop peers."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import secrets
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from uuid import UUID, uuid4

from core.discovery import Hello
from core.identity import (
    DeviceIdentity,
    IdentityError,
    validate_certificate,
    verify_signature,
)
from core.protocol import ProtocolError, recv_message, send_message
from core.roster import Peer
from core.scope import resolve_host
from core.trust import KeyChangedError, TrustRecord, TrustStore

SECURE_PORT = 50003
SECURITY_VERSION = 1
CONNECT_TIMEOUT = 3.0
HANDSHAKE_TIMEOUT = 3.0
IO_TIMEOUT = 5.0
MAX_NAME_LENGTH = 80
MAX_CERTIFICATE_DER = 8192
MAX_SIGNATURE = 256
AUTH_DOMAIN = b"LAN-MANAGER-SECURE-AUTH-V1\x00"
PAIR_DOMAIN = b"LAN-MANAGER-SECURE-PAIR-V1\x00"
PAIR_CODE_DOMAIN = b"LAN-MANAGER-PAIR-CODE-V1\x00"
logger = logging.getLogger(__name__)


class SecureTransportError(Exception):
    """A secure connection or pairing exchange failed validation."""


@dataclass
class SecureChannel:
    """An authenticated TLS socket and its peer identity binding."""

    socket: ssl.SSLSocket
    peer_id: str
    session_id: str
    fingerprint: str
    encrypted: bool = field(default=True, init=False)

    def close(self) -> None:
        """Close the TLS socket."""
        self.socket.close()

    def shutdown(self, how: int = socket.SHUT_RDWR) -> None:
        """Shut down the TLS socket in the requested direction."""
        self.socket.shutdown(how)

    def fileno(self) -> int:
        """Return the underlying socket descriptor."""
        return self.socket.fileno()


@dataclass(frozen=True)
class PairingCandidate:
    """An immutable certificate awaiting explicit local approval."""

    request_id: str
    peer_id: str
    session_id: str
    name: str
    certificate_der: bytes
    fingerprint: str
    comparison_code: str
    created: float
    source_ip: str = ""


class SecureTransport:
    """Create authenticated TLS channels and manage explicit pairing."""

    def __init__(self, identity: DeviceIdentity, trust_store: TrustStore,
                 local_hello: Hello,
                 emit: Callable[[str, PairingCandidate], object] | None = None,
                 max_pending: int = 16, pairing_ttl: float = 120.0,
                 observe_socket: Callable[[socket.socket, bool], object]
                 | None = None) -> None:
        if type(max_pending) is not int or not 1 <= max_pending <= 1024:
            raise ValueError("max_pending must be between 1 and 1024")
        if not math.isfinite(pairing_ttl) or pairing_ttl <= 0:
            raise ValueError("pairing_ttl must be finite and positive")
        _validate_local_hello(identity, local_hello)
        self.identity = identity
        self.trust_store = trust_store
        self.local_hello = local_hello
        self.emit = emit
        self.observe_socket = observe_socket
        self.max_pending = max_pending
        self.pairing_ttl = pairing_ttl
        self._pending: dict[str, PairingCandidate] = {}
        self._outbound_pending: dict[str, PairingCandidate] = {}
        self._pending_lock = threading.RLock()
        self._server_context = _server_context(identity)
        self._client_context = _client_context()

    def connect(self, peer: Peer) -> SecureChannel:
        """Connect only to an already-paired peer and authenticate both ends."""
        hello = _validate_peer(peer)
        record = self.trust_store.get(hello.peer_id)
        if record is None:
            raise SecureTransportError("peer is not paired")
        if record.fingerprint != hello.certificate_sha256:
            raise SecureTransportError("advertised certificate differs from trust")
        tls_socket: ssl.SSLSocket | None = None
        raw_socket: socket.socket | None = None
        try:
            raw_socket = socket.create_connection(
                (peer.ip, hello.secure_port), timeout=CONNECT_TIMEOUT)
            raw_socket.settimeout(HANDSHAKE_TIMEOUT)
            tls_socket = self._client_context.wrap_socket(
                raw_socket, server_hostname=None, do_handshake_on_connect=False)
            raw_socket = None
            return self._finish_client_handshake(tls_socket, hello, record)
        except SecureTransportError:
            self._observe_socket(tls_socket, False)
            _close_sockets(tls_socket, raw_socket)
            raise
        except (OSError, ssl.SSLError, ProtocolError, TimeoutError,
                IdentityError, ValueError) as error:
            self._observe_socket(tls_socket, False)
            _close_sockets(tls_socket, raw_socket)
            raise SecureTransportError("secure connection failed") from error

    def connect_over(self, raw_socket: socket.socket, peer: Peer,
                     expect_session: bool = True) -> SecureChannel:
        """Run the paired TLS handshake over an already open socket."""
        hello = _validate_peer(peer)
        if type(expect_session) is not bool:
            raise ValueError("expect_session must be bool")
        record = self.trust_store.get(hello.peer_id)
        if record is None:
            raise SecureTransportError("peer is not paired")
        if record.fingerprint != hello.certificate_sha256:
            raise SecureTransportError("advertised certificate differs from trust")
        tls_socket: ssl.SSLSocket | None = None
        try:
            raw_socket.settimeout(HANDSHAKE_TIMEOUT)
            tls_socket = self._client_context.wrap_socket(
                raw_socket, server_hostname=None, do_handshake_on_connect=False)
            raw_socket = None
            return self._finish_client_handshake(
                tls_socket, hello, record, expect_session)
        except SecureTransportError:
            self._observe_socket(tls_socket, False)
            _close_sockets(tls_socket, raw_socket)
            raise
        except (OSError, ssl.SSLError, ProtocolError, TimeoutError,
                IdentityError, ValueError) as error:
            self._observe_socket(tls_socket, False)
            _close_sockets(tls_socket, raw_socket)
            raise SecureTransportError("secure relay failed") from error

    def _finish_client_handshake(self, tls_socket: ssl.SSLSocket,
                                 hello: Hello, record: TrustRecord,
                                 expect_session: bool = True) -> SecureChannel:
        """Authenticate both ends over one wrapped TLS socket."""
        try:
            self._observe_socket(tls_socket, True)
            tls_socket.do_handshake()
            certificate_der = _peer_certificate(tls_socket)
            fingerprint = _certificate_fingerprint(
                certificate_der, hello.peer_id)
            if (certificate_der != record.certificate_der
                    or fingerprint != record.fingerprint
                    or not self.trust_store.verify(
                        hello.peer_id, certificate_der)):
                raise SecureTransportError("TLS certificate does not match trust")
            challenge = _receive_challenge(tls_socket, hello, expect_session)
            live_session = (_canonical_uuid(challenge["session_id"], "session_id")
                            if not expect_session else hello.session_id)
            signature = self.identity.sign(_authentication_transcript(
                challenge["nonce"], challenge["fingerprint"],
                self.local_hello.peer_id, self.local_hello.session_id,
                self.identity.fingerprint))
            send_message(tls_socket, {
                "version": SECURITY_VERSION,
                "type": "SECURE_AUTH",
                "peer_id": self.local_hello.peer_id,
                "session_id": self.local_hello.session_id,
                "fingerprint": self.identity.fingerprint,
                "signature": _encode_base64(signature),
            }, timeout=IO_TIMEOUT)
            ready = _receive_frame(tls_socket)
            _validate_ready(ready, replace(hello, session_id=live_session))
            tls_socket.settimeout(IO_TIMEOUT)
            return SecureChannel(tls_socket, hello.peer_id, live_session,
                                 fingerprint)
        except SecureTransportError:
            self._observe_socket(tls_socket, False)
            tls_socket.close()
            raise
        except (OSError, ssl.SSLError, ProtocolError, TimeoutError,
                IdentityError, ValueError) as error:
            self._observe_socket(tls_socket, False)
            tls_socket.close()
            raise SecureTransportError("secure handshake failed") from error

    def probe_session(self, host: str, port: int,
                      peer_id: str) -> tuple[str, str]:
        """Learn one paired peer's live session and pinned address."""
        record = self.trust_store.get(peer_id)
        if record is None:
            raise SecureTransportError("peer is not paired")
        try:
            targets = resolve_host(host)
        except ValueError as error:
            raise SecureTransportError(f"probe target invalid: {error}") from error
        error: Exception | None = None
        for target in targets:
            try:
                return (self._probe_one(target, port, record.peer_id,
                                        record.certificate_der,
                                        record.fingerprint), target)
            except (OSError, SecureTransportError, ValueError) as exc:
                error = exc
                continue
        assert error is not None
        raise error

    def _probe_one(self, host: str, port: int, peer_id: str,
                   certificate_der: bytes, fingerprint: str) -> str:
        """Complete one TLS handshake and return the live session ID."""
        tls_socket: ssl.SSLSocket | None = None
        raw_socket: socket.socket | None = None
        try:
            raw_socket = socket.create_connection(
                (host, port), timeout=CONNECT_TIMEOUT)
            raw_socket.settimeout(HANDSHAKE_TIMEOUT)
            tls_socket = self._client_context.wrap_socket(
                raw_socket, server_hostname=None, do_handshake_on_connect=False)
            raw_socket = None
            self._observe_socket(tls_socket, True)
            tls_socket.do_handshake()
            presented = _peer_certificate(tls_socket)
            presented_fingerprint = _certificate_fingerprint(
                presented, peer_id)
            if (presented != certificate_der
                    or presented_fingerprint != fingerprint
                    or not self.trust_store.verify(peer_id, presented)):
                raise SecureTransportError("TLS certificate does not match trust")
            frame = _receive_frame(tls_socket)
            _require_frame(frame, "SECURE_CHALLENGE",
                           {"version", "type", "nonce", "peer_id",
                            "session_id", "fingerprint"})
            _validate_nonce(frame["nonce"])
            if (_canonical_uuid(frame["peer_id"], "peer_id") != peer_id
                    or _validate_fingerprint(frame["fingerprint"])
                    != fingerprint):
                raise SecureTransportError("challenge differs from paired peer")
            return _canonical_uuid(frame["session_id"], "session_id")
        except SecureTransportError:
            self._observe_socket(tls_socket, False)
            _close_sockets(tls_socket, raw_socket)
            raise
        except (OSError, ssl.SSLError, ProtocolError, TimeoutError,
                IdentityError, ValueError) as error:
            self._observe_socket(tls_socket, False)
            _close_sockets(tls_socket, raw_socket)
            raise SecureTransportError("session probe failed") from error
        finally:
            self._observe_socket(tls_socket, False)
            _close_sockets(tls_socket, raw_socket)

    def accept(self, raw_socket: socket.socket,
               allow_pairing: bool = True) -> SecureChannel | None:
        """TLS-wrap one accepted socket and authenticate or stage its peer."""
        if type(allow_pairing) is not bool:
            raise ValueError("allow_pairing must be bool")
        try:
            source_ip = raw_socket.getpeername()[0]
        except OSError:
            source_ip = ""
        tls_socket: ssl.SSLSocket | None = None
        try:
            raw_socket.settimeout(HANDSHAKE_TIMEOUT)
            tls_socket = self._server_context.wrap_socket(
                raw_socket, server_side=True, do_handshake_on_connect=False)
            self._observe_socket(tls_socket, True)
            tls_socket.do_handshake()
            nonce = secrets.token_bytes(32).hex()
            send_message(tls_socket, {
                "version": SECURITY_VERSION,
                "type": "SECURE_CHALLENGE",
                "nonce": nonce,
                "peer_id": self.local_hello.peer_id,
                "session_id": self.local_hello.session_id,
                "fingerprint": self.identity.fingerprint,
            }, timeout=IO_TIMEOUT)
            frame = _receive_frame(tls_socket)
            frame_type = frame.get("type")
            if frame_type == "SECURE_AUTH":
                peer_id, session_id, fingerprint = self._authenticate(
                    frame, nonce)
                send_message(tls_socket, _ready_frame(self.local_hello,
                                                       self.identity.fingerprint),
                             timeout=IO_TIMEOUT)
                tls_socket.settimeout(IO_TIMEOUT)
                return SecureChannel(tls_socket, peer_id, session_id,
                                     fingerprint)
            if frame_type == "PAIR_REQUEST":
                if not allow_pairing:
                    raise SecureTransportError(
                        "internet pairing refused; pair on LAN first")
                candidate = self._stage_pairing(frame, nonce, source_ip)
                self._emit_pairing(candidate)
                send_message(tls_socket, {
                    "version": SECURITY_VERSION,
                    "type": "PAIR_PENDING",
                    "request_id": candidate.request_id,
                    "comparison_code": candidate.comparison_code,
                }, timeout=IO_TIMEOUT)
                self._observe_socket(tls_socket, False)
                tls_socket.close()
                return None
            raise SecureTransportError("unknown initial security frame")
        except SecureTransportError:
            self._observe_socket(tls_socket, False)
            _close_sockets(tls_socket, raw_socket)
            raise
        except (OSError, ssl.SSLError, ProtocolError, TimeoutError,
                 IdentityError, ValueError) as error:
            self._observe_socket(tls_socket, False)
            _close_sockets(tls_socket, raw_socket)
            raise SecureTransportError("secure acceptance failed") from error

    def request_pair(self, peer: Peer) -> PairingCandidate:
        """Request remote approval and trust the explicitly selected peer."""
        hello = _validate_peer(peer)
        existing = self.trust_store.get(hello.peer_id)
        if (existing is not None
                and existing.fingerprint != hello.certificate_sha256):
            raise KeyChangedError(
                "paired peer advertised a different certificate")
        request_id = str(uuid4())
        tls_socket: ssl.SSLSocket | None = None
        raw_socket: socket.socket | None = None
        candidate: PairingCandidate
        try:
            raw_socket = socket.create_connection(
                (peer.ip, hello.secure_port), timeout=CONNECT_TIMEOUT)
            raw_socket.settimeout(HANDSHAKE_TIMEOUT)
            tls_socket = self._client_context.wrap_socket(
                raw_socket, server_hostname=None, do_handshake_on_connect=False)
            raw_socket = None
            self._observe_socket(tls_socket, True)
            tls_socket.do_handshake()
            certificate_der = _peer_certificate(tls_socket)
            fingerprint = _certificate_fingerprint(
                certificate_der, hello.peer_id)
            if fingerprint != hello.certificate_sha256:
                raise SecureTransportError(
                    "TLS certificate differs from discovery advertisement")
            challenge = _receive_challenge(tls_socket, hello)
            comparison_code = _comparison_code(
                challenge["nonce"], fingerprint, self.identity.fingerprint)
            signature = self.identity.sign(_pairing_transcript(
                challenge["nonce"], challenge["fingerprint"],
                self.local_hello.peer_id, self.local_hello.session_id,
                self.identity.fingerprint, request_id))
            send_message(tls_socket, {
                "version": SECURITY_VERSION,
                "type": "PAIR_REQUEST",
                "request_id": request_id,
                "peer_id": self.local_hello.peer_id,
                "session_id": self.local_hello.session_id,
                "name": self.local_hello.name,
                "certificate_der": _encode_base64(
                    self.identity.certificate_der),
                "fingerprint": self.identity.fingerprint,
                "signature": _encode_base64(signature),
            }, timeout=IO_TIMEOUT)
            pending = _receive_frame(tls_socket)
            _validate_pending(pending, request_id, comparison_code)
            candidate = PairingCandidate(
                request_id, hello.peer_id, hello.session_id, hello.name,
                certificate_der, fingerprint, comparison_code, time.monotonic())
        except SecureTransportError:
            self._observe_socket(tls_socket, False)
            _close_sockets(tls_socket, raw_socket)
            raise
        except (OSError, ssl.SSLError, ProtocolError, TimeoutError,
                 IdentityError, ValueError) as error:
            self._observe_socket(tls_socket, False)
            _close_sockets(tls_socket, raw_socket)
            raise SecureTransportError("pairing request failed") from error
        self._observe_socket(tls_socket, False)
        _close_sockets(tls_socket, raw_socket)
        with self._pending_lock:
            self._expire_pending_locked(time.monotonic())
            if (len(self._pending) + len(self._outbound_pending)
                    >= self.max_pending):
                raise SecureTransportError("pending pairing limit reached")
            self._outbound_pending[candidate.request_id] = candidate
        return candidate

    def pending(self) -> tuple[PairingCandidate, ...]:
        """Return unexpired pairing candidates in arrival order."""
        with self._pending_lock:
            self._expire_pending_locked(time.monotonic())
            return tuple(sorted(self._pending.values(),
                                key=lambda item: (item.created,
                                                  item.request_id)))

    def accept_pair(self, request_id: str) -> PairingCandidate:
        """Persist one pending certificate without replacing a changed key."""
        checked_id = _canonical_uuid(request_id, "request_id")
        with self._pending_lock:
            self._expire_pending_locked(time.monotonic())
            candidate = self._pending.get(checked_id)
            if candidate is None:
                raise SecureTransportError("pairing request is not pending")
            self.trust_store.pair(candidate.peer_id,
                                  candidate.certificate_der, candidate.name)
            del self._pending[checked_id]
            return candidate

    def accept_outbound_pair(self, request_id: str) -> PairingCandidate:
        """Pin one requested certificate after local comparison-code approval."""
        checked_id = _canonical_uuid(request_id, "request_id")
        with self._pending_lock:
            self._expire_pending_locked(time.monotonic())
            candidate = self._outbound_pending.get(checked_id)
            if candidate is None:
                raise SecureTransportError(
                    "outbound pairing request is not pending")
            self.trust_store.pair(candidate.peer_id,
                                  candidate.certificate_der, candidate.name)
            del self._outbound_pending[checked_id]
            return candidate

    def decline_pair(self, request_id: str) -> PairingCandidate:
        """Remove and return one pending pairing candidate."""
        checked_id = _canonical_uuid(request_id, "request_id")
        with self._pending_lock:
            self._expire_pending_locked(time.monotonic())
            candidate = self._pending.pop(checked_id, None)
            if candidate is None:
                raise SecureTransportError("pairing request is not pending")
            return candidate

    def decline_outbound_pair(self, request_id: str) -> PairingCandidate:
        """Discard one requested certificate without trusting it."""
        checked_id = _canonical_uuid(request_id, "request_id")
        with self._pending_lock:
            self._expire_pending_locked(time.monotonic())
            candidate = self._outbound_pending.pop(checked_id, None)
            if candidate is None:
                raise SecureTransportError(
                    "outbound pairing request is not pending")
            return candidate

    def _authenticate(self, frame: dict[str, object],
                      nonce: str) -> tuple[str, str, str]:
        required = {"version", "type", "peer_id", "session_id",
                    "fingerprint", "signature"}
        _require_frame(frame, "SECURE_AUTH", required)
        peer_id = _canonical_uuid(frame["peer_id"], "peer_id")
        session_id = _canonical_uuid(frame["session_id"], "session_id")
        fingerprint = _validate_fingerprint(frame["fingerprint"])
        signature = _decode_base64(frame["signature"], MAX_SIGNATURE,
                                   "signature")
        record = self.trust_store.get(peer_id)
        if record is None:
            raise SecureTransportError("peer is not paired")
        if fingerprint != record.fingerprint:
            raise SecureTransportError("authentication fingerprint mismatch")
        transcript = _authentication_transcript(
            nonce, self.identity.fingerprint, peer_id, session_id, fingerprint)
        if not verify_signature(record.certificate_der, transcript, signature):
            raise SecureTransportError("authentication signature is invalid")
        return peer_id, session_id, fingerprint

    def _stage_pairing(self, frame: dict[str, object], nonce: str,
                       source_ip: str = "") -> PairingCandidate:
        required = {"version", "type", "request_id", "peer_id",
                    "session_id", "name", "certificate_der", "fingerprint",
                    "signature"}
        _require_frame(frame, "PAIR_REQUEST", required)
        request_id = _canonical_uuid(frame["request_id"], "request_id")
        peer_id = _canonical_uuid(frame["peer_id"], "peer_id")
        session_id = _canonical_uuid(frame["session_id"], "session_id")
        name = _validate_name(frame["name"])
        certificate_der = _decode_base64(
            frame["certificate_der"], MAX_CERTIFICATE_DER, "certificate")
        fingerprint = _validate_fingerprint(frame["fingerprint"])
        actual_fingerprint = _certificate_fingerprint(certificate_der, peer_id)
        if fingerprint != actual_fingerprint:
            raise SecureTransportError("pairing certificate fingerprint mismatch")
        signature = _decode_base64(frame["signature"], MAX_SIGNATURE,
                                   "signature")
        transcript = _pairing_transcript(
            nonce, self.identity.fingerprint, peer_id, session_id, fingerprint,
            request_id)
        if not verify_signature(certificate_der, transcript, signature):
            raise SecureTransportError("pairing signature is invalid")
        candidate = PairingCandidate(
            request_id, peer_id, session_id, name, certificate_der, fingerprint,
            _comparison_code(nonce, self.identity.fingerprint, fingerprint),
            time.monotonic(), source_ip)
        with self._pending_lock:
            self._expire_pending_locked(candidate.created)
            if request_id in self._pending:
                raise SecureTransportError("duplicate pairing request")
            if (len(self._pending) + len(self._outbound_pending)
                    >= self.max_pending):
                raise SecureTransportError("pending pairing limit reached")
            self._pending[request_id] = candidate
        return candidate

    def _expire_pending_locked(self, now: float) -> None:
        expired = [request_id for request_id, candidate in self._pending.items()
                   if now - candidate.created >= self.pairing_ttl]
        for request_id in expired:
            del self._pending[request_id]
        expired_outbound = [
            request_id
            for request_id, candidate in self._outbound_pending.items()
            if now - candidate.created >= self.pairing_ttl]
        for request_id in expired_outbound:
            del self._outbound_pending[request_id]

    def _emit_pairing(self, candidate: PairingCandidate) -> None:
        if self.emit is None:
            return
        try:
            self.emit("pair_request", candidate)
        except Exception:
            logger.exception("Pairing callback failed")

    def _observe_socket(self, conn: socket.socket | None, add: bool) -> None:
        if conn is not None and self.observe_socket is not None:
            self.observe_socket(conn, add)


def _server_context(identity: DeviceIdentity) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=str(identity.path), keyfile=str(identity.path))
    return context


def _client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _validate_local_hello(identity: DeviceIdentity, hello: Hello) -> None:
    _validate_hello_security(hello)
    if hello.peer_id != identity.peer_id:
        raise ValueError("local HELLO peer_id differs from identity")
    if hello.certificate_sha256 != identity.fingerprint:
        raise ValueError("local HELLO certificate differs from identity")


def _validate_peer(peer: Peer) -> Hello:
    if not isinstance(peer, Peer):
        raise SecureTransportError("peer must be a roster Peer")
    _validate_hello_security(peer.hello)
    if not isinstance(peer.ip, str) or not peer.ip or len(peer.ip) > 255:
        raise SecureTransportError("peer endpoint is invalid")
    return peer.hello


def _validate_hello_security(hello: Hello) -> None:
    if not isinstance(hello, Hello):
        raise SecureTransportError("secure metadata is missing")
    _canonical_uuid(hello.peer_id, "peer_id")
    _canonical_uuid(hello.session_id, "session_id")
    _validate_name(hello.name)
    if "secure_transport_v1" not in hello.capabilities:
        raise SecureTransportError("peer lacks secure_transport_v1")
    if type(hello.secure_port) is not int or not 1 <= hello.secure_port <= 65535:
        raise SecureTransportError("secure port is invalid")
    _validate_fingerprint(hello.certificate_sha256)


def _peer_certificate(tls_socket: ssl.SSLSocket) -> bytes:
    certificate = tls_socket.getpeercert(binary_form=True)
    if not isinstance(certificate, bytes) or not certificate:
        raise SecureTransportError("TLS peer did not present a certificate")
    if len(certificate) > MAX_CERTIFICATE_DER:
        raise SecureTransportError("TLS peer certificate is too large")
    return certificate


def _certificate_fingerprint(certificate_der: bytes, peer_id: str) -> str:
    try:
        return validate_certificate(certificate_der, peer_id)
    except IdentityError as error:
        raise SecureTransportError(str(error)) from error


def _receive_challenge(tls_socket: ssl.SSLSocket, hello: Hello,
                       expect_session: bool = True) -> dict[str, object]:
    frame = _receive_frame(tls_socket)
    required = {"version", "type", "nonce", "peer_id",
                "session_id", "fingerprint"}
    _require_frame(frame, "SECURE_CHALLENGE", required)
    _validate_nonce(frame["nonce"])
    session_id = _canonical_uuid(frame["session_id"], "session_id")
    if (_canonical_uuid(frame["peer_id"], "peer_id") != hello.peer_id
            or (expect_session and session_id != hello.session_id)
            or _validate_fingerprint(frame["fingerprint"])
            != hello.certificate_sha256):
        raise SecureTransportError("challenge differs from selected peer")
    return frame


def _receive_frame(tls_socket: ssl.SSLSocket) -> dict[str, object]:
    frame = recv_message(tls_socket, timeout=IO_TIMEOUT)
    if not isinstance(frame, dict):
        raise SecureTransportError("security frame is missing")
    return frame


def _require_frame(frame: dict[str, object], frame_type: str,
                   required: set[str]) -> None:
    if set(frame) != required:
        raise SecureTransportError(f"{frame_type} has invalid fields")
    if (type(frame.get("version")) is not int
            or frame["version"] != SECURITY_VERSION):
        raise SecureTransportError("unsupported security version")
    if frame.get("type") != frame_type:
        raise SecureTransportError(f"expected {frame_type}")


def _ready_frame(hello: Hello, fingerprint: str) -> dict[str, object]:
    return {
        "version": SECURITY_VERSION,
        "type": "SECURE_READY",
        "peer_id": hello.peer_id,
        "session_id": hello.session_id,
        "fingerprint": fingerprint,
    }


def _validate_ready(frame: dict[str, object], hello: Hello) -> None:
    required = {"version", "type", "peer_id", "session_id",
                "fingerprint"}
    _require_frame(frame, "SECURE_READY", required)
    if (_canonical_uuid(frame["peer_id"], "peer_id") != hello.peer_id
            or _canonical_uuid(frame["session_id"], "session_id")
            != hello.session_id
            or _validate_fingerprint(frame["fingerprint"])
            != hello.certificate_sha256):
        raise SecureTransportError("ready frame differs from selected peer")


def _validate_pending(frame: dict[str, object], request_id: str,
                      comparison_code: str) -> None:
    required = {"version", "type", "request_id", "comparison_code"}
    _require_frame(frame, "PAIR_PENDING", required)
    if (_canonical_uuid(frame["request_id"], "request_id") != request_id
            or frame.get("comparison_code") != comparison_code):
        raise SecureTransportError("pairing confirmation mismatch")


def _canonical_uuid(value: object, label: str) -> str:
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError("noncanonical UUID")
    except (ValueError, AttributeError) as error:
        raise SecureTransportError(f"invalid {label}") from error
    return value


def _validate_name(value: object) -> str:
    if (not isinstance(value, str) or not value.strip()
            or len(value) > MAX_NAME_LENGTH):
        raise SecureTransportError("name must contain 1 to 80 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SecureTransportError("name contains control characters")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise SecureTransportError("name is not valid Unicode") from error
    return value


def _validate_fingerprint(value: object) -> str:
    if (not isinstance(value, str) or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)):
        raise SecureTransportError("certificate fingerprint is invalid")
    return value


def _validate_nonce(value: object) -> str:
    if (not isinstance(value, str) or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)):
        raise SecureTransportError("challenge nonce is invalid")
    return value


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_base64(value: object, maximum: int, label: str) -> bytes:
    if (not isinstance(value, str) or not value or not value.isascii()
            or len(value) > ((maximum + 2) // 3) * 4):
        raise SecureTransportError(f"{label} is not bounded base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise SecureTransportError(f"{label} is not valid base64") from error
    if (not decoded or len(decoded) > maximum
            or _encode_base64(decoded) != value):
        raise SecureTransportError(f"{label} is not canonical base64")
    return decoded


def _authentication_transcript(nonce: str, server_fingerprint: str,
                               client_peer_id: str, client_session_id: str,
                               client_fingerprint: str) -> bytes:
    return _transcript(AUTH_DOMAIN, {
        "client_fingerprint": client_fingerprint,
        "client_peer_id": client_peer_id,
        "client_session_id": client_session_id,
        "nonce": nonce,
        "server_fingerprint": server_fingerprint,
    })


def _pairing_transcript(nonce: str, server_fingerprint: str,
                        client_peer_id: str, client_session_id: str,
                        client_fingerprint: str, request_id: str) -> bytes:
    return _transcript(PAIR_DOMAIN, {
        "client_fingerprint": client_fingerprint,
        "client_peer_id": client_peer_id,
        "client_session_id": client_session_id,
        "nonce": nonce,
        "request_id": request_id,
        "server_fingerprint": server_fingerprint,
    })


def _transcript(domain: bytes, fields: dict[str, str]) -> bytes:
    payload = json.dumps(fields, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":")).encode("ascii")
    return domain + payload


def _comparison_code(nonce: str, first_fingerprint: str,
                     second_fingerprint: str) -> str:
    fingerprints = sorted((first_fingerprint, second_fingerprint))
    digest = hashlib.sha256(
        PAIR_CODE_DOMAIN + bytes.fromhex(nonce)
        + bytes.fromhex(fingerprints[0]) + bytes.fromhex(fingerprints[1])
    ).hexdigest()[:16].upper()
    return "-".join(digest[index:index + 4]
                    for index in range(0, len(digest), 4))


def _close_sockets(tls_socket: ssl.SSLSocket | None,
                   raw_socket: socket.socket | None) -> None:
    if tls_socket is not None:
        try:
            tls_socket.close()
        except OSError:
            logger.debug("Could not close TLS socket", exc_info=True)
    if raw_socket is not None:
        try:
            raw_socket.close()
        except OSError:
            logger.debug("Could not close raw socket", exc_info=True)
