"""Bounded file transfers over dedicated framed TCP connections."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from dataclasses import dataclass, field
import hashlib
import logging
import os
from pathlib import Path
import select
import socket
import ssl
import threading
import time
from typing import Any, BinaryIO
from uuid import UUID, uuid4

from core.discovery import Hello
from core.protocol import (
    MAX_FILE_SIZE, ProtocolError, envelope, recv_message, send_message,
    validate_envelope,
)
from core.resume import ReceiveManifest, SendManifest
from core.roster import Peer, candidate_ips
from core.secure_transport import SecureTransportError

CHUNK_SIZE = 64 * 1024
MAX_TRANSFERS = 4
OFFER_TIMEOUT = 60.0
VERIFY_TIMEOUT = 300.0


class TransferError(ProtocolError):
    """A transfer failed validation or was cancelled."""


def validate_offer(message: dict[str, Any], local_session: str) -> dict[str, Any]:
    """Validate an offer before publishing it to the receiving user."""
    validate_envelope(message)
    body = message["body"]
    if message["type"] != "FILE_OFFER" or body.get("to_session") != local_session:
        raise TransferError("offer addressed to a different session")
    try:
        identifier = body.get("transfer_id")
        if not isinstance(identifier, str) or str(UUID(identifier)) != identifier:
            raise ValueError("noncanonical UUID")
    except ValueError as error:
        raise TransferError("invalid transfer ID") from error
    name = body.get("name")
    if (not isinstance(name, str) or not name.strip() or len(name) > 255
            or name in {".", ".."} or any(c in name for c in "/\\:")
            or any(ord(c) < 32 for c in name)):
        raise TransferError("invalid offered filename")
    size = body.get("size")
    if type(size) is not int or not 0 <= size <= MAX_FILE_SIZE:
        raise TransferError("file size exceeds the 1 GiB limit")
    digest = body.get("sha256")
    if (not isinstance(digest, str) or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)):
        raise TransferError("invalid SHA-256")
    resume = body.get("resume_id")
    if resume is not None:
        try:
            if not isinstance(resume, str) or str(UUID(resume)) != resume:
                raise ValueError("noncanonical UUID")
        except ValueError as error:
            raise TransferError("invalid resume ID") from error
    return body


def validate_accept(body: dict[str, Any], size: int) -> int:
    """Validate an accept offset against the offered file size."""
    if not isinstance(body, dict):
        raise TransferError("accept must be an object")
    try:
        identifier = body.get("transfer_id")
        if not isinstance(identifier, str) or str(UUID(identifier)) != identifier:
            raise ValueError("noncanonical UUID")
    except ValueError as error:
        raise TransferError("invalid transfer ID") from error
    offset = body.get("offset", 0)
    if (type(offset) is not int or type(size) is not int
            or not 0 <= size <= MAX_FILE_SIZE or not 0 <= offset <= size):
        raise TransferError("accept offset outside offered size")
    return offset


@dataclass
class Transfer:
    """Lifecycle state shared through explicit locks and cancellation events."""

    identifier: str
    cancel: threading.Event = field(default_factory=threading.Event)
    decision: threading.Event = field(default_factory=threading.Event)
    destination: Path | None = None
    conn: socket.socket | None = None
    thread: threading.Thread | None = None
    last_progress: float = 0
    authenticated: bool = False
    connected: bool = False


class TransferService:
    """Limit active transfers and publish UI-independent lifecycle events."""

    def __init__(self, hello: Hello,
                 emit: Callable[[str, Any], bool],
                 connector: Callable[[Peer], tuple[socket.socket, bool]]
                 | None = None,
                 observe_socket: Callable[[socket.socket, bool], object]
                 | None = None) -> None:
        self.hello = hello
        self.emit = emit
        self.connector = connector or self._connect_plaintext
        self.observe_socket = observe_socket
        self._lock = threading.Lock()
        self._transfers: dict[str, Transfer] = {}
        self._stopped = False

    def _launch(self, identifier: str, action: Callable[[Transfer], None],
                 conn: socket.socket | None = None,
                 authenticated: bool = False) -> None:
        with self._lock:
            if self._stopped or len(self._transfers) >= MAX_TRANSFERS:
                raise TransferError("transfer limit reached or service stopped")
            if identifier in self._transfers:
                raise TransferError("duplicate active transfer ID")
            transfer = Transfer(identifier, conn=conn,
                                authenticated=authenticated,
                                connected=conn is not None)
            if conn is not None and self.observe_socket is not None:
                self.observe_socket(conn, True)
            transfer.thread = threading.Thread(target=self._execute,
                                               args=(transfer, action), daemon=True)
            self._transfers[identifier] = transfer
            transfer.thread.start()

    def _execute(self, transfer: Transfer, action: Callable[[Transfer], None]) -> None:
        try:
            action(transfer)
        except (OSError, ProtocolError, SecureTransportError, ValueError) as error:
            state = "cancelled" if transfer.cancel.is_set() else "failed"
            self._status(transfer, state, message=str(error))
        finally:
            if transfer.conn is not None:
                transfer.conn.close()
                if self.observe_socket is not None:
                    self.observe_socket(transfer.conn, False)
            with self._lock:
                self._transfers.pop(transfer.identifier, None)

    def send(self, path: Path, peer: Peer) -> str:
        """Hash and offer a file on a bounded background worker."""
        if "file_v1" not in peer.hello.capabilities:
            raise TransferError("peer does not advertise file_v1")
        identifier = str(uuid4())
        self._launch(identifier, lambda transfer: self._send(transfer, path, peer))
        return identifier

    def resume_pending(self, peer: Peer, directory: Path) -> str | None:
        """Re-offer one interrupted send; changed sources restart fresh."""
        if "file_v1" not in peer.hello.capabilities:
            raise TransferError("peer does not advertise file_v1")
        for record in SendManifest.scan(Path(directory)):
            if record["peer_id"] != peer.hello.peer_id:
                continue
            path = Path(record["path"])
            if not path.is_file():
                SendManifest.discard(Path(directory), record["transfer_id"])
                continue
            with path.open("rb") as stream:
                size = 0
                digest = hashlib.sha256()
                while True:
                    chunk = stream.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
            if (record.get("size") != size
                    or record.get("sha256") != digest.hexdigest()):
                SendManifest.discard(Path(directory), record["transfer_id"])
                return self.send(path, peer)
            identifier = record["transfer_id"]
            self._launch(identifier,
                         lambda transfer: self._send(transfer, path, peer, True))
            return identifier
        return None

    def receive(self, conn: socket.socket, message: dict[str, Any],
                authenticated: bool = False) -> None:
        """Take ownership of an offer connection only after successful admission."""
        body = validate_offer(message, self.hello.session_id)
        self._launch(body["transfer_id"],
                     lambda transfer: self._receive(transfer, message), conn,
                     authenticated)

    def decide(self, identifier: str, destination: Path | None) -> bool:
        """Accept with an explicit new destination, or decline with None."""
        with self._lock:
            transfer = self._transfers.get(identifier)
            if transfer is None or transfer.decision.is_set() or transfer.cancel.is_set():
                return False
            transfer.destination = destination
            transfer.decision.set()
            return True

    def cancel(self, identifier: str) -> None:
        """Interrupt a pending offer or established transfer in either direction."""
        with self._lock:
            transfer = self._transfers.get(identifier)
            if transfer is not None:
                transfer.cancel.set()
                transfer.decision.set()
                if transfer.conn is not None:
                    try:
                        transfer.conn.shutdown(socket.SHUT_RDWR)
                    except OSError as error:
                        logging.debug("Transfer shutdown raced close: %s", error)
                    # Shutdown does not wake a recv blocked on the same
                    # socket on Windows, so close to interrupt it promptly.
                    try:
                        transfer.conn.close()
                    except OSError as error:
                        logging.debug("Transfer close raced worker: %s", error)

    def stop(self) -> None:
        """Cancel all active work and reject new transfers."""
        with self._lock:
            self._stopped = True
            identifiers = tuple(self._transfers)
        for identifier in identifiers:
            self.cancel(identifier)

    def join(self, timeout: float = 6.0) -> bool:
        """Wait for active workers outside the GUI event loop."""
        with self._lock:
            threads = tuple(item.thread for item in self._transfers.values())
        deadline = time.monotonic() + timeout
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))
        return not any(thread.is_alive() for thread in threads)

    def _check(self, transfer: Transfer) -> None:
        if transfer.cancel.is_set():
            raise TransferError("transfer cancelled")

    def _status(self, transfer: Transfer, state: str, **values: Any) -> None:
        self.emit("transfer", {"id": transfer.identifier, "state": state,
                               "authenticated": transfer.authenticated,
                               "connected": transfer.connected, **values})

    def _progress(self, transfer: Transfer, state: str, count: int, total: int) -> None:
        now = time.monotonic()
        if now - transfer.last_progress >= 0.1 or count == total:
            transfer.last_progress = now
            self._status(transfer, state, bytes=count, total=total)

    def _hash(self, transfer: Transfer, stream: BinaryIO) -> tuple[int, str]:
        digest = hashlib.sha256()
        size = 0
        while True:
            self._check(transfer)
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_SIZE:
                raise TransferError("file exceeds 1 GiB limit")
            digest.update(chunk)
        return size, digest.hexdigest()

    def _write(self, transfer: Transfer, kind: str, **body: Any) -> None:
        self._check(transfer)
        send_message(transfer.conn, envelope(kind, self.hello.peer_id,
                                             self.hello.session_id,
                                             {"transfer_id": transfer.identifier, **body}))

    def _read(self, transfer: Transfer, peer_id: str, session_id: str,
              timeout: float = 5.0) -> dict[str, Any]:
        self._check(transfer)
        message = recv_message(transfer.conn, timeout)
        if message is None:
            raise TransferError("peer closed before transfer completion")
        validate_envelope(message)
        if (message["peer_id"] != peer_id or message["session_id"] != session_id
                or message["body"].get("transfer_id") != transfer.identifier):
            raise TransferError("transfer identity mismatch")
        return message

    def _send(self, transfer: Transfer, path: Path, peer: Peer,
              resume: bool = False) -> None:
        self._status(transfer, "hashing", name=path.name)
        manifest_dir = path.parent
        with path.open("rb") as stream:
            size, digest = self._hash(transfer, stream)
            SendManifest.save(manifest_dir, {
                "transfer_id": transfer.identifier, "path": str(path),
                "size": size, "sha256": digest,
                "peer_id": peer.hello.peer_id, "session_id": peer.hello.session_id})
            stream.seek(0)
            transfer.conn, transfer.authenticated = self.connector(peer)
            transfer.connected = True
            if self.observe_socket is not None:
                self.observe_socket(transfer.conn, True)
            offer_body: dict[str, Any] = {
                "transfer_id": transfer.identifier, "name": path.name,
                "size": size, "sha256": digest,
                "to_session": peer.hello.session_id}
            if resume:
                offer_body["resume_id"] = transfer.identifier
            offer = envelope("FILE_OFFER", self.hello.peer_id, self.hello.session_id,
                             offer_body)
            validate_offer(offer, peer.hello.session_id)
            self._check(transfer)
            send_message(transfer.conn, offer)
            self._status(transfer, "offered", name=path.name, total=size)
            reply = self._read(transfer, peer.hello.peer_id, peer.hello.session_id,
                               OFFER_TIMEOUT + 5)
            if reply["type"] == "FILE_DECLINE":
                SendManifest.discard(manifest_dir, transfer.identifier)
                self._status(transfer, "declined")
                return
            if reply["type"] != "FILE_ACCEPT":
                raise TransferError("expected FILE_ACCEPT")
            offset = validate_accept(reply["body"], size)
            sent_hash = hashlib.sha256()
            if offset:
                remaining = offset
                while remaining:
                    self._check(transfer)
                    prefix = stream.read(min(CHUNK_SIZE, remaining))
                    if not prefix:
                        raise TransferError("source shrank after hashing")
                    sent_hash.update(prefix)
                    remaining -= len(prefix)
            while True:
                self._check(transfer)
                chunk = stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                if offset + len(chunk) > size:
                    raise TransferError("source file grew during transfer")
                self._write(transfer, "FILE_CHUNK", offset=offset,
                            data=base64.b64encode(chunk).decode("ascii"))
                offset += len(chunk)
                sent_hash.update(chunk)
                self._progress(transfer, "queued", offset, size)
            if offset != size or sent_hash.hexdigest() != digest:
                raise TransferError("source changed after hashing")
            self._write(transfer, "FILE_DONE")
            self._status(transfer, "awaiting_verification", bytes=offset, total=size)
            reply = self._read(transfer, peer.hello.peer_id, peer.hello.session_id,
                               VERIFY_TIMEOUT)
            if (reply["type"] != "FILE_RESULT" or reply["body"].get("sha256") != digest
                    or reply["body"].get("size") != size
                    or reply["body"].get("status") != "verified"):
                raise TransferError("receiver did not verify file")
            SendManifest.discard(manifest_dir, transfer.identifier)
            self._status(transfer, "verified", bytes=size, total=size)

    def _decline(self, transfer: Transfer) -> None:
        # Best effort so the sender stops waiting; failures surface via status.
        try:
            send_message(transfer.conn, envelope("FILE_DECLINE", self.hello.peer_id,
                                                 self.hello.session_id,
                                                 {"transfer_id": transfer.identifier}))
        except (OSError, ProtocolError, ValueError) as error:
            logging.debug("Could not send transfer decline: %s", error)

    def _wait_decision(self, transfer: Transfer) -> None:
        # Poll so sender disconnect during the wait ends the offer promptly.
        deadline = time.monotonic() + OFFER_TIMEOUT
        while not transfer.decision.wait(0.2):
            self._check(transfer)
            if time.monotonic() >= deadline:
                raise TransferError("offer expired without a decision")
            conn = transfer.conn
            if conn is None:
                continue
            try:
                readable, _, _ = select.select([conn], [], [], 0)
            except (OSError, ValueError):
                raise TransferError("sender disconnected during offer")
            if readable:
                if isinstance(conn, ssl.SSLSocket):
                    raise TransferError(
                        "sender disconnected or sent unexpected data during offer")
                try:
                    probe = conn.recv(1, socket.MSG_PEEK)
                except OSError as error:
                    raise TransferError("sender disconnected during offer") from error
                if not probe:
                    raise TransferError("sender closed before decision")
                raise TransferError("unexpected data before accept")

    def _publish(self, temporary: Path, destination: Path) -> None:
        # Atomic hard-link publication refuses a racing existing destination.
        try:
            os.link(temporary, destination)
            return
        except FileExistsError as error:
            raise TransferError("destination already exists; choose a new filename") from error
        except OSError as error:
            raise TransferError(
                "cannot publish without overwriting; choose a filesystem supporting hard links"
            ) from error

    def _receive(self, transfer: Transfer, offer: dict[str, Any]) -> None:
        body = offer["body"]
        accepted = False
        declined = False
        temporary: Path | None = None
        resume_dir: Path | None = None
        resume_name: str | None = None
        try:
            if not self.emit("file_offer", {"id": transfer.identifier, "name": body["name"],
                                            "size": body["size"], "peer_id": offer["peer_id"],
                                            "authenticated": transfer.authenticated}):
                raise TransferError("offer queue full")
            try:
                self._wait_decision(transfer)
            except TransferError:
                self._decline(transfer)
                declined = True
                raise
            self._check(transfer)
            destination = transfer.destination
            if destination is None:
                self._write(transfer, "FILE_DECLINE")
                declined = True
                self._status(transfer, "declined")
                return
            if destination.exists():
                raise TransferError("destination already exists; choose a new filename")
            resume_dir, resume_name = destination.parent, destination.name
            manifest = ReceiveManifest.load(resume_dir, resume_name)
            part = resume_dir / (resume_name + ".part")
            offset = 0
            if self._resume_match(manifest, offer, body):
                assert manifest is not None
                offset = manifest["held"]
                if not part.is_file() or part.stat().st_size != offset:
                    ReceiveManifest.discard(resume_dir, resume_name)
                    raise TransferError("held bytes changed; restart the transfer")
            elif part.exists():
                ReceiveManifest.discard(resume_dir, resume_name)
                try:
                    part.unlink()
                except OSError as error:
                    raise TransferError("cannot clear stale partial file") from error
                ReceiveManifest.save(resume_dir, {
                    "transfer_id": transfer.identifier, "name": resume_name,
                    "size": body["size"], "sha256": body["sha256"], "held": 0,
                    "peer_id": offer["peer_id"], "session_id": offer["session_id"]})
                part.touch()
            else:
                ReceiveManifest.save(resume_dir, {
                    "transfer_id": transfer.identifier, "name": resume_name,
                    "size": body["size"], "sha256": body["sha256"], "held": 0,
                    "peer_id": offer["peer_id"], "session_id": offer["session_id"]})
                part.touch()
            temporary = part
            with temporary.open("r+b") as stream:
                stream.seek(offset)
                self._write(transfer, "FILE_ACCEPT", offset=offset)
                accepted = True
                count = offset
                while True:
                    message = self._read(transfer, offer["peer_id"], offer["session_id"])
                    if message["type"] == "FILE_DONE":
                        if count != body["size"]:
                            raise TransferError("file ended before advertised size")
                        break
                    chunk_body = message["body"]
                    if (message["type"] != "FILE_CHUNK"
                            or type(chunk_body.get("offset")) is not int
                            or chunk_body["offset"] != count):
                        raise TransferError("unexpected chunk or offset")
                    data = chunk_body.get("data")
                    if not isinstance(data, str) or len(data) > 4 * ((CHUNK_SIZE + 2) // 3):
                        raise TransferError("oversized encoded chunk")
                    try:
                        chunk = base64.b64decode(data, validate=True)
                    except (ValueError, binascii.Error) as error:
                        raise TransferError("invalid Base64 chunk") from error
                    if not 1 <= len(chunk) <= CHUNK_SIZE or count + len(chunk) > body["size"]:
                        raise TransferError("chunk exceeds offered size or chunk limit")
                    stream.write(chunk)
                    count += len(chunk)
                    ReceiveManifest.save(resume_dir, {
                        "transfer_id": transfer.identifier, "name": resume_name,
                        "size": body["size"], "sha256": body["sha256"], "held": count,
                        "peer_id": offer["peer_id"], "session_id": offer["session_id"]})
                    self._progress(transfer, "written", count, body["size"])
                stream.flush()
                os.fsync(stream.fileno())
            self._status(transfer, "verifying", bytes=count, total=body["size"])
            with temporary.open("rb") as stream:
                size, digest = self._hash(transfer, stream)
            if size != body["size"] or digest != body["sha256"]:
                raise TransferError("received file failed SHA-256 verification")
            self._check(transfer)
            self._publish(temporary, destination)
            ReceiveManifest.discard(resume_dir, resume_name)
            try:
                temporary.unlink()
            except OSError as error:
                logging.error("Cannot remove transfer part file %s: %s", temporary, error)
            temporary = None
            self._status(transfer, "saved", path=str(destination), bytes=size, total=size)
            self._write(transfer, "FILE_RESULT", status="verified", size=size, sha256=digest)
        except (OSError, ProtocolError, ValueError):
            if not accepted and not declined:
                self._decline(transfer)
            raise
        finally:
            if temporary is not None and resume_dir is None:
                try:
                    temporary.unlink()
                except OSError as error:
                    logging.error("Cannot remove transfer temporary file %s: %s", temporary, error)

    @staticmethod
    def _resume_match(manifest: dict[str, Any] | None, offer: dict[str, Any],
                      body: dict[str, Any]) -> bool:
        """Match a resume offer against one stored manifest."""
        if manifest is None:
            return False
        return (body.get("resume_id") == manifest["transfer_id"] == body["transfer_id"]
                and manifest["size"] == body["size"]
                and manifest["sha256"] == body["sha256"]
                and manifest["peer_id"] == offer["peer_id"])

    @staticmethod
    def _connect_plaintext(peer: Peer) -> tuple[socket.socket, bool]:
        error: OSError | None = None
        for address in candidate_ips(peer):
            try:
                return (socket.create_connection(
                    (address, peer.hello.tcp_port), timeout=3), False)
            except OSError as exc:
                error = exc
                continue
        assert error is not None
        raise error
