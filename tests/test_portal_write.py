from __future__ import annotations

import http.client
import json
import socket
from uuid import uuid4

from core.chat import ChatService
from core.discovery import Hello
from core.portal import GuestStore, PortalServer
from core.roster import Peer


def _hello(name: str = "Portal host") -> Hello:
    return Hello(str(uuid4()), str(uuid4()), name, 50001,
                 ("chat_v1", "file_v1", "posts_v1"))


def _post(port: int, path: str, body: bytes, cookie: str | None = None,
          content_type: str = "application/json") -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        headers = {"Content-Type": content_type, "Content-Length": str(len(body))}
        if cookie is not None:
            headers["Cookie"] = cookie
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        return response.status, {name.lower(): value
                                 for name, value in response.getheaders()}, payload
    finally:
        connection.close()


def _room_sender(service: ChatService, peer: Peer):
    def send(display_name: str, text: str) -> str:
        return service.send(f"Guest {display_name}: {text}", (peer,))
    return send


def test_guest_claim_sets_cookie_and_labels_unverified() -> None:
    store = GuestStore()
    guest_id, header = store.claim("Phone A", None)
    assert store.resolve(header.split("=", 1)[1].split(";")[0]) == guest_id


def test_guest_spoof_of_paired_name_stays_unverified() -> None:
    store = GuestStore()
    guest_id, _ = store.claim("Host", None)
    assert store.display(guest_id) == "Host"
    assert store.identity(guest_id) == "unverified_guest"


def test_guest_forged_cookie_resolves_none() -> None:
    store = GuestStore()
    assert store.resolve("guest_id=deadbeef") is None
    assert store.resolve("guest_id=" + "0" * 32) is None


def test_portal_chat_send_journals_room_as_guest() -> None:
    hello = _hello()
    service = ChatService(hello)
    recipient = Hello(str(uuid4()), str(uuid4()), "Peer", 50001, ("chat_v1",))
    peer = Peer(recipient, "192.168.1.30", 1.0)
    portal = PortalServer(hello, service.peer_repository, None,
                          service.message_journal, None,
                          room_sender=_room_sender(service, peer),
                          allow_loopback=True)
    state = portal.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        status, headers, body = _post(
            state.port, "/api/chat/send",
            json.dumps({"display_name": "Phone", "text": "hi"}).encode("utf-8"))
        assert status == 200
        payload = json.loads(body)
        assert "message_id" in payload
        cookie = headers.get("set-cookie")
        assert cookie is not None and "guest_id=" in cookie
        connection = http.client.HTTPConnection("127.0.0.1", state.port, timeout=2)
        try:
            connection.request("GET", "/api/messages")
            messages = json.loads(connection.getresponse().read())
        finally:
            connection.close()
        assert [item["text"] for item in messages["items"]] == ["Guest Phone: hi"]
    finally:
        portal.stop()
        assert portal.join(3)


def test_portal_chat_rejects_malformed_utf8_and_oversize() -> None:
    hello = _hello()
    service = ChatService(hello)
    portal = PortalServer(hello, service.peer_repository, None,
                          service.message_journal, None,
                          room_sender=lambda display, text: "x",
                          allow_loopback=True)
    state = portal.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        status, _, _ = _post(state.port, "/api/chat/send", b"\xff\xfe")
        assert status == 400
        status, _, _ = _post(
            state.port, "/api/chat/send",
            json.dumps({"display_name": "P", "text": "x" * 2001}).encode("utf-8"))
        assert status == 413
    finally:
        portal.stop()
        assert portal.join(3)


def test_portal_chat_full_queue_returns_429() -> None:
    hello = _hello()
    service = ChatService(hello)

    def _full(display_name: str, text: str) -> str:
        raise RuntimeError("outbound queue full")

    portal = PortalServer(hello, service.peer_repository, None,
                          service.message_journal, None,
                          room_sender=_full, allow_loopback=True)
    state = portal.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        status, _, body = _post(
            state.port, "/api/chat/send",
            json.dumps({"display_name": "Phone", "text": "hi"}).encode("utf-8"))
        assert status == 429
        assert json.loads(body)["error"] == "Server busy, retry shortly."
    finally:
        portal.stop()
        assert portal.join(3)


def test_portal_feed_post_stores_unsigned_guest_copy(tmp_path) -> None:
    from core.storage import JsonLinesPostStore

    hello = _hello()
    service = ChatService(hello)
    store = JsonLinesPostStore(tmp_path / "posts.jsonl")
    portal = PortalServer(hello, service.peer_repository, store,
                          service.message_journal, None, allow_loopback=True)
    state = portal.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        status, _, body = _post(
            state.port, "/api/feed/post",
            json.dumps({"display_name": "Phone", "text": "hello feed"}).encode("utf-8"))
        assert status == 200
        post_id = json.loads(body)["post_id"]
        stored = store.get(post_id)
        assert stored is not None
        assert stored["text"] == "hello feed"
        assert stored.get("guest_name") == "Phone"
        assert "security" not in stored
        connection = http.client.HTTPConnection("127.0.0.1", state.port, timeout=2)
        try:
            connection.request("GET", "/api/feed")
            feed = json.loads(connection.getresponse().read())
        finally:
            connection.close()
        matches = [item for item in feed["items"] if item["post_id"] == post_id]
        assert len(matches) == 1
        assert matches[0]["provenance"] == "guest_unverified"
    finally:
        portal.stop()
        assert portal.join(3)


def test_portal_feed_rejects_oversize_and_empty(tmp_path) -> None:
    from core.storage import JsonLinesPostStore

    hello = _hello()
    service = ChatService(hello)
    store = JsonLinesPostStore(tmp_path / "posts.jsonl")
    portal = PortalServer(hello, service.peer_repository, store,
                          service.message_journal, None, allow_loopback=True)
    state = portal.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        status, _, _ = _post(
            state.port, "/api/feed/post",
            json.dumps({"display_name": "P", "text": "x" * 5001}).encode("utf-8"))
        assert status == 413
        status, _, _ = _post(
            state.port, "/api/feed/post",
            json.dumps({"display_name": "P", "text": "  "}).encode("utf-8"))
        assert status == 400
    finally:
        portal.stop()
        assert portal.join(3)


def _upload(port: int, filename: str, data: bytes,
            cookie: str | None = None) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        headers = {"Content-Type": "application/octet-stream",
                   "Content-Length": str(len(data)),
                   "X-Filename": filename, "X-Display-Name": "Phone"}
        if cookie is not None:
            headers["Cookie"] = cookie
        connection.request("POST", "/api/files/upload", body=data, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        return response.status, {name.lower(): value
                                 for name, value in response.getheaders()}, payload
    finally:
        connection.close()


def test_portal_files_upload_list_download(tmp_path) -> None:
    hello = _hello()
    service = ChatService(hello)
    portal = PortalServer(hello, service.peer_repository, None,
                          service.message_journal, None,
                          registry_root=tmp_path / "public",
                          allow_loopback=True)
    state = portal.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        status, _, body = _upload(state.port, "notes.txt", b"hello public")
        assert status == 200
        entry = json.loads(body)
        assert entry["name"] == "notes.txt"
        assert len(entry["sha256"]) == 64
        connection = http.client.HTTPConnection("127.0.0.1", state.port, timeout=2)
        try:
            connection.request("GET", "/api/files/list")
            listing = json.loads(connection.getresponse().read())
        finally:
            connection.close()
        assert listing["available"] is True
        assert [item["name"] for item in listing["items"]] == ["notes.txt"]
        connection = http.client.HTTPConnection("127.0.0.1", state.port, timeout=2)
        try:
            connection.request("GET", "/api/files/download?id=notes.txt")
            response = connection.getresponse()
            data = response.read()
            digest = response.getheader("X-SHA256")
        finally:
            connection.close()
        assert data == b"hello public"
        assert digest == entry["sha256"]
    finally:
        portal.stop()
        assert portal.join(3)


def test_portal_files_reject_traversal_and_oversize(tmp_path) -> None:
    hello = _hello()
    service = ChatService(hello)
    portal = PortalServer(hello, service.peer_repository, None,
                          service.message_journal, None,
                          registry_root=tmp_path / "public",
                          allow_loopback=True)
    state = portal.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        status, _, _ = _upload(state.port, "../../x", b"a")
        assert status == 400
        status, _, _ = _upload(state.port, "dup.txt", b"1")
        assert status == 200
        status, _, _ = _upload(state.port, "dup.txt", b"2")
        assert status == 409
    finally:
        portal.stop()
        assert portal.join(3)


def test_pages_expose_guest_forms_and_plaintext_warning(tmp_path) -> None:
    from core.storage import JsonLinesPostStore

    hello = _hello()
    service = ChatService(hello)
    store = JsonLinesPostStore(tmp_path / "posts.jsonl")
    portal = PortalServer(hello, service.peer_repository, store,
                          service.message_journal, None,
                          room_sender=lambda display, text: "x",
                          registry_root=tmp_path / "public",
                          allow_loopback=True)
    state = portal.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        for path in ("/chat", "/feed", "/files"):
            connection = http.client.HTTPConnection("127.0.0.1", state.port, timeout=2)
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                page = response.read().decode("utf-8")
                assert response.status == 200
            finally:
                connection.close()
            assert "<form" in page
        connection = http.client.HTTPConnection("127.0.0.1", state.port, timeout=2)
        try:
            connection.request("GET", "/chat")
            chat_page = connection.getresponse().read().decode("utf-8")
        finally:
            connection.close()
        assert "plaintext" in chat_page.lower()
    finally:
        portal.stop()
        assert portal.join(3)


def test_portal_accepts_plain_browser_form_posts(tmp_path) -> None:
    from urllib.parse import urlencode

    from core.storage import JsonLinesPostStore

    hello = _hello()
    service = ChatService(hello)
    recipient = Hello(str(uuid4()), str(uuid4()), "Peer", 50001, ("chat_v1",))
    peer = Peer(recipient, "192.168.1.30", 1.0)
    store = JsonLinesPostStore(tmp_path / "posts.jsonl")
    portal = PortalServer(hello, service.peer_repository, store,
                          service.message_journal, None,
                          room_sender=_room_sender(service, peer),
                          registry_root=tmp_path / "public",
                          allow_loopback=True)
    state = portal.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        body = urlencode({"display_name": "Browser", "text": "form hi"}).encode("utf-8")
        connection = http.client.HTTPConnection("127.0.0.1", state.port, timeout=2)
        try:
            connection.request("POST", "/api/chat/send", body=body,
                               headers={"Content-Type": "application/x-www-form-urlencoded",
                                        "Content-Length": str(len(body))})
            assert connection.getresponse().status == 200
        finally:
            connection.close()
        body = urlencode({"display_name": "Browser", "text": "form post"}).encode("utf-8")
        connection = http.client.HTTPConnection("127.0.0.1", state.port, timeout=2)
        try:
            connection.request("POST", "/api/feed/post", body=body,
                               headers={"Content-Type": "application/x-www-form-urlencoded",
                                        "Content-Length": str(len(body))})
            assert connection.getresponse().status == 200
        finally:
            connection.close()
        assert store.count() == 1
    finally:
        portal.stop()
        assert portal.join(3)


def test_portal_accepts_multipart_file_upload(tmp_path) -> None:
    boundary = "----form1234"
    payload = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="display_name"\r\n\r\n'
        "Browser\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="form.txt"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("latin-1") + b"form bytes" + f"\r\n--{boundary}--\r\n".encode("latin-1")
    hello = _hello()
    service = ChatService(hello)
    portal = PortalServer(hello, service.peer_repository, None,
                          service.message_journal, None,
                          registry_root=tmp_path / "public",
                          allow_loopback=True)
    state = portal.start("127.0.0.1", 0)
    assert state.port is not None
    try:
        connection = http.client.HTTPConnection("127.0.0.1", state.port, timeout=10)
        try:
            connection.request("POST", "/api/files/upload", body=payload,
                               headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                                        "Content-Length": str(len(payload))})
            response = connection.getresponse()
            assert response.status == 200
            entry = json.loads(response.read())
        finally:
            connection.close()
        assert entry["name"] == "form.txt"
        connection = http.client.HTTPConnection("127.0.0.1", state.port, timeout=2)
        try:
            connection.request("GET", "/api/files/download?id=form.txt")
            assert connection.getresponse().read() == b"form bytes"
        finally:
            connection.close()
    finally:
        portal.stop()
        assert portal.join(3)
