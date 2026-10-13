from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from core.post_signatures import sign_post
from core.posts import validate_tombstone

TARGET = "00000000-0000-4000-8000-000000000001"


class SigningIdentity:
    def __init__(self, author_id: str) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, author_id)])
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(self._key, hashes.SHA256())
        )
        self.certificate_der = certificate.public_bytes(serialization.Encoding.DER)

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data, ec.ECDSA(hashes.SHA256()))


def _signed_target(author_id: str | None = None) -> dict[str, object]:
    target = {
        "post_id": str(uuid4()),
        "author_id": author_id or str(uuid4()),
        "text": "original",
        "created_ms": 123456,
        "refs": [],
    }
    return sign_post(target, SigningIdentity(target["author_id"]))


def _signed_tombstone() -> dict[str, object]:
    signed_target = _signed_target()
    tombstone = {
        "post_id": str(uuid4()),
        "author_id": signed_target["author_id"],
        "text": "tombstone",
        "created_ms": 123457,
        "refs": [],
        "tombstone": {"target": signed_target["post_id"]},
    }
    return sign_post(tombstone, SigningIdentity(signed_target["author_id"]))


def test_tombstone_validation() -> None:
    tombstone = _signed_tombstone()
    assert validate_tombstone(tombstone)["tombstone"]["target"] == tombstone["tombstone"]["target"]
    unsigned = dict(tombstone)
    del unsigned["security"]
    with pytest.raises(ValueError):
        validate_tombstone(unsigned)
    bad = dict(tombstone)
    bad["tombstone"] = {"target": "not-a-uuid"}
    with pytest.raises(ValueError):
        validate_tombstone(bad)


def test_forged_tombstone_key_rejected() -> None:
    tombstone = _signed_tombstone()
    forged = dict(tombstone)
    forged["author_id"] = str(uuid4())
    with pytest.raises(ValueError):
        validate_tombstone(forged)
    assert TARGET != tombstone["tombstone"]["target"]


def test_sync_hides_tombstoned_target(tmp_path):
    from core.feed import serve_query
    from core.storage import JsonLinesPostStore
    store = JsonLinesPostStore(tmp_path / 'posts.jsonl')
    target = _signed_target()
    from core.post_signatures import sign_post as _sign
    author = SigningIdentity(target['author_id'])
    store.add(_sign(dict(target), author))
    tombstone = {
        'post_id': str(uuid4()),
        'author_id': target['author_id'],
        'text': 'tombstone',
        'created_ms': 123457,
        'refs': [],
        'tombstone': {'target': target['post_id']},
    }
    tomb_id = store.add(_sign(tombstone, author)) and tombstone['post_id']
    page = serve_query(store, {'limit': 50, 'cursor': None, 'author_id': None})
    ids = [post['post_id'] for post in page['posts']]
    assert target['post_id'] not in ids and tomb_id in ids


def test_tombstone_before_target_still_hides(tmp_path):
    from core.feed import merge_page, serve_query
    from core.post_signatures import sign_post
    from core.storage import JsonLinesPostStore
    store = JsonLinesPostStore(tmp_path / 'posts.jsonl')
    target = _signed_target()
    author = SigningIdentity(target['author_id'])
    tombstone = {
        'post_id': str(uuid4()),
        'author_id': target['author_id'],
        'text': 'tombstone',
        'created_ms': 123457,
        'refs': [],
        'tombstone': {'target': target['post_id']},
    }
    signed_tomb = sign_post(tombstone, author)
    added, _ = merge_page(store, [signed_tomb])
    assert added == 1
    added, _ = merge_page(store, [target])
    assert added == 1
    page = serve_query(store, {'limit': 50, 'cursor': None, 'author_id': None})
    ids = [post['post_id'] for post in page['posts']]
    assert target['post_id'] not in ids
    assert signed_tomb['post_id'] in ids


def _secure_service(tmp_path, name='Local'):
    import socket as _socket
    from pathlib import Path as _Path
    from core.chat import ChatService
    from core.discovery import Hello
    from core.identity import DeviceIdentity
    from core.secure_transport import SecureTransport
    from core.storage import JsonLinesPostStore
    from core.trust import TrustStore
    from uuid import uuid4 as _uuid4
    peer_id = str(_uuid4())

    def _free_port():
        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    identity = DeviceIdentity.load_or_create(tmp_path / (name + '.pem'), peer_id)
    hello = Hello(peer_id, str(_uuid4()), name, _free_port(),
                  ('chat_v1', 'file_v1', 'posts_v1', 'secure_transport_v1'),
                  _free_port(), identity.fingerprint)
    transport = SecureTransport(identity, TrustStore(tmp_path / (name + '-trust.json')), hello)
    store = JsonLinesPostStore(tmp_path / (name + '-posts.jsonl'))
    service = ChatService(hello, discovery_port=_free_port(), post_store=store,
                          secure_transport=transport)
    return service


def test_delete_and_edit_signed_post(tmp_path):
    service = _secure_service(tmp_path)
    post_id = service.publish_post('original')
    tomb_id = service.delete_post(post_id)
    assert tomb_id != post_id
    with pytest.raises(ValueError):
        service.delete_post('00000000-0000-4000-8000-000000000099')
    post_id2 = service.publish_post('version one')
    edit_id = service.edit_post(post_id2, 'version two')
    assert edit_id != post_id2
    with pytest.raises(ValueError):
        service.edit_post(post_id2, '   ')
