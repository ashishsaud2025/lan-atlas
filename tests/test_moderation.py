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
