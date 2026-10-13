"""Optional certificate-backed signatures for immutable posts."""

from __future__ import annotations

import base64
import copy
import json
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from core.posts import POST_SECURITY_ALGORITHM, POST_SECURITY_VERSION, validate_post

SIGNING_PREFIX = b"LAN-MANAGER-POST-V1\x00"


class PostSigner(Protocol):
    """Minimum device identity interface needed to sign a post."""

    certificate_der: bytes
    fingerprint: str

    def sign(self, data: bytes) -> bytes:
        """Return a DER-encoded ECDSA signature for data."""
        ...


@dataclass(frozen=True)
class PostVerification:
    """Immutable outcome of inspecting a post's optional signature."""

    state: Literal["unsigned", "signed", "invalid"]
    fingerprint: str | None = None
    reason: str | None = None


def _signing_payload(post: dict[str, Any]) -> bytes:
    fields = {
        "post_id": post["post_id"],
        "author_id": post["author_id"],
        "text": post["text"],
        "created_ms": post["created_ms"],
        "refs": post.get("refs", []),
    }
    if "tombstone" in post:
        fields["tombstone"] = post["tombstone"]
    try:
        encoded = json.dumps(
            fields,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("post signing fields must be JSON-compatible") from exc
    return SIGNING_PREFIX + encoded


def _load_certificate(certificate_der: bytes) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(certificate_der)
    except ValueError as exc:
        raise ValueError("post certificate is not valid DER") from exc


def _validate_certificate(certificate: x509.Certificate, author_id: str) -> None:
    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ValueError("post certificate public key must be P-256")
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != author_id:
        raise ValueError("post certificate subject CN must equal author_id")


def sign_post(post: dict[str, Any], identity: PostSigner) -> dict[str, Any]:
    """Return an isolated copy of a post with version-one signature metadata."""
    signed_post = copy.deepcopy(post)
    signed_post.pop("security", None)
    validate_post(signed_post)

    certificate_der = bytes(identity.certificate_der)
    certificate = _load_certificate(certificate_der)
    _validate_certificate(certificate, signed_post["author_id"])
    payload = _signing_payload(signed_post)
    signature = bytes(identity.sign(payload))
    try:
        certificate.public_key().verify(
            signature, payload, ec.ECDSA(hashes.SHA256())
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("identity returned an invalid post signature") from exc

    signed_post["security"] = {
        "version": POST_SECURITY_VERSION,
        "algorithm": POST_SECURITY_ALGORITHM,
        "certificate": base64.b64encode(certificate_der).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    validate_post(signed_post)
    return signed_post


def verify_post(post: dict[str, Any]) -> PostVerification:
    """Classify a post as unsigned, correctly signed, or invalid."""
    try:
        validate_post(post)
    except (TypeError, ValueError) as exc:
        return PostVerification("invalid", reason=f"post validation failed: {exc}")
    if "security" not in post:
        return PostVerification("unsigned")

    security = post["security"]
    certificate_der = base64.b64decode(security["certificate"], validate=True)
    signature = base64.b64decode(security["signature"], validate=True)
    fingerprint: str | None = None
    try:
        certificate = _load_certificate(certificate_der)
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        _validate_certificate(certificate, post["author_id"])
        certificate.public_key().verify(
            signature, _signing_payload(post), ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        return PostVerification(
            "invalid", fingerprint=fingerprint, reason="post signature does not match"
        )
    except (TypeError, ValueError) as exc:
        return PostVerification("invalid", fingerprint=fingerprint, reason=str(exc))
    return PostVerification("signed", fingerprint=fingerprint)
