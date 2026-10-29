from __future__ import annotations

import re
from pathlib import Path

from core.post_signatures import verify_post
from core.posts import validate_tombstone

FIXTURE = (Path(__file__).parents[1] / "android" / "app" / "src" / "test" /
           "resources" / "post-phone-signed-v1.properties")


def _unescape(value: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character != "\\":
            out.append(character)
            index += 1
            continue
        index += 1
        if index >= len(value):
            out.append("\\")
            break
        escape = value[index]
        index += 1
        if escape == "u":
            out.append(chr(int(value[index:index + 4], 16)))
            index += 4
        else:
            out.append({"n": "\n", "r": "\r", "t": "\t", "f": "\f"}.get(escape, escape))
    return "".join(out)


def _load() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in FIXTURE.read_text(encoding="ascii").splitlines():
        if not line or line.startswith(("#", "!")):
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = _unescape(value)
    return values


def _post(values: dict[str, str], prefix: str) -> dict:
    post: dict = {
        "post_id": values[f"{prefix}.post_id"],
        "author_id": values[f"{prefix}.author_id"],
        "text": values[f"{prefix}.text"],
        "created_ms": int(values[f"{prefix}.created_ms"]),
        "refs": [],
    }
    refs = []
    index = 0
    while f"{prefix}.ref{index}.kind" in values:
        ref = {"kind": values[f"{prefix}.ref{index}.kind"]}
        for key in ("id", "name", "sha256"):
            if f"{prefix}.ref{index}.{key}" in values:
                ref[key] = values[f"{prefix}.ref{index}.{key}"]
        if f"{prefix}.ref{index}.size" in values:
            ref["size"] = int(values[f"{prefix}.ref{index}.size"])
        refs.append(ref)
        index += 1
    post["refs"] = refs
    if f"{prefix}.tombstone.target" in values:
        tombstone = {"target": values[f"{prefix}.tombstone.target"]}
        if f"{prefix}.replacement.post_id" in values:
            tombstone["replacement"] = _post(values, f"{prefix}.replacement")
        post["tombstone"] = tombstone
    if f"{prefix}.certificate" in values:
        post["security"] = {
            "version": 1,
            "algorithm": "ecdsa-p256-sha256",
            "certificate": values[f"{prefix}.certificate"],
            "signature": values[f"{prefix}.signature"],
        }
    return post


def test_phone_fixture_posts_verify_with_the_desktop_verifier() -> None:
    values = _load()
    fingerprints = set()
    for prefix in ("post", "delete", "edit_target", "edit_replacement",
                   "edit_tombstone"):
        verification = verify_post(_post(values, prefix))
        assert verification.state == "signed", prefix
        fingerprints.add(verification.fingerprint)
    assert len(fingerprints) == 1


def test_phone_fixture_tombstones_hide_their_targets() -> None:
    values = _load()
    delete = validate_tombstone(_post(values, "delete"))
    assert delete["tombstone"]["target"] == values["post.post_id"]
    edit = validate_tombstone(_post(values, "edit_tombstone"))
    assert edit["tombstone"]["target"] == values["edit_target.post_id"]
    assert (edit["tombstone"]["replacement"]["post_id"]
            == values["edit_replacement.post_id"])
    assert edit["author_id"] == edit["tombstone"]["replacement"]["author_id"]


def test_phone_fixture_keeps_canonical_signature_fields() -> None:
    values = _load()
    text = values["post.text"]
    assert "\n" in text and "\t" in text and '"' in text and "\\" in text
    assert "\u00e9" in text and "\u2192" in text
    assert values["post.ref0.name"] == "phone notes.txt"
    assert re.fullmatch("[0-9a-f]{64}", values["post.ref0.sha256"])
    assert values["post.author_id"] == values["edit_tombstone.author_id"]


def test_phone_fixture_rejects_tampering() -> None:
    values = _load()
    tampered = _post(values, "post")
    tampered["text"] = "changed after signing"
    assert verify_post(tampered).state == "invalid"
    replacement = _post(values, "edit_tombstone")
    replacement["tombstone"]["replacement"]["text"] = "changed after signing"
    assert verify_post(replacement).state == "invalid"
