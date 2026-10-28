from __future__ import annotations

import re
from pathlib import Path

from core.post_signatures import verify_post
from core.posts import validate_tombstone

FIXTURE = (Path(__file__).parents[1] / "android" / "app" / "src" / "test" /
           "resources" / "post-moderation-v1.properties")


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


def _post(values: dict[str, str], prefix: str, signed: bool) -> dict:
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
            tombstone["replacement"] = _post(values, f"{prefix}.replacement", True)
        post["tombstone"] = tombstone
    if signed:
        post["security"] = {
            "version": 1,
            "algorithm": "ecdsa-p256-sha256",
            "certificate": values[f"{prefix}.certificate"],
            "signature": values[f"{prefix}.signature"],
        }
    return post


def test_android_fixture_matches_desktop_signatures() -> None:
    values = _load()
    for prefix in ("target", "delete", "edit_target", "edit_tombstone",
                   "replacement", "attacker_tombstone"):
        assert verify_post(_post(values, prefix, True)).state == "signed", prefix
    assert verify_post(_post(values, "unsigned", False)).state == "unsigned"


def test_android_fixture_tombstones_are_valid_and_author_bound() -> None:
    values = _load()
    delete = validate_tombstone(_post(values, "delete", True))
    assert delete["tombstone"]["target"] == values["target.post_id"]
    edit = validate_tombstone(_post(values, "edit_tombstone", True))
    assert edit["tombstone"]["replacement"]["post_id"] == values["replacement.post_id"]
    attacker = validate_tombstone(_post(values, "attacker_tombstone", True))
    assert attacker["author_id"] == values["attacker_tombstone.author_id"]
    assert attacker["author_id"] != values["target.author_id"]


def test_android_fixture_exercises_canonical_json() -> None:
    values = _load()
    text = values["target.text"]
    assert "\n" in text and "\t" in text and '"' in text and "\\" in text
    assert "é" in text and "→" in text
    assert re.fullmatch("[0-9a-f]{64}", values["target.ref0.sha256"])


def test_android_fixture_rejects_tampering() -> None:
    values = _load()
    tampered = _post(values, "target", True)
    tampered["text"] = "changed after signing"
    assert verify_post(tampered).state == "invalid"
