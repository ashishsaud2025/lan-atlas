from __future__ import annotations

from pathlib import Path

import pytest

from core.public_files import PublicFileRegistry


def test_publish_and_download_round_trip_with_hash(tmp_path: Path) -> None:
    registry = PublicFileRegistry(tmp_path)
    entry = registry.publish("notes.txt", b"hello", guest="Phone")
    path, sha256 = registry.open_file(entry["file_id"])
    assert path.read_bytes() == b"hello"
    assert sha256 == entry["sha256"]
    assert len(registry.list()) == 1


def test_reject_traversal_oversize_and_no_overwrite(tmp_path: Path) -> None:
    registry = PublicFileRegistry(tmp_path)
    with pytest.raises(ValueError):
        registry.publish("../../x", b"a", guest="P")
    with pytest.raises(ValueError):
        registry.publish("big.bin", b"x" * (67108864 + 1), guest="P")
    registry.publish("a.txt", b"1", guest="P")
    with pytest.raises(ValueError):
        registry.publish("a.txt", b"2", guest="P")
