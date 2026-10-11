from __future__ import annotations

from core.resume import ReceiveManifest, SendManifest

TID = "00000000-0000-4000-8000-000000000001"
PID = "00000000-0000-4000-8000-000000000002"
SID = "00000000-0000-4000-8000-000000000003"


def _receive_record(**overrides):
    record = {"transfer_id": TID, "name": "notes.txt", "size": 10,
              "sha256": "a" * 64, "held": 4, "peer_id": PID,
              "session_id": SID}
    record.update(overrides)
    return record


def test_corrupt_manifest_discards_to_none(tmp_path):
    (tmp_path / "resume.json").write_text("{broken", encoding="utf-8")
    assert ReceiveManifest.load(tmp_path, "notes.txt") is None


def test_expired_manifest_loads_none(tmp_path):
    import json
    record = _receive_record(saved_ms=1)
    (tmp_path / ("notes.txt." + "resume.json")).write_text(
        json.dumps(record), encoding="utf-8")
    assert ReceiveManifest.load(tmp_path, "notes.txt") is None


def test_save_load_round_trip(tmp_path):
    ReceiveManifest.save(tmp_path, _receive_record())
    loaded = ReceiveManifest.load(tmp_path, "notes.txt")
    assert loaded is not None
    assert loaded["held"] == 4
    assert loaded["sha256"] == "a" * 64


def test_send_manifest_round_trip(tmp_path):
    SendManifest.save(tmp_path, {"transfer_id": TID, "path": "notes.txt",
                                 "peer_id": PID, "session_id": SID})
    loaded = SendManifest.load(tmp_path, TID)
    assert loaded is not None
    assert loaded["peer_id"] == PID
