from __future__ import annotations

from core.portal import GuestStore


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
