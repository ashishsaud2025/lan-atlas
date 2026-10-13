"""Serve and merge cached feed pages between peers."""

from __future__ import annotations

import json
from typing import Any

from core.post_signatures import verify_post
from core.posts import validate_post, validate_tombstone
from core.protocol import MAX_MESSAGE_SIZE
from core.storage import PostStore

POST_PAGE_BYTE_BUDGET = MAX_MESSAGE_SIZE - 4096


def tombstoned_ids(store: PostStore) -> set[str]:
    """Return targets of valid signed tombstones across the whole store."""
    hidden: set[str] = set()
    cursor: dict[str, Any] | None = None
    while True:
        posts, cursor, complete = store.page(50, cursor)
        for post in posts:
            if not isinstance(post, dict) or "tombstone" not in post:
                continue
            try:
                tombstone = validate_tombstone(post)
            except ValueError:
                continue
            target = tombstone["tombstone"]["target"]
            assert isinstance(target, str)
            hidden.add(target)
        if complete:
            return hidden


def serve_query(store: PostStore, body: dict[str, Any]) -> dict[str, Any]:
    """Answer one POST_QUERY from local storage, including cached re-shares."""
    if type(body.get("limit")) is not int or not 1 <= body["limit"] <= 50:
        raise ValueError("page limit must be 1 to 50")
    limit = body["limit"]
    hidden = tombstoned_ids(store)
    bounded: list[dict[str, Any]] = []
    cursor = body.get("cursor")
    complete = True
    next_cursor: dict[str, Any] | None = cursor
    while len(bounded) < limit:
        posts, next_cursor, complete = store.page(
            limit, cursor, body.get("author_id"))
        budget_cut = False
        for post in posts:
            if len(bounded) >= limit:
                break
            if post["post_id"] in hidden:
                continue
            candidate = [*bounded, post]
            encoded = json.dumps(
                candidate, ensure_ascii=False, allow_nan=False,
                separators=(",", ":")).encode("utf-8")
            if len(encoded) > POST_PAGE_BYTE_BUDGET:
                budget_cut = True
                break
            bounded.append(post)
        if budget_cut:
            complete = False
            break
        if complete or len(bounded) >= limit:
            break
        cursor = next_cursor
    if bounded:
        last = bounded[-1]
        next_cursor = {
            "last_author": last["author_id"], "last_post": last["post_id"]}
    return {
        "posts": bounded,
        "next_cursor": next_cursor,
        "complete": complete,
    }


def merge_page(store: PostStore, posts: list[dict[str, Any]]) -> tuple[int, int]:
    """Validate and store one received page; return added and duplicate counts."""
    added = duplicates = 0
    for post in posts:
        validate_post(post)
        verification = verify_post(post)
        if verification.state == "invalid":
            raise ValueError(f"invalid signed post: {verification.reason}")
        if store.add(post):
            added += 1
        else:
            duplicates += 1
    return added, duplicates
