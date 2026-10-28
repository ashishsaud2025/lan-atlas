package org.lanmanager.prototype;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.Test;

public final class FeedRulesTest {
    private static final String ID = "00000000-0000-4000-8000-000000000001";
    private static final String AUTHOR = "00000000-0000-4000-8000-000000000002";
    private final Properties fixture = PostFixtures.load();

    @Test public void text_enforces_bounds() {
        assertTrue(FeedRules.validText("hi"));
        assertFalse(FeedRules.validText("  "));
        assertFalse(FeedRules.validText(null));
        assertFalse(FeedRules.validText("x".repeat(5001)));
    }

    @Test public void uuid_requires_canonical_spelling() {
        assertTrue(FeedRules.validUuid(ID));
        assertFalse(FeedRules.validUuid("NOT-A-UUID"));
        assertFalse(FeedRules.validUuid(null));
    }

    @Test public void cursor_orders_stably() {
        assertTrue(FeedRules.afterCursor("a", "1", "a", "2"));
        assertFalse(FeedRules.afterCursor("a", "2", "a", "1"));
        assertFalse(FeedRules.afterCursor("a", "1", "a", "1"));
        assertTrue(FeedRules.afterCursor(null, null, "a", "1"));
    }

    @Test public void invalid_page_rejected_whole() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        assertEquals(1, cache.putValidated(ID, AUTHOR, "hi", 1));
        Map<String, Object> bad = new HashMap<>();
        bad.put("post_id", "00000000-0000-4000-8000-000000000009");
        Map<String, Object> good = new HashMap<>();
        good.put("post_id", ID);
        good.put("author_id", AUTHOR);
        good.put("text", "hi");
        good.put("created_ms", 2L);
        try {
            cache.mergeInto(Arrays.asList(bad, good));
            assertFalse("invalid page must throw", true);
        } catch (IllegalArgumentException expected) {
        }
        assertEquals(1, cache.servePage(50, null, null).posts.size());
    }

    @Test public void staged_duplicates_count_once() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        Map<String, Object> post = new HashMap<>();
        post.put("post_id", ID);
        post.put("author_id", AUTHOR);
        post.put("text", "hi");
        post.put("created_ms", 1L);
        assertEquals(1, cache.mergeInto(Arrays.asList(post, post)));
        assertEquals(1, cache.servePage(50, null, null).posts.size());
    }

    @Test public void author_page_filters_before_limit() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        String other = "00000000-0000-4000-8000-000000000003";
        for (int index = 0; index < 4; index++) {
            String id = String.format("00000000-0000-4000-8000-%012d", index);
            assertEquals(1, cache.putValidated(id, other, "post", index));
        }
        String mine = "00000000-0000-4000-8000-000000000009";
        assertEquals(1, cache.putValidated(mine, AUTHOR, "mine", 9));
        FeedRules.FeedCache.FeedPage page = cache.servePage(2, null, AUTHOR);
        assertEquals(1, page.posts.size());
        assertTrue(page.complete);
    }

    @Test public void duplicate_ids_merge_once() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        assertEquals(1, cache.putValidated(ID, AUTHOR, "hi", 1));
        assertEquals(0, cache.putValidated(ID, AUTHOR, "hi", 1));
        assertEquals(1, cache.servePage(50, null, null).posts.size());
    }

    @Test public void paging_honors_limit_and_cursor() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        for (int index = 0; index < 5; index++) {
            String id = String.format("00000000-0000-4000-8000-%012d", index);
            assertEquals(1, cache.putValidated(id, AUTHOR, "post", index));
        }
        assertEquals(2, cache.servePage(2, null, null).posts.size());
        Map<String, Object> cursor = new HashMap<>();
        cursor.put("last_author", AUTHOR);
        cursor.put("last_post", "00000000-0000-4000-8000-000000000001");
        assertEquals(3, cache.servePage(50, cursor, null).posts.size());
    }

    @Test public void signed_post_page_keeps_signature_and_refs() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        Map<String, Object> target = PostFixtures.signed(fixture, "target");
        assertEquals(1, cache.mergeInto(Arrays.asList(target)));
        Map<String, Object> served = cache.servePage(50, null, null).posts.get(0);
        Map<?, ?> security = (Map<?, ?>) served.get("security");
        assertEquals(fixture.getProperty("target.certificate"), security.get("certificate"));
        assertEquals(1, ((List<?>) served.get("refs")).size());
    }

    @Test public void verified_tombstone_hides_target_from_serving() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        Map<String, Object> target = PostFixtures.signed(fixture, "target");
        Map<String, Object> tombstone = PostFixtures.signed(fixture, "delete");
        assertEquals(2, cache.mergeInto(Arrays.asList(target, tombstone)));
        assertTrue(cache.hiddenIds().contains(fixture.getProperty("target.post_id")));
        assertEquals(PostSignatures.State.SIGNED,
            cache.stateOf(fixture.getProperty("delete.post_id")));
        List<String> served = ids(cache.servePage(50, null, null));
        assertFalse(served.contains(fixture.getProperty("target.post_id")));
        assertTrue(served.contains(fixture.getProperty("delete.post_id")));
    }

    @Test public void tombstone_before_target_still_hides() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        cache.mergeInto(Arrays.asList(PostFixtures.signed(fixture, "delete")));
        cache.mergeInto(Arrays.asList(PostFixtures.signed(fixture, "target")));
        assertFalse(ids(cache.servePage(50, null, null))
            .contains(fixture.getProperty("target.post_id")));
    }

    @Test public void attacker_tombstone_cannot_hide_foreign_post() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        cache.mergeInto(Arrays.asList(
            PostFixtures.signed(fixture, "target"),
            PostFixtures.signed(fixture, "attacker_tombstone")));
        assertTrue(cache.hiddenIds().isEmpty());
        assertTrue(ids(cache.servePage(50, null, null))
            .contains(fixture.getProperty("target.post_id")));
    }

    @Test public void unsigned_tombstone_cannot_hide_anything() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        Map<String, Object> tombstone = PostFixtures.unsigned(fixture, "unsigned");
        tombstone.put("post_id", "00000000-0000-4000-8000-000000000108");
        Map<String, Object> mapping = new HashMap<>();
        mapping.put("target", fixture.getProperty("target.post_id"));
        tombstone.put("tombstone", mapping);
        cache.mergeInto(Arrays.asList(PostFixtures.signed(fixture, "target"), tombstone));
        assertTrue(cache.hiddenIds().isEmpty());
        assertEquals(PostSignatures.State.UNSIGNED, cache.stateOf(
            "00000000-0000-4000-8000-000000000108"));
    }

    @Test public void invalid_signed_post_rejects_whole_page() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        cache.mergeInto(Arrays.asList(PostFixtures.signed(fixture, "target")));
        Map<String, Object> tampered = PostFixtures.signed(fixture, "target");
        tampered.put("post_id", "00000000-0000-4000-8000-000000000109");
        tampered.put("text", "forged after signing");
        try {
            cache.mergeInto(Arrays.asList(
                PostFixtures.unsigned(fixture, "unsigned"), tampered));
            assertFalse("invalid page must throw", true);
        } catch (IllegalArgumentException expected) {
        }
        assertEquals(1, cache.servePage(50, null, null).posts.size());
        assertFalse(cache.servePage(50, null, null).posts.get(0).get("post_id")
            .equals(fixture.getProperty("unsigned.post_id")));
    }

    @Test public void edit_tombstone_marks_and_reveals_replacement() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        cache.mergeInto(Arrays.asList(
            PostFixtures.signed(fixture, "edit_target"),
            PostFixtures.signed(fixture, "edit_tombstone"),
            PostFixtures.signed(fixture, "replacement")));
        assertTrue(cache.hiddenIds().contains(fixture.getProperty("edit_target.post_id")));
        assertTrue(cache.editedIds().contains(fixture.getProperty("replacement.post_id")));
        List<String> display = new ArrayList<>();
        for (Map<String, Object> post : cache.displayPage(50)) {
            display.add((String) post.get("post_id"));
        }
        assertFalse(display.contains(fixture.getProperty("edit_target.post_id")));
        assertTrue(display.contains(fixture.getProperty("replacement.post_id")));
        assertTrue(display.contains(fixture.getProperty("edit_tombstone.post_id")));
    }

    @Test public void serving_pages_skip_hidden_targets_without_stalling() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        cache.mergeInto(Arrays.asList(
            PostFixtures.signed(fixture, "target"),
            PostFixtures.signed(fixture, "delete"),
            PostFixtures.unsigned(fixture, "unsigned")));
        FeedRules.FeedCache.FeedPage first = cache.servePage(1, null, null);
        assertEquals(1, first.posts.size());
        assertFalse(first.complete);
        assertEquals(fixture.getProperty("delete.post_id"),
            first.posts.get(0).get("post_id"));
        Map<String, Object> cursor = new HashMap<>();
        cursor.put("last_author", first.posts.get(0).get("author_id"));
        cursor.put("last_post", first.posts.get(0).get("post_id"));
        FeedRules.FeedCache.FeedPage second = cache.servePage(1, cursor, null);
        assertEquals(1, second.posts.size());
        assertTrue(second.complete);
        assertEquals(fixture.getProperty("unsigned.post_id"),
            second.posts.get(0).get("post_id"));
        assertNull(second.posts.get(0).get("security"));
        assertNotNull(second.posts.get(0).get("text"));
    }

    @Test public void serving_caps_pages_below_the_frame_budget() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        for (int index = 0; index < 25; index++) {
            String id = String.format("00000000-0000-4000-8000-%012d", index);
            assertEquals(1, cache.putValidated(id, AUTHOR, "post", index));
        }
        FeedRules.FeedCache.FeedPage first = cache.servePage(50, null, null);
        assertEquals(16, first.posts.size());
        assertFalse(first.complete);
        Map<String, Object> cursor = new HashMap<>();
        cursor.put("last_author", AUTHOR);
        cursor.put("last_post", first.posts.get(first.posts.size() - 1).get("post_id"));
        FeedRules.FeedCache.FeedPage second = cache.servePage(50, cursor, null);
        assertEquals(9, second.posts.size());
        assertTrue(second.complete);
    }

    @Test public void text_rejects_unpaired_surrogates() {
        assertFalse(FeedRules.validText("bad \ud800 text"));
        assertTrue(FeedRules.validText("emoji \ud83d\ude00"));
    }

    @Test public void serving_honors_byte_budget() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        for (int index = 0; index < 5; index++) {
            String id = String.format("00000000-0000-4000-8000-%012d", index);
            assertEquals(1, cache.putValidated(id, AUTHOR, "post", index));
        }
        Map<String, Object> first = cache.servePage(50, null, null).posts.get(0);
        long single = FeedRules.estimateBytes(first);
        FeedRules.FeedCache.FeedPage page = cache.servePage(50, null, null, single * 2);
        assertEquals(2, page.posts.size());
        assertFalse(page.complete);
        Map<String, Object> cursor = new HashMap<>();
        cursor.put("last_author", page.posts.get(1).get("author_id"));
        cursor.put("last_post", page.posts.get(1).get("post_id"));
        FeedRules.FeedCache.FeedPage next = cache.servePage(50, cursor, null);
        assertEquals(3, next.posts.size());
        assertTrue(next.complete);
    }

    @Test public void local_posts_trim_to_the_cache_bound() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        for (int index = 0; index < FeedRules.CACHE_BOUND + 5; index++) {
            String id = String.format("00000000-0000-4000-8000-%012d", index);
            assertEquals(1, cache.putValidated(id, AUTHOR, "post", index));
        }
        assertEquals(FeedRules.CACHE_BOUND, cache.size());
    }

    @Test public void merged_posts_are_stored_as_copies() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        Map<String, Object> target = PostFixtures.signed(fixture, "target");
        assertEquals(1, cache.mergeInto(Arrays.asList(target)));
        target.put("text", "mutated after merge");
        assertFalse("mutated after merge".equals(
            cache.servePage(50, null, null).posts.get(0).get("text")));
    }

    @Test public void display_snapshot_reports_evidence_consistently() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        cache.mergeInto(Arrays.asList(
            PostFixtures.signed(fixture, "edit_target"),
            PostFixtures.signed(fixture, "edit_tombstone"),
            PostFixtures.signed(fixture, "replacement")));
        FeedRules.FeedCache.DisplaySnapshot snapshot = cache.displaySnapshot(50);
        assertTrue(snapshot.edited.contains(fixture.getProperty("replacement.post_id")));
        assertEquals(PostSignatures.State.SIGNED, snapshot.states.get(
            fixture.getProperty("edit_tombstone.post_id")));
        assertFalse(snapshot.states.containsKey(fixture.getProperty("edit_target.post_id")));
    }

    private static List<String> ids(FeedRules.FeedCache.FeedPage page) {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> post : page.posts) {
            out.add((String) post.get("post_id"));
        }
        return out;
    }
}
