package org.lanmanager.prototype;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class FeedRulesTest {
    private static final String ID = "00000000-0000-4000-8000-000000000001";
    private static final String AUTHOR = "00000000-0000-4000-8000-000000000002";

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
        java.util.Map<String, String> bad = new java.util.HashMap<>();
        bad.put("post_id", "00000000-0000-4000-8000-000000000009");
        java.util.Map<String, String> good = new java.util.HashMap<>();
        good.put("post_id", ID);
        good.put("author_id", AUTHOR);
        good.put("text", "hi");
        good.put("created_ms", "2");
        assertEquals(0, cache.mergeInto(java.util.Arrays.asList(bad, good)));
        assertEquals(1, cache.ordered(50, null).size());
    }

    @Test public void duplicate_ids_merge_once() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        String id = "00000000-0000-4000-8000-000000000001";
        String author = "00000000-0000-4000-8000-000000000002";
        assertEquals(1, cache.putValidated(id, author, "hi", 1));
        assertEquals(0, cache.putValidated(id, author, "hi", 1));
        assertEquals(1, cache.ordered(50, null).size());
    }

    @Test public void paging_honors_limit_and_cursor() {
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        for (int index = 0; index < 5; index++) {
            String id = String.format("00000000-0000-4000-8000-%012d", index);
            assertEquals(1, cache.putValidated(id, AUTHOR, "post", index));
        }
        assertEquals(2, cache.ordered(2, null).size());
        java.util.Map<String, Object> cursor = new java.util.HashMap<>();
        cursor.put("last_author", AUTHOR);
        cursor.put("last_post", "00000000-0000-4000-8000-000000000001");
        assertEquals(3, cache.ordered(50, cursor).size());
    }
}
