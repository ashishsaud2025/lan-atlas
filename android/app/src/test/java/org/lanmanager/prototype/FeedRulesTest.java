package org.lanmanager.prototype;

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
}
