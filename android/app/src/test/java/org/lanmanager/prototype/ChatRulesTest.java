package org.lanmanager.prototype;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class ChatRulesTest {
    @Test public void text_enforces_bounds() {
        assertTrue(ChatRules.validText("hi"));
        assertFalse(ChatRules.validText("  "));
        assertFalse(ChatRules.validText(null));
        assertFalse(ChatRules.validText("x".repeat(2001)));
    }

    @Test public void require_text_strips_and_rejects() {
        assertEquals("hi", ChatRules.requireText("  hi  "));
        try {
            ChatRules.requireText("   ");
            assertFalse("blank text must throw", true);
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test public void bounds_are_pinned() {
        assertEquals(2000, ChatRules.MAX_TEXT);
        assertEquals(200, ChatRules.MAX_HISTORY);
        assertEquals(1024, ChatRules.DEDUPE_BOUND);
    }

    @Test public void chat_and_echo_ports_are_pinned() {
        assertEquals(50001, ChatRules.CHAT_PORT);
        assertEquals(50002, ChatRules.ECHO_PORT);
    }
}
