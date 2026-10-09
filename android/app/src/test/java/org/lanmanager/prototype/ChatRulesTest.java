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

    @Test public void dm_to_another_session_is_rejected() {
        String local = "00000000-0000-4000-8000-000000000001";
        String other = "00000000-0000-4000-8000-000000000002";
        assertFalse(ChatRules.acceptableDm(other, local));
        assertTrue(ChatRules.acceptableDm(local, local));
        assertFalse(ChatRules.acceptableDm(null, local));
    }

    @Test public void ack_must_match_sent_id() {
        String sent = "00000000-0000-4000-8000-000000000001";
        String other = "00000000-0000-4000-8000-000000000002";
        assertTrue(ChatRules.matchesAck(sent, sent));
        assertFalse(ChatRules.matchesAck(sent, other));
        assertFalse(ChatRules.matchesAck(sent, null));
    }

    @Test public void duplicate_message_id_is_dropped() {        ChatRules.ChatDedupe seen = new ChatRules.ChatDedupe();
        String session = "00000000-0000-4000-8000-000000000001";
        String message = "00000000-0000-4000-8000-000000000003";
        assertTrue(seen.fresh(session, message));
        assertFalse(seen.fresh(session, message));
    }

    @Test public void incoming_text_allows_desktop_range() {
        assertTrue(ChatRules.validIncomingText("hi"));
        assertTrue(ChatRules.validIncomingText("x".repeat(4096)));
        assertFalse(ChatRules.validIncomingText("  "));
        assertFalse(ChatRules.validIncomingText("x".repeat(4097)));
    }

    @Test public void malformed_frame_closes_without_value() throws Exception {
        java.net.ServerSocket listener = new java.net.ServerSocket(0);
        try (java.net.Socket writer = new java.net.Socket("127.0.0.1", listener.getLocalPort());
             java.net.Socket reader = listener.accept()) {
            writer.getOutputStream().write(new byte[]{0, 0, 0, 2, (byte) 0xFF, (byte) 0xFE});
            writer.getOutputStream().flush();
            try {
                Frames.receive(reader.getInputStream());
                assertFalse("malformed frame must throw", true);
            } catch (java.io.IOException expected) {
            }
        } finally {
            listener.close();
        }
    }

    @Test public void chat_and_echo_ports_are_pinned() {
        assertEquals(50001, ChatRules.CHAT_PORT);
        assertEquals(50002, ChatRules.ECHO_PORT);
    }
}
