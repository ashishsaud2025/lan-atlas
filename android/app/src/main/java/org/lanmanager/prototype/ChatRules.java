package org.lanmanager.prototype;

import java.util.LinkedHashMap;
import java.util.Map;

/** Shared chat rules mirroring the desktop framed CHAT contract. */
public final class ChatRules {
    public static final int MAX_TEXT = 2000;
    public static final int MAX_INCOMING_TEXT = 4096;
    public static final int MAX_HISTORY = 200;
    public static final int DEDUPE_BOUND = 1024;
    public static final int CHAT_PORT = 50001;
    public static final int ECHO_PORT = 50002;

    private ChatRules() {}

    public static boolean validText(String value) {
        if (value == null || value.length() > MAX_TEXT) return false;
        return !value.codePoints().allMatch(character ->
            Character.isWhitespace(character) || Character.isSpaceChar(character));
    }

    public static String requireText(String value) {
        if (!validText(value)) throw new IllegalArgumentException("Invalid chat text");
        return value;
    }

    public static boolean validIncomingText(String value) {
        if (value == null || value.isBlank() || value.length() > MAX_INCOMING_TEXT) return false;
        return true;
    }

    public static boolean acceptableDm(String toSession, String localSession) {
        if (toSession == null || localSession == null) return false;
        return toSession.equals(localSession);
    }

    public static boolean acceptsChat(int port) {
        return port == CHAT_PORT;
    }

    public static boolean matchesAck(String sentId, String replyTo, String replyPeerId,
                                     String replySessionId, String peerId, String sessionId) {
        if (sentId == null || replyTo == null || replyPeerId == null
                || replySessionId == null || peerId == null || sessionId == null) return false;
        return sentId.equals(replyTo) && replyPeerId.equals(peerId)
            && replySessionId.equals(sessionId);
    }

    /** Bounded duplicate tracker keyed by sender session plus message ID. */
    public static final class ChatDedupe {
        private final Map<String, Boolean> seen = new LinkedHashMap<>() {
            @Override protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                return size() > DEDUPE_BOUND;
            }
        };

        public synchronized boolean fresh(String sessionId, String messageId) {
            String key = sessionId + "\u0000" + messageId;
            if (seen.containsKey(key)) return false;
            seen.put(key, Boolean.TRUE);
            return true;
        }
    }
}
