package org.lanmanager.prototype;

import java.util.UUID;

/** Shared feed rules mirroring the desktop post paging contract. */
public final class FeedRules {
    public static final int MAX_TEXT = 5000;
    public static final int PAGE_LIMIT = 50;
    public static final int CACHE_BOUND = 200;

    private FeedRules() {}

    public static boolean validText(String value) {
        if (value == null || value.length() > MAX_TEXT) return false;
        return !value.codePoints().allMatch(character ->
            Character.isWhitespace(character) || Character.isSpaceChar(character));
    }

    public static boolean validUuid(String value) {
        if (value == null) return false;
        try {
            return UUID.fromString(value).toString().equals(value);
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    public static String sortKey(String authorId, String postId) {
        return authorId + "|" + postId;
    }

    public static boolean afterCursor(String lastAuthor, String lastPost,
                                      String author, String post) {
        if (lastAuthor == null || lastPost == null) return true;
        return sortKey(author, post).compareTo(sortKey(lastAuthor, lastPost)) > 0;
    }
}
