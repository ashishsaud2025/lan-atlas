package org.lanmanager.prototype;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    /** Bounded memory post cache keyed by post ID with stable ordering. */
    public static final class FeedCache {
        private final Map<String, Map<String, Object>> posts = new LinkedHashMap<>() {
            @Override protected boolean removeEldestEntry(
                    Map.Entry<String, Map<String, Object>> eldest) {
                return size() > CACHE_BOUND;
            }
        };

        public synchronized int putValidated(String id, String author, String text,
                                             long createdMs) {
            if (!validUuid(id) || !validUuid(author) || !validText(text)) return 0;
            if (posts.containsKey(id)) return 0;
            Map<String, Object> post = new LinkedHashMap<>();
            post.put("post_id", id);
            post.put("author_id", author);
            post.put("text", text);
            post.put("created_ms", createdMs);
            posts.put(id, post);
            return 1;
        }

        public synchronized int mergeInto(List<Map<String, String>> page) {
            List<Map<String, Object>> staged = new ArrayList<>();
            for (Map<String, String> raw : page) {
                String id = raw.get("post_id");
                String author = raw.get("author_id");
                String text = raw.get("text");
                long created;
                try {
                    created = Long.parseLong(raw.get("created_ms"));
                } catch (NumberFormatException | NullPointerException error) {
                    return 0;
                }
                if (!validUuid(id) || !validUuid(author) || !validText(text)) return 0;
                if (posts.containsKey(id)) continue;
                Map<String, Object> post = new LinkedHashMap<>();
                post.put("post_id", id);
                post.put("author_id", author);
                post.put("text", text);
                post.put("created_ms", created);
                staged.add(post);
            }
            for (Map<String, Object> post : staged) {
                posts.put((String) post.get("post_id"), post);
                while (posts.size() > CACHE_BOUND) {
                    posts.remove(posts.keySet().iterator().next());
                }
            }
            return staged.size();
        }

        public synchronized List<Map<String, Object>> ordered(int limit,
                                                              Map<String, Object> cursor) {
            String lastAuthor = cursor == null ? null : (String) cursor.get("last_author");
            String lastPost = cursor == null ? null : (String) cursor.get("last_post");
            List<Map<String, Object>> sorted = new ArrayList<>(posts.values());
            Collections.sort(sorted, Comparator.comparing(
                post -> sortKey((String) post.get("author_id"), (String) post.get("post_id"))));
            List<Map<String, Object>> page = new ArrayList<>();
            for (Map<String, Object> post : sorted) {
                if (page.size() >= Math.min(limit, PAGE_LIMIT)) break;
                if (afterCursor(lastAuthor, lastPost,
                        (String) post.get("author_id"), (String) post.get("post_id"))) {
                    page.add(Collections.unmodifiableMap(post));
                }
            }
            return page;
        }
    }
}
