package org.lanmanager.prototype;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Shared feed rules mirroring the desktop post paging and moderation contract. */
public final class FeedRules {
    public static final int MAX_TEXT = 4096;
    public static final int PAGE_LIMIT = 50;
    public static final int CACHE_BOUND = 200;
    // 16 worst-case signed posts stay below the 1 MiB frame even with escaped text.
    private static final int SERVE_PAGE_LIMIT = 16;

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
        private final Map<String, Map<String, Object>> posts = new LinkedHashMap<>();
        private final Map<String, PostSignatures.State> states = new HashMap<>();

        public synchronized int putValidated(String id, String author, String text,
                                             long createdMs) {
            if (!validUuid(id) || !validUuid(author) || !validText(text)) return 0;
            if (posts.containsKey(id)) return 0;
            Map<String, Object> post = new LinkedHashMap<>();
            post.put("post_id", id);
            post.put("author_id", author);
            post.put("text", text);
            post.put("created_ms", createdMs);
            post.put("refs", new ArrayList<>());
            PostSignatures.validate(post);
            posts.put(id, post);
            states.put(id, PostSignatures.State.UNSIGNED);
            return 1;
        }

        /** Validate, verify, then merge a whole page or leave the cache untouched. */
        public int mergeInto(List<Map<String, Object>> page) {
            List<Map<String, Object>> verified = new ArrayList<>();
            List<PostSignatures.State> verifiedStates = new ArrayList<>();
            for (Map<String, Object> raw : page) {
                PostSignatures.Verification verification = PostSignatures.verify(raw);
                if (verification.state == PostSignatures.State.INVALID) {
                    throw new IllegalArgumentException(
                        "Invalid signed post: " + verification.reason);
                }
                verified.add(raw);
                verifiedStates.add(verification.state);
            }
            synchronized (this) {
                List<Map<String, Object>> staged = new ArrayList<>();
                List<PostSignatures.State> stagedStates = new ArrayList<>();
                Set<String> stagedIds = new HashSet<>();
                for (int index = 0; index < verified.size(); index++) {
                    Map<String, Object> post = verified.get(index);
                    String id = (String) post.get("post_id");
                    if (posts.containsKey(id) || !stagedIds.add(id)) continue;
                    staged.add(post);
                    stagedStates.add(verifiedStates.get(index));
                }
                for (int index = 0; index < staged.size(); index++) {
                    Map<String, Object> post = staged.get(index);
                    String id = (String) post.get("post_id");
                    posts.put(id, post);
                    states.put(id, stagedStates.get(index));
                }
                while (posts.size() > CACHE_BOUND) {
                    String eldest = posts.keySet().iterator().next();
                    posts.remove(eldest);
                    states.remove(eldest);
                }
                return staged.size();
            }
        }

        /** Verification state cached with the post, if it is still present. */
        public synchronized PostSignatures.State stateOf(String postId) {
            PostSignatures.State state = states.get(postId);
            return state == null ? PostSignatures.State.UNSIGNED : state;
        }

        /** Targets hidden by a verified signed tombstone from the same author. */
        public synchronized Set<String> hiddenIds() {
            Set<String> hidden = new HashSet<>();
            for (Map.Entry<String, Map<String, Object>> entry : posts.entrySet()) {
                if (states.get(entry.getKey()) != PostSignatures.State.SIGNED) continue;
                Map<String, Object> tombstone = tombstoneOf(entry.getValue());
                if (tombstone == null) continue;
                String target = (String) tombstone.get("target");
                Map<String, Object> targetPost = posts.get(target);
                if (targetPost == null) continue;
                if (entry.getValue().get("author_id").equals(targetPost.get("author_id"))) {
                    hidden.add(target);
                }
            }
            return hidden;
        }

        /** Replacement post IDs named by verified signed tombstones. */
        public synchronized Set<String> editedIds() {
            Set<String> edited = new HashSet<>();
            for (Map.Entry<String, Map<String, Object>> entry : posts.entrySet()) {
                if (states.get(entry.getKey()) != PostSignatures.State.SIGNED) continue;
                Map<String, Object> tombstone = tombstoneOf(entry.getValue());
                if (tombstone == null) continue;
                Object replacement = tombstone.get("replacement");
                if (replacement instanceof Map) {
                    Object id = ((Map<?, ?>) replacement).get("post_id");
                    if (id instanceof String) edited.add((String) id);
                }
            }
            return edited;
        }

        /** One author-filtered page slice with its completion flag. */
        public static final class FeedPage {
            public final List<Map<String, Object>> posts;
            public final boolean complete;

            FeedPage(List<Map<String, Object>> posts, boolean complete) {
                this.posts = posts;
                this.complete = complete;
            }
        }

        /** Serve a page for peers: tombstones travel, hidden targets do not. */
        public synchronized FeedPage servePage(int limit, Map<String, Object> cursor,
                                               String author) {
            String lastAuthor = cursor == null ? null : (String) cursor.get("last_author");
            String lastPost = cursor == null ? null : (String) cursor.get("last_post");
            Set<String> hidden = hiddenIds();
            List<Map<String, Object>> matching = new ArrayList<>();
            for (Map<String, Object> post : sorted()) {
                if (author != null && !author.equals(post.get("author_id"))) continue;
                if (!afterCursor(lastAuthor, lastPost,
                        (String) post.get("author_id"), (String) post.get("post_id"))) {
                    continue;
                }
                if (hidden.contains(post.get("post_id"))) continue;
                matching.add(Collections.unmodifiableMap(post));
            }
            int count = Math.min(Math.max(limit, 1), SERVE_PAGE_LIMIT);
            boolean complete = matching.size() <= count;
            return new FeedPage(matching.subList(0, Math.min(count, matching.size())), complete);
        }

        /** Visible rows for this device, including deletion evidence tombstones. */
        public synchronized List<Map<String, Object>> displayPage(int limit) {
            Set<String> hidden = hiddenIds();
            List<Map<String, Object>> page = new ArrayList<>();
            int count = Math.min(Math.max(limit, 1), CACHE_BOUND);
            for (Map<String, Object> post : sorted()) {
                if (page.size() >= count) break;
                if (hidden.contains(post.get("post_id"))) continue;
                page.add(Collections.unmodifiableMap(post));
            }
            return page;
        }

        private List<Map<String, Object>> sorted() {
            List<Map<String, Object>> order = new ArrayList<>(posts.values());
            Collections.sort(order, Comparator.comparing(
                post -> sortKey((String) post.get("author_id"), (String) post.get("post_id"))));
            return order;
        }

        private static Map<String, Object> tombstoneOf(Map<String, Object> post) {
            Object value = post.get("tombstone");
            if (!(value instanceof Map)) return null;
            @SuppressWarnings("unchecked")
            Map<String, Object> tombstone = (Map<String, Object>) value;
            return tombstone;
        }
    }
}
