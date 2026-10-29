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
    // Desktop reserves the same 4096 bytes of envelope headroom.
    static final long SERVE_BYTE_BUDGET = 1048576L - 4096L;
    private static final int SERVE_PAGE_LIMIT = 16;

    private FeedRules() {}

    public static boolean validText(String value) {
        if (value == null || value.length() > MAX_TEXT) return false;
        if (unpairedSurrogate(value)) return false;
        return !blank(value);
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

    /** Code point whitespace test that keeps API 26 to 32 working. */
    public static boolean blank(String value) {
        return value.codePoints().allMatch(character ->
            Character.isWhitespace(character) || Character.isSpaceChar(character));
    }

    private static boolean unpairedSurrogate(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 >= value.length()
                        || !Character.isLowSurrogate(value.charAt(index + 1))) return true;
                index++;
            } else if (Character.isLowSurrogate(character)) {
                return true;
            }
        }
        return false;
    }

    /** Bounded memory post cache keyed by post ID with stable ordering. */
    public static final class FeedCache {
        private final Map<String, Map<String, Object>> posts = new LinkedHashMap<>();
        private final Map<String, PostSignatures.State> states = new HashMap<>();
        private final Map<String, String> fingerprints = new HashMap<>();

        public synchronized int size() {
            return posts.size();
        }

        public synchronized int putValidated(String id, String author, String text,
                                             long createdMs) {
            if (!validUuid(id) || !validUuid(author) || !validText(text)) return 0;
            if (createdMs < 0 || posts.containsKey(id)) return 0;
            Map<String, Object> post = new LinkedHashMap<>();
            post.put("post_id", id);
            post.put("author_id", author);
            post.put("text", text);
            post.put("created_ms", createdMs);
            post.put("refs", new ArrayList<>());
            PostSignatures.validate(post);
            posts.put(id, post);
            states.put(id, PostSignatures.State.UNSIGNED);
            fingerprints.remove(id);
            trim();
            return 1;
        }

        /** Validate, verify, then merge a whole page or leave the cache untouched. */
        public int mergeInto(List<Map<String, Object>> page) {
            List<Map<String, Object>> verified = new ArrayList<>();
            List<PostSignatures.State> verifiedStates = new ArrayList<>();
            List<String> verifiedFingerprints = new ArrayList<>();
            for (Map<String, Object> raw : page) {
                PostSignatures.Verification verification = PostSignatures.verify(raw);
                if (verification.state == PostSignatures.State.INVALID) {
                    throw new IllegalArgumentException(
                        "Invalid post: " + verification.reason);
                }
                verified.add(copyOf(raw));
                verifiedStates.add(verification.state);
                verifiedFingerprints.add(verification.fingerprint);
            }
            synchronized (this) {
                List<Map<String, Object>> staged = new ArrayList<>();
                List<PostSignatures.State> stagedStates = new ArrayList<>();
                List<String> stagedFingerprints = new ArrayList<>();
                Set<String> stagedIds = new HashSet<>();
                for (int index = 0; index < verified.size(); index++) {
                    Map<String, Object> post = verified.get(index);
                    String id = (String) post.get("post_id");
                    if (posts.containsKey(id) || !stagedIds.add(id)) continue;
                    staged.add(post);
                    stagedStates.add(verifiedStates.get(index));
                    stagedFingerprints.add(verifiedFingerprints.get(index));
                }
                for (int index = 0; index < staged.size(); index++) {
                    Map<String, Object> post = staged.get(index);
                    String id = (String) post.get("post_id");
                    posts.put(id, post);
                    states.put(id, stagedStates.get(index));
                    if (stagedFingerprints.get(index) == null) {
                        fingerprints.remove(id);
                    } else {
                        fingerprints.put(id, stagedFingerprints.get(index));
                    }
                }
                trim();
                return staged.size();
            }
        }

        /** Deep copy of one cached post, or null when it is not stored. */
        public synchronized Map<String, Object> get(String postId) {
            Map<String, Object> post = posts.get(postId);
            return post == null ? null : copyOf(post);
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

        /** Visible rows with their moderation evidence from one consistent read. */
        public static final class DisplaySnapshot {
            public final List<Map<String, Object>> posts;
            public final Set<String> edited;
            public final Map<String, PostSignatures.State> states;
            public final Map<String, String> fingerprints;

            DisplaySnapshot(List<Map<String, Object>> posts, Set<String> edited,
                            Map<String, PostSignatures.State> states,
                            Map<String, String> fingerprints) {
                this.posts = posts;
                this.edited = edited;
                this.states = states;
                this.fingerprints = fingerprints;
            }
        }

        /** Serve a page for peers: tombstones travel, hidden targets do not. */
        public synchronized FeedPage servePage(int limit, Map<String, Object> cursor,
                                               String author) {
            return servePage(limit, cursor, author, SERVE_BYTE_BUDGET);
        }

        synchronized FeedPage servePage(int limit, Map<String, Object> cursor, String author,
                                        long byteBudget) {
            String lastAuthor = cursor == null ? null : (String) cursor.get("last_author");
            String lastPost = cursor == null ? null : (String) cursor.get("last_post");
            Set<String> hidden = hiddenIds();
            List<Map<String, Object>> candidates = new ArrayList<>();
            for (Map<String, Object> post : sorted()) {
                if (author != null && !author.equals(post.get("author_id"))) continue;
                if (!afterCursor(lastAuthor, lastPost,
                        (String) post.get("author_id"), (String) post.get("post_id"))) {
                    continue;
                }
                if (hidden.contains(post.get("post_id"))) continue;
                candidates.add(Collections.unmodifiableMap(post));
            }
            int count = Math.min(Math.max(limit, 1), SERVE_PAGE_LIMIT);
            int taken = 0;
            long used = 0;
            while (taken < candidates.size() && taken < count) {
                long size = estimateBytes(candidates.get(taken));
                // Always advance at least one post so a page can never stall.
                if (taken > 0 && used + size > byteBudget) break;
                used += size;
                taken++;
            }
            return new FeedPage(candidates.subList(0, taken), taken == candidates.size());
        }

        /** Visible rows for this device, including deletion evidence tombstones. */
        public synchronized List<Map<String, Object>> displayPage(int limit) {
            return displaySnapshot(limit).posts;
        }

        public synchronized DisplaySnapshot displaySnapshot(int limit) {
            Set<String> hidden = hiddenIds();
            List<Map<String, Object>> page = new ArrayList<>();
            int count = Math.min(Math.max(limit, 1), CACHE_BOUND);
            for (Map<String, Object> post : sorted()) {
                if (page.size() >= count) break;
                if (hidden.contains(post.get("post_id"))) continue;
                page.add(Collections.unmodifiableMap(post));
            }
            Map<String, PostSignatures.State> pageStates = new HashMap<>();
            Map<String, String> pageFingerprints = new HashMap<>();
            for (Map<String, Object> post : page) {
                String id = (String) post.get("post_id");
                pageStates.put(id, stateOf(id));
                String fingerprint = fingerprints.get(id);
                if (fingerprint != null) pageFingerprints.put(id, fingerprint);
            }
            return new DisplaySnapshot(page, editedIds(), pageStates, pageFingerprints);
        }

        private void trim() {
            while (posts.size() > CACHE_BOUND) {
                String eldest = posts.keySet().iterator().next();
                posts.remove(eldest);
                states.remove(eldest);
                fingerprints.remove(eldest);
            }
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

    /** Worst-case UTF-8 JSON size used to keep POST_PAGE inside one frame. */
    static long estimateBytes(Object value) {
        if (value == null) return 4;
        if (value instanceof String) return quotedBytes((String) value);
        if (value instanceof Boolean) return 5;
        if (value instanceof Number) return 20;
        if (value instanceof Map) {
            long total = 2;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                total += quotedBytes(String.valueOf(entry.getKey())) + 1
                    + estimateBytes(entry.getValue()) + 1;
            }
            return total;
        }
        if (value instanceof List) {
            long total = 2;
            for (Object item : (List<?>) value) total += estimateBytes(item) + 1;
            return total;
        }
        return 32;
    }

    private static long quotedBytes(String value) {
        long total = 2;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '"' || character == '\\') {
                total += 2;
            } else if (character < 0x20) {
                total += 6;
            } else if (character < 0x80) {
                total += 1;
            } else if (character < 0x800) {
                total += 2;
            } else if (Character.isHighSurrogate(character)) {
                total += 4;
                index++;
            } else {
                total += 3;
            }
        }
        return total;
    }

    private static Map<String, Object> copyOf(Map<String, Object> post) {
        Map<String, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : post.entrySet()) {
            copy.put(entry.getKey(), copyValue(entry.getValue()));
        }
        return copy;
    }

    private static Object copyValue(Object value) {
        if (value instanceof Map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                copy.put((String) entry.getKey(), copyValue(entry.getValue()));
            }
            return copy;
        }
        if (value instanceof List) {
            List<Object> copy = new ArrayList<>();
            for (Object item : (List<?>) value) copy.add(copyValue(item));
            return copy;
        }
        return value;
    }
}
