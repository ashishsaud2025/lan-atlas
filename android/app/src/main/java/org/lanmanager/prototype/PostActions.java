package org.lanmanager.prototype;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Author delete and edit actions matching the desktop tombstone rules. */
public final class PostActions {
    private static final String TOMBSTONE_TEXT = "tombstone";

    private PostActions() {}

    /** Only a post signed by this exact device key may be changed. */
    public static boolean can_moderate(Map<String, Object> post, String author_id,
                                       String fingerprint) {
        if (post == null) return false;
        PostSignatures.Verification verification = PostSignatures.verify(post);
        return can_moderate(post, author_id, fingerprint, verification.state,
            verification.fingerprint);
    }

    /** Same guard using verification evidence already cached with the post. */
    public static boolean can_moderate(Map<String, Object> post, String author_id,
                                       String fingerprint, PostSignatures.State state,
                                       String post_fingerprint) {
        if (post == null || author_id == null || fingerprint == null) return false;
        if (!author_id.equals(post.get("author_id"))) return false;
        if (post.containsKey("tombstone")) return false;
        return state == PostSignatures.State.SIGNED
            && fingerprint.equals(post_fingerprint);
    }

    /** Build and sign a tombstone that hides one own signed post. */
    public static Map<String, Object> delete(PostIdentity identity,
                                             Map<String, Object> target, long created_ms) {
        String target_id = require_modifiable(identity, target);
        return identity.sign(tombstone(target_id, null, identity.author_id(), created_ms));
    }

    /** Build and sign a replacement post plus the tombstone that links to it. */
    public static List<Map<String, Object>> edit(PostIdentity identity,
                                                 Map<String, Object> target, String text,
                                                 long created_ms) {
        String target_id = require_modifiable(identity, target);
        if (!FeedRules.validText(text)) {
            throw new IllegalArgumentException("post text must contain 1 to 4096 characters");
        }
        Map<String, Object> replacement = identity.sign(
            new_post(identity.author_id(), text, created_ms));
        Map<String, Object> tombstone = identity.sign(
            tombstone(target_id, replacement, identity.author_id(), created_ms));
        return Arrays.asList(replacement, tombstone);
    }

    /** A plain unsigned post owned by author_id. */
    public static Map<String, Object> new_post(String author_id, String text, long created_ms) {
        Map<String, Object> post = new LinkedHashMap<>();
        post.put("post_id", UUID.randomUUID().toString());
        post.put("author_id", author_id);
        post.put("text", text);
        post.put("created_ms", created_ms);
        post.put("refs", new ArrayList<>());
        return post;
    }

    private static String require_modifiable(PostIdentity identity,
                                             Map<String, Object> target) {
        if (!can_moderate(target, identity.author_id(), identity.fingerprint())) {
            throw new IllegalArgumentException("only posts signed by this device can be changed");
        }
        return (String) target.get("post_id");
    }

    private static Map<String, Object> tombstone(String target_id,
                                                 Map<String, Object> replacement,
                                                 String author_id, long created_ms) {
        Map<String, Object> post = new_post(author_id, TOMBSTONE_TEXT, created_ms);
        Map<String, Object> mapping = new LinkedHashMap<>();
        mapping.put("target", target_id);
        if (replacement != null) mapping.put("replacement", replacement);
        post.put("tombstone", mapping);
        return post;
    }
}
