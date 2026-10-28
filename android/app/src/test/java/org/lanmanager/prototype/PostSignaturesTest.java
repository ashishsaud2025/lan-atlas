package org.lanmanager.prototype;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Map;
import java.util.Properties;
import org.junit.Test;

public final class PostSignaturesTest {
    private final Properties fixture = PostFixtures.load();

    @Test public void desktop_signed_target_verifies() {
        Map<String, Object> post = PostFixtures.signed(fixture, "target");
        PostSignatures.Verification result = PostSignatures.verify(post);
        assertEquals(PostSignatures.State.SIGNED, result.state);
        assertNotNull(result.fingerprint);
    }

    @Test public void desktop_signed_tombstone_verifies() {
        Map<String, Object> post = PostFixtures.signed(fixture, "delete");
        assertEquals(PostSignatures.State.SIGNED, PostSignatures.verify(post).state);
    }

    @Test public void nested_replacement_is_covered_by_tombstone_signature() {
        Map<String, Object> post = PostFixtures.signed(fixture, "edit_tombstone");
        assertEquals(PostSignatures.State.SIGNED, PostSignatures.verify(post).state);
        Map<String, Object> tombstone = asMap(post.get("tombstone"));
        Map<String, Object> replacement = asMap(tombstone.get("replacement"));
        replacement.put("text", "forged replacement");
        assertEquals(PostSignatures.State.INVALID, PostSignatures.verify(post).state);
    }

    @Test public void tampered_text_is_invalid() {
        Map<String, Object> post = PostFixtures.signed(fixture, "target");
        post.put("text", "changed after signing");
        assertEquals(PostSignatures.State.INVALID, PostSignatures.verify(post).state);
    }

    @Test public void unsigned_post_reports_unsigned() {
        Map<String, Object> post = PostFixtures.unsigned(fixture, "unsigned");
        assertEquals(PostSignatures.State.UNSIGNED, PostSignatures.verify(post).state);
    }

    @Test public void unsigned_tombstone_never_counts_as_signed() {
        Map<String, Object> post = PostFixtures.unsigned(fixture, "unsigned");
        Map<String, Object> tombstone = new java.util.HashMap<>();
        tombstone.put("target", fixture.getProperty("target.post_id"));
        post.put("tombstone", tombstone);
        assertEquals(PostSignatures.State.UNSIGNED, PostSignatures.verify(post).state);
    }

    @Test public void wrong_algorithm_is_invalid() {
        Map<String, Object> post = PostFixtures.signed(fixture, "target");
        asMap(post.get("security")).put("algorithm", "rsa");
        assertEquals(PostSignatures.State.INVALID, PostSignatures.verify(post).state);
    }

    @Test public void null_refs_are_rejected_like_the_desktop() {
        Map<String, Object> post = PostFixtures.unsigned(fixture, "unsigned");
        post.put("refs", null);
        assertEquals(PostSignatures.State.INVALID, PostSignatures.verify(post).state);
    }

    @Test public void different_signature_is_detected() {
        Map<String, Object> first = PostFixtures.signed(fixture, "target");
        Map<String, Object> second = PostFixtures.signed(fixture, "unsigned");
        second.put("security", first.get("security"));
        assertEquals(PostSignatures.State.INVALID, PostSignatures.verify(second).state);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return (Map<String, Object>) value;
    }

    @Test public void foreign_author_tombstone_is_still_signed() {
        Map<String, Object> post = PostFixtures.signed(fixture, "attacker_tombstone");
        assertEquals(PostSignatures.State.SIGNED, PostSignatures.verify(post).state);
        assertNotEquals(fixture.getProperty("target.author_id"),
            post.get("author_id"));
    }
}
