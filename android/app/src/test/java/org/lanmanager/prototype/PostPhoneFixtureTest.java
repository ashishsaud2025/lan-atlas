package org.lanmanager.prototype;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.junit.Test;

/** Pins the checked-in phone fixture to the current verifier. */
public final class PostPhoneFixtureTest {
    private final Properties fixture = PostFixtures.load("post-phone-signed-v1.properties");

    @Test public void checked_in_phone_posts_verify() {
        Set<String> fingerprints = new HashSet<>();
        for (String prefix : new String[] {"post", "delete", "edit_target",
                "edit_replacement", "edit_tombstone"}) {
            PostSignatures.Verification verification =
                PostSignatures.verify(PostFixtures.signed(fixture, prefix));
            assertEquals(prefix, PostSignatures.State.SIGNED, verification.state);
            fingerprints.add(verification.fingerprint);
        }
        assertEquals(1, fingerprints.size());
    }

    @Test public void checked_in_phone_edit_is_author_bound() {
        Map<String, Object> post = PostFixtures.signed(fixture, "post");
        Map<String, Object> delete = PostFixtures.signed(fixture, "delete");
        Map<String, Object> edit = PostFixtures.signed(fixture, "edit_tombstone");
        Map<?, ?> delete_mapping = (Map<?, ?>) delete.get("tombstone");
        Map<?, ?> edit_mapping = (Map<?, ?>) edit.get("tombstone");
        assertEquals(post.get("post_id"), delete_mapping.get("target"));
        assertEquals(fixture.getProperty("edit_target.post_id"),
            edit_mapping.get("target"));
        @SuppressWarnings("unchecked")
        Map<String, Object> replacement = (Map<String, Object>) edit_mapping.get("replacement");
        assertEquals(edit.get("author_id"), replacement.get("author_id"));
        assertEquals(PostSignatures.State.SIGNED,
            PostSignatures.verify(replacement).state);
        assertFalse(PostActions.can_moderate(edit, (String) edit.get("author_id"),
            "unrelated-fingerprint"));
    }

    @Test public void checked_in_phone_post_rejects_tampering() {
        Map<String, Object> post = PostFixtures.signed(fixture, "post");
        post.put("text", "changed after signing");
        assertEquals(PostSignatures.State.INVALID, PostSignatures.verify(post).state);
    }
}
