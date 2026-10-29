package org.lanmanager.prototype;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.Test;

public final class PostActionsTest {
    private static final String AUTHOR = "00000000-0000-4000-8000-000000000002";
    private final Properties fixture = PostFixtures.load();

    private Map<String, Object> own_post(PostIdentity identity) {
        return identity.sign(PostFixtures.unsigned(fixture, "unsigned"));
    }

    @Test public void own_signed_post_may_be_modified() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        assertTrue(PostActions.can_moderate(own_post(identity), AUTHOR, identity.fingerprint()));
    }

    @Test public void unsigned_post_may_not_be_modified() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        Map<String, Object> post = PostFixtures.unsigned(fixture, "unsigned");
        assertFalse(PostActions.can_moderate(post, AUTHOR, identity.fingerprint()));
    }

    @Test public void post_signed_by_another_key_may_not_be_modified() {
        PostIdentity mine = PostIdentity.generate(AUTHOR);
        PostIdentity other = PostIdentity.generate(AUTHOR);
        Map<String, Object> post = own_post(other);
        assertTrue(PostActions.can_moderate(post, AUTHOR, other.fingerprint()));
        assertFalse(PostActions.can_moderate(post, AUTHOR, mine.fingerprint()));
    }

    @Test public void delete_tombstone_hides_the_target() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        Map<String, Object> target = own_post(identity);
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        cache.mergeInto(Arrays.asList(target));
        Map<String, Object> tombstone = PostActions.delete(identity, target, 1700000000100L);
        assertEquals("tombstone", tombstone.get("text"));
        assertEquals(PostSignatures.State.SIGNED, PostSignatures.verify(tombstone).state);
        cache.mergeInto(Arrays.asList(tombstone));
        assertTrue(cache.hiddenIds().contains(target.get("post_id")));
        List<Map<String, Object>> display = cache.displayPage(50);
        assertEquals(1, display.size());
        assertEquals(tombstone.get("post_id"), display.get(0).get("post_id"));
    }

    @Test public void edit_publishes_a_replacement_and_tombstone() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        Map<String, Object> target = own_post(identity);
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        cache.mergeInto(Arrays.asList(target));
        List<Map<String, Object>> pair = PostActions.edit(
            identity, target, "version two", 1700000000200L);
        assertEquals(2, pair.size());
        for (Map<String, Object> post : pair) {
            assertEquals(PostSignatures.State.SIGNED, PostSignatures.verify(post).state);
        }
        cache.mergeInto(pair);
        assertTrue(cache.hiddenIds().contains(target.get("post_id")));
        assertTrue(cache.editedIds().contains(pair.get(0).get("post_id")));
        List<String> served = new ArrayList<>();
        for (Map<String, Object> post : cache.servePage(50, null, null).posts) {
            served.add((String) post.get("post_id"));
        }
        assertFalse(served.contains(target.get("post_id")));
        assertTrue(served.contains(pair.get(0).get("post_id")));
        assertTrue(served.contains(pair.get(1).get("post_id")));
    }

    @Test public void tombstones_cannot_be_deleted_or_edited() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        Map<String, Object> target = own_post(identity);
        Map<String, Object> tombstone = PostActions.delete(
            identity, target, 1700000000400L);
        assertFalse(PostActions.can_moderate(
            tombstone, AUTHOR, identity.fingerprint()));
        try {
            PostActions.delete(identity, tombstone, 1700000000401L);
            assertFalse("tombstone delete must throw", true);
        } catch (IllegalArgumentException expected) {
        }
        try {
            PostActions.edit(identity, tombstone, "version three", 1700000000402L);
            assertFalse("tombstone edit must throw", true);
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test public void cached_evidence_requires_the_same_key() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        Map<String, Object> post = own_post(identity);
        String fingerprint = identity.fingerprint();
        assertTrue(PostActions.can_moderate(post, AUTHOR, fingerprint,
            PostSignatures.State.SIGNED, fingerprint));
        assertFalse(PostActions.can_moderate(post, AUTHOR, fingerprint,
            PostSignatures.State.SIGNED, "0000000000000000000000000000000000000000"));
        assertFalse(PostActions.can_moderate(post, AUTHOR, fingerprint,
            PostSignatures.State.UNSIGNED, fingerprint));
    }

    @Test public void cache_only_hands_out_isolated_copies() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        Map<String, Object> target = own_post(identity);
        String id = (String) target.get("post_id");
        FeedRules.FeedCache cache = new FeedRules.FeedCache();
        cache.mergeInto(Arrays.asList(target));
        Map<String, Object> copy = cache.get(id);
        assertEquals(target.get("text"), copy.get("text"));
        copy.put("text", "mutated outside the cache");
        assertEquals(target.get("text"), cache.get(id).get("text"));
        assertNull(cache.get("00000000-0000-4000-8000-0000000000ff"));
    }

    @Test public void edit_tombstone_embeds_a_verified_replacement() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        Map<String, Object> target = own_post(identity);
        List<Map<String, Object>> pair = PostActions.edit(
            identity, target, "version two", 1700000000200L);
        Map<?, ?> tombstone = (Map<?, ?>) pair.get(1).get("tombstone");
        Map<?, ?> replacement = (Map<?, ?>) tombstone.get("replacement");
        assertEquals(pair.get(0).get("post_id"), replacement.get("post_id"));
        assertEquals(PostSignatures.State.SIGNED,
            PostSignatures.verify(asMap(replacement)).state);
    }

    @Test public void another_key_cannot_delete_the_post() {
        PostIdentity mine = PostIdentity.generate(AUTHOR);
        PostIdentity other = PostIdentity.generate(AUTHOR);
        Map<String, Object> target = own_post(mine);
        try {
            PostActions.delete(other, target, 1700000000300L);
            assertFalse("foreign key must throw", true);
        } catch (IllegalArgumentException expected) {
        }
        assertEquals(PostSignatures.State.SIGNED,
            PostSignatures.verify(PostActions.delete(mine, target, 1700000000301L)).state);
    }

    @Test public void edit_refuses_blank_text() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        Map<String, Object> target = own_post(identity);
        try {
            PostActions.edit(identity, target, "   ", 1700000000200L);
            assertFalse("blank text must throw", true);
        } catch (IllegalArgumentException expected) {
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Map<?, ?> value) {
        return (Map<String, Object>) value;
    }
}
