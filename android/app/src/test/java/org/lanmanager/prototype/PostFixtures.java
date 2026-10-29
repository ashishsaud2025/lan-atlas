package org.lanmanager.prototype;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/** Loads the desktop-signed moderation fixture for the JVM tests. */
final class PostFixtures {
    private PostFixtures() {}

    static Properties load() {
        return load("post-moderation-v1.properties");
    }

    static Properties load(String name) {
        Properties properties = new Properties();
        try (InputStream stream = PostFixtures.class.getResourceAsStream("/" + name)) {
            if (stream == null) throw new IllegalStateException("fixture missing: " + name);
            properties.load(stream);
            return properties;
        } catch (IOException error) {
            throw new IllegalStateException("fixture unreadable: " + name, error);
        }
    }

    static Map<String, Object> signed(Properties properties, String prefix) {
        Map<String, Object> post = base(properties, prefix);
        Map<String, Object> security = new HashMap<>();
        security.put("version", 1);
        security.put("algorithm", "ecdsa-p256-sha256");
        security.put("certificate", properties.getProperty(prefix + ".certificate"));
        security.put("signature", properties.getProperty(prefix + ".signature"));
        post.put("security", security);
        return post;
    }

    static Map<String, Object> unsigned(Properties properties, String prefix) {
        return base(properties, prefix);
    }

    private static Map<String, Object> base(Properties properties, String prefix) {
        Map<String, Object> post = new LinkedHashMap<>();
        post.put("post_id", properties.getProperty(prefix + ".post_id"));
        post.put("author_id", properties.getProperty(prefix + ".author_id"));
        post.put("text", properties.getProperty(prefix + ".text"));
        post.put("created_ms", Long.parseLong(properties.getProperty(prefix + ".created_ms")));
        List<Map<String, Object>> refs = new ArrayList<>();
        for (int index = 0; index < 8; index++) {
            String refPrefix = prefix + ".ref" + index;
            if (!properties.containsKey(refPrefix + ".kind")) break;
            Map<String, Object> ref = new LinkedHashMap<>();
            ref.put("kind", properties.getProperty(refPrefix + ".kind"));
            for (String key : new String[] {"id", "name", "size", "sha256"}) {
                String value = properties.getProperty(refPrefix + "." + key);
                if (value == null) continue;
                ref.put(key, "size".equals(key) ? Long.valueOf(value) : value);
            }
            refs.add(ref);
        }
        post.put("refs", refs);
        if (properties.containsKey(prefix + ".tombstone.target")) {
            Map<String, Object> tombstone = new LinkedHashMap<>();
            tombstone.put("target", properties.getProperty(prefix + ".tombstone.target"));
            if (properties.containsKey(prefix + ".replacement.post_id")) {
                tombstone.put("replacement", signed(properties, prefix + ".replacement"));
            }
            post.put("tombstone", tombstone);
        }
        return post;
    }
}
