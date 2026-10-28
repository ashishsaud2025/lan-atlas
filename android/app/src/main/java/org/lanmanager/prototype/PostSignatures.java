package org.lanmanager.prototype;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;

/** Mirrors the desktop post shape and signature rules without trusting a key. */
public final class PostSignatures {
    public enum State { UNSIGNED, SIGNED, INVALID }

    public static final class Verification {
        public final State state;
        public final String fingerprint;
        public final String reason;

        Verification(State state, String fingerprint, String reason) {
            this.state = state;
            this.fingerprint = fingerprint;
            this.reason = reason;
        }
    }

    private static final byte[] SIGNING_PREFIX =
        "LAN-MANAGER-POST-V1\u0000".getBytes(StandardCharsets.US_ASCII);
    private static final int MAX_TEXT = 4096;
    private static final int MAX_REFS = 8;
    private static final int MAX_REF_NAME = 255;
    private static final long MAX_FILE_SIZE = 1024L * 1024 * 1024;
    private static final int MAX_CERTIFICATE_DER = 16 * 1024;
    private static final int MAX_SIGNATURE_DER = 256;

    private PostSignatures() {}

    /** Classify one post exactly as the desktop verifier does. */
    public static Verification verify(Map<String, Object> post) {
        try {
            validate(post);
        } catch (IllegalArgumentException error) {
            return new Verification(State.INVALID, null, error.getMessage());
        }
        if (!post.containsKey("security")) {
            return new Verification(State.UNSIGNED, null, null);
        }
        String fingerprint = null;
        try {
            Map<String, Object> security = asMap(post.get("security"), "post security");
            byte[] certificateDer = canonicalBase64(
                security.get("certificate"), "certificate", MAX_CERTIFICATE_DER);
            byte[] signatureDer = canonicalBase64(
                security.get("signature"), "signature", MAX_SIGNATURE_DER);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(certificateDer));
            fingerprint = sha256Hex(certificateDer);
            PublicKey key = certificate.getPublicKey();
            if (!(key instanceof ECPublicKey)) {
                throw new IllegalArgumentException("post certificate public key must be P-256");
            }
            ECPublicKey ecKey = (ECPublicKey) key;
            if (!isP256(ecKey.getParams())) {
                throw new IllegalArgumentException("post certificate public key must be P-256");
            }
            String subject = certificate.getSubjectX500Principal()
                .getName(X500Principal.RFC2253);
            if (!subject.equals("CN=" + post.get("author_id"))) {
                throw new IllegalArgumentException("post certificate subject CN must equal author_id");
            }
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(ecKey);
            verifier.update(signingPayload(post));
            if (!verifier.verify(signatureDer)) {
                throw new IllegalArgumentException("post signature does not match");
            }
        } catch (Exception error) {
            return new Verification(State.INVALID, fingerprint, error.getMessage());
        }
        return new Verification(State.SIGNED, fingerprint, null);
    }

    /** Reject a post before it enters the cache or a page. */
    public static void validate(Map<String, Object> post) {
        if (post == null) throw new IllegalArgumentException("post must be an object");
        for (String required : new String[] {"post_id", "author_id", "text", "created_ms"}) {
            if (!post.containsKey(required)) throw new IllegalArgumentException("post has invalid fields");
        }
        boolean secured = post.containsKey("security") || post.containsKey("tombstone");
        if (secured) {
            for (String key : post.keySet()) {
                if (!"post_id".equals(key) && !"author_id".equals(key)
                        && !"text".equals(key) && !"created_ms".equals(key)
                        && !"refs".equals(key) && !"security".equals(key)
                        && !"tombstone".equals(key)) {
                    throw new IllegalArgumentException("post has invalid fields");
                }
            }
        }
        String postId = canonicalUuid(post.get("post_id"), "post_id");
        String authorId = canonicalUuid(post.get("author_id"), "author_id");
        String text = asText(post.get("text"));
        if (text.codePointCount(0, text.length()) > MAX_TEXT) {
            throw new IllegalArgumentException("post text must contain 1 to 4096 characters");
        }
        createdMs(post.get("created_ms"));
        List<Object> refs = asList(post.containsKey("refs")
            ? post.get("refs") : Collections.emptyList(), "post refs");
        if (refs.size() > MAX_REFS) {
            throw new IllegalArgumentException("post refs must be a list of at most 8 items");
        }
        for (Object ref : refs) validateRef(ref);
        if (post.containsKey("security")) validateSecurity(post.get("security"));
        if (post.containsKey("tombstone")) {
            validateTombstone(post.get("tombstone"), postId, authorId);
        }
    }

    private static void validateRef(Object value) {
        Map<String, Object> ref = asMap(value, "reference");
        Object kind = ref.get("kind");
        if (!"file".equals(kind) && !"post".equals(kind)) {
            throw new IllegalArgumentException("reference kind must be file or post");
        }
        if ("post".equals(kind)) {
            canonicalUuid(ref.get("id"), "post reference id");
            return;
        }
        Object rawName = ref.get("name");
        if (!(rawName instanceof String) || FeedRules.blank((String) rawName)) {
            throw new IllegalArgumentException("invalid file reference name");
        }
        String name = (String) rawName;
        if (name.codePointCount(0, name.length()) > MAX_REF_NAME
                || ".".equals(name) || "..".equals(name)
                || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 || name.indexOf(':') >= 0
                || name.codePoints().anyMatch(character -> character < 32)) {
            throw new IllegalArgumentException("invalid file reference name");
        }
        long size = integral(ref.get("size"), "file reference size");
        if (size < 0 || size > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("file reference size outside allowed range");
        }
        Object digest = ref.get("sha256");
        if (digest != null) {
            if (!(digest instanceof String) || ((String) digest).length() != 64) {
                throw new IllegalArgumentException("invalid file reference SHA-256");
            }
            for (char character : ((String) digest).toCharArray()) {
                if ("0123456789abcdef".indexOf(character) < 0) {
                    throw new IllegalArgumentException("invalid file reference SHA-256");
                }
            }
        }
    }

    private static void validateSecurity(Object value) {
        Map<String, Object> security = asMap(value, "post security");
        if (!security.keySet().equals(new java.util.HashSet<>(
                java.util.Arrays.asList("version", "algorithm", "certificate", "signature")))) {
            throw new IllegalArgumentException("post security has invalid fields");
        }
        if (integral(security.get("version"), "post security version") != 1) {
            throw new IllegalArgumentException("unsupported post security version");
        }
        if (!"ecdsa-p256-sha256".equals(security.get("algorithm"))) {
            throw new IllegalArgumentException("unsupported post security algorithm");
        }
        canonicalBase64(security.get("certificate"), "certificate", MAX_CERTIFICATE_DER);
        canonicalBase64(security.get("signature"), "signature", MAX_SIGNATURE_DER);
    }

    private static void validateTombstone(Object value, String postId, String authorId) {
        Map<String, Object> tombstone = asMap(value, "tombstone");
        for (String key : tombstone.keySet()) {
            if (!"target".equals(key) && !"replacement".equals(key)) {
                throw new IllegalArgumentException("tombstone has invalid fields");
            }
        }
        String target = canonicalUuid(tombstone.get("target"), "tombstone target");
        if (target.equals(postId)) {
            throw new IllegalArgumentException("tombstone cannot target its own post");
        }
        if (!tombstone.containsKey("replacement") || tombstone.get("replacement") == null) {
            return;
        }
        if (!(tombstone.get("replacement") instanceof Map)) {
            throw new IllegalArgumentException("tombstone replacement must be a plain post");
        }
        Map<String, Object> replacement = asMap(
            tombstone.get("replacement"), "tombstone replacement");
        if (replacement.containsKey("tombstone")) {
            throw new IllegalArgumentException("tombstone replacement must be a plain post");
        }
        validate(replacement);
        if (!authorId.equals(replacement.get("author_id"))) {
            throw new IllegalArgumentException("tombstone replacement must share the author");
        }
    }

    private static String asText(Object value) {
        if (!(value instanceof String)) {
            throw new IllegalArgumentException("post text must contain 1 to 4096 characters");
        }
        String text = (String) value;
        boolean blank = text.codePoints().allMatch(character ->
            Character.isWhitespace(character) || Character.isSpaceChar(character));
        if (text.isEmpty() || blank) {
            throw new IllegalArgumentException("post text must contain 1 to 4096 characters");
        }
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 >= text.length()
                        || !Character.isLowSurrogate(text.charAt(index + 1))) {
                    throw new IllegalArgumentException("post text contains an unpaired surrogate");
                }
                index++;
            } else if (Character.isLowSurrogate(character)) {
                throw new IllegalArgumentException("post text contains an unpaired surrogate");
            }
        }
        return text;
    }

    private static String canonicalUuid(Object value, String name) {
        if (!(value instanceof String)) throw new IllegalArgumentException("invalid " + name);
        try {
            if (!UUID.fromString((String) value).toString().equals(value)) {
                throw new IllegalArgumentException("invalid " + name);
            }
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return (String) value;
    }

    private static long createdMs(Object value) {
        long created = integral(value, "post created_ms");
        if (created < 0) {
            throw new IllegalArgumentException("post created_ms must be a nonnegative int");
        }
        return created;
    }

    private static long integral(Object value, String name) {
        if (value instanceof Integer || value instanceof Long
                || value instanceof Short || value instanceof Byte) {
            return ((Number) value).longValue();
        }
        throw new IllegalArgumentException(name + " must be an integer");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value, String name) {
        if (!(value instanceof Map)) throw new IllegalArgumentException(name + " must be an object");
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object value, String name) {
        if (!(value instanceof List)) throw new IllegalArgumentException(name + " must be a list");
        return (List<Object>) value;
    }

    private static byte[] canonicalBase64(Object value, String name, int maximum) {
        if (!(value instanceof String) || ((String) value).isEmpty()) {
            throw new IllegalArgumentException("post security " + name + " must be base64 text");
        }
        String encoded = (String) value;
        if (encoded.length() > 4 * ((maximum + 2) / 3)) {
            throw new IllegalArgumentException("post security " + name + " exceeds allowed size");
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException(
                "post security " + name + " is not strict base64");
        }
        if (raw.length == 0 || raw.length > maximum) {
            throw new IllegalArgumentException("post security " + name + " exceeds allowed size");
        }
        if (!Base64.getEncoder().encodeToString(raw).equals(encoded)) {
            throw new IllegalArgumentException(
                "post security " + name + " is not canonical base64");
        }
        return raw;
    }

    private static byte[] signingPayload(Map<String, Object> post) {
        Map<String, Object> fields = new TreeMap<>();
        fields.put("post_id", post.get("post_id"));
        fields.put("author_id", post.get("author_id"));
        fields.put("text", post.get("text"));
        fields.put("created_ms", post.get("created_ms"));
        Object refs = post.get("refs");
        fields.put("refs", refs == null ? Collections.emptyList() : refs);
        if (post.containsKey("tombstone")) {
            fields.put("tombstone", post.get("tombstone"));
        }
        byte[] encoded = canonicalJson(fields).getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[SIGNING_PREFIX.length + encoded.length];
        System.arraycopy(SIGNING_PREFIX, 0, payload, 0, SIGNING_PREFIX.length);
        System.arraycopy(encoded, 0, payload, SIGNING_PREFIX.length, encoded.length);
        return payload;
    }

    static String canonicalJson(Object value) {
        StringBuilder out = new StringBuilder();
        writeCanonical(out, value);
        return out.toString();
    }

    private static void writeCanonical(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String) {
            writeString(out, (String) value);
        } else if (value instanceof Boolean) {
            out.append(((Boolean) value) ? "true" : "false");
        } else if (value instanceof Integer || value instanceof Long
                || value instanceof Short || value instanceof Byte) {
            out.append(((Number) value).longValue());
        } else if (value instanceof Map) {
            Map<String, Object> object = new TreeMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!(entry.getKey() instanceof String)) {
                    throw new IllegalArgumentException("post JSON keys must be strings");
                }
                object.put((String) entry.getKey(), entry.getValue());
            }
            out.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> entry : object.entrySet()) {
                if (!first) out.append(',');
                first = false;
                writeString(out, entry.getKey());
                out.append(':');
                writeCanonical(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof List) {
            out.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) out.append(',');
                first = false;
                writeCanonical(out, item);
            }
            out.append(']');
        } else if (value instanceof Number) {
            throw new IllegalArgumentException("post JSON numbers must be integers");
        } else {
            throw new IllegalArgumentException("post JSON value is unsupported");
        }
    }

    private static void writeString(StringBuilder out, String value) {
        out.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        out.append(String.format("\\u%04x", (int) character));
                    } else {
                        out.append(character);
                    }
            }
        }
        out.append('"');
    }

    private static boolean isP256(ECParameterSpec actual) {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
            return actual.getCurve().getField().equals(expected.getCurve().getField())
                && actual.getCurve().getA().equals(expected.getCurve().getA())
                && actual.getCurve().getB().equals(expected.getCurve().getB())
                && actual.getGenerator().equals(expected.getGenerator())
                && actual.getOrder().equals(expected.getOrder())
                && actual.getCofactor() == expected.getCofactor();
        } catch (Exception error) {
            return false;
        }
    }

    private static String sha256Hex(byte[] data) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte item : digest) hex.append(String.format("%02x", item & 0xff));
        return hex.toString();
    }
}
