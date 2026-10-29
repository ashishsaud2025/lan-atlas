package org.lanmanager.prototype;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;
import javax.security.auth.x500.X500Principal;
import org.junit.Test;

public final class PostIdentityTest {
    private static final String AUTHOR = "00000000-0000-4000-8000-000000000002";
    private final Properties fixture = PostFixtures.load();

    private static X509Certificate certificate_of(PostIdentity identity) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(identity.certificate_der()));
    }

    @Test public void generated_certificate_is_self_signed_and_named() throws Exception {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        X509Certificate certificate = certificate_of(identity);
        assertEquals("CN=" + AUTHOR,
            certificate.getSubjectX500Principal().getName(X500Principal.RFC2253));
        certificate.verify(certificate.getPublicKey());
        certificate.checkValidity();
        assertEquals("EC", certificate.getPublicKey().getAlgorithm());
        assertEquals(64, identity.fingerprint().length());
    }

    @Test public void signed_post_verifies_and_detects_tampering() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        Map<String, Object> signed = identity.sign(PostFixtures.unsigned(fixture, "unsigned"));
        assertEquals(PostSignatures.State.SIGNED, PostSignatures.verify(signed).state);
        assertEquals(identity.fingerprint(), PostSignatures.verify(signed).fingerprint);
        signed.put("text", "changed after signing");
        assertEquals(PostSignatures.State.INVALID, PostSignatures.verify(signed).state);
    }

    @Test public void encoding_round_trips_the_same_key() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        PostIdentity restored = PostIdentity.decode(identity.encode(), AUTHOR);
        assertEquals(identity.fingerprint(), restored.fingerprint());
        assertArrayEquals(identity.certificate_der(), restored.certificate_der());
        Map<String, Object> post = restored.sign(PostFixtures.unsigned(fixture, "unsigned"));
        assertEquals(PostSignatures.State.SIGNED, PostSignatures.verify(post).state);
    }

    @Test public void another_author_id_is_refused_at_load() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        try {
            PostIdentity.decode(identity.encode(), "00000000-0000-4000-8000-000000000009");
            assertFalse("mismatched author must throw", true);
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test public void signing_someone_elses_post_is_refused() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        Map<String, Object> post = PostFixtures.unsigned(fixture, "unsigned");
        post.put("author_id", "00000000-0000-4000-8000-000000000009");
        try {
            identity.sign(post);
            assertFalse("foreign author must throw", true);
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test public void corrupted_identity_bytes_are_rejected() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        byte[] blob = identity.encode();
        blob[blob.length - 1] ^= 0x7f;
        try {
            PostIdentity.decode(blob, AUTHOR);
            assertFalse("corrupted identity must throw", true);
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test public void a_key_from_another_certificate_is_rejected() throws Exception {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        PostIdentity other = PostIdentity.generate(AUTHOR);
        try {
            PostIdentity.decode(rebuild(identity.encode(), other.certificate_der()), AUTHOR);
            assertFalse("key and certificate mismatch must throw", true);
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test public void trailing_certificate_bytes_are_rejected() throws Exception {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        byte[] certificate = identity.certificate_der();
        byte[] extended = Arrays.copyOf(certificate, certificate.length + 3);
        extended[certificate.length] = 1;
        try {
            PostIdentity.decode(rebuild(identity.encode(), extended), AUTHOR);
            assertFalse("trailing certificate data must throw", true);
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test public void signed_post_with_a_trailing_certificate_byte_is_invalid() {
        PostIdentity identity = PostIdentity.generate(AUTHOR);
        Map<String, Object> post = identity.sign(
            PostFixtures.unsigned(fixture, "unsigned"));
        @SuppressWarnings("unchecked")
        Map<String, Object> security = (Map<String, Object>) post.get("security");
        byte[] certificate = java.util.Base64.getDecoder().decode(
            (String) security.get("certificate"));
        byte[] extended = Arrays.copyOf(certificate, certificate.length + 3);
        extended[certificate.length] = 1;
        security.put("certificate",
            java.util.Base64.getEncoder().encodeToString(extended));
        assertEquals(PostSignatures.State.INVALID, PostSignatures.verify(post).state);
    }

    private static byte[] rebuild(byte[] blob, byte[] certificate) throws Exception {
        DataInputStream input = new DataInputStream(new ByteArrayInputStream(blob));
        assertEquals(0x4c4d5049, input.readInt());
        assertEquals(1, input.readInt());
        assertEquals(AUTHOR, input.readUTF());
        int key_length = input.readInt();
        input.readInt();
        byte[] key = new byte[key_length];
        input.readFully(key);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(buffer);
        output.writeInt(0x4c4d5049);
        output.writeInt(1);
        output.writeUTF(AUTHOR);
        output.writeInt(key.length);
        output.writeInt(certificate.length);
        output.write(key);
        output.write(certificate);
        output.flush();
        return buffer.toByteArray();
    }
}
