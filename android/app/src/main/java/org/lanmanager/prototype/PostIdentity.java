package org.lanmanager.prototype;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.security.auth.x500.X500Principal;

/** Persistent P-256 signing identity bound to one installation peer ID. */
public final class PostIdentity {
    private static final int MAGIC = 0x4c4d5049;
    private static final int VERSION = 1;
    private static final byte[] PROBE = "LAN-MANAGER-IDENTITY-V1".getBytes(
        java.nio.charset.StandardCharsets.US_ASCII);

    private final String author_id;
    private final PrivateKey private_key;
    private final X509Certificate certificate;
    private final byte[] certificate_der;

    private PostIdentity(String author_id, PrivateKey private_key,
                         X509Certificate certificate, byte[] certificate_der) {
        this.author_id = author_id;
        this.private_key = private_key;
        this.certificate = certificate;
        this.certificate_der = certificate_der.clone();
    }

    public static PostIdentity generate(String author_id) {
        if (!FeedRules.validUuid(author_id)) {
            throw new IllegalArgumentException("author must be a canonical UUID");
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = generator.generateKeyPair();
            byte[] der = DerCertificate.self_signed(
                author_id, pair.getPublic(), pair.getPrivate());
            X509Certificate certificate = parse(der);
            certificate.verify(certificate.getPublicKey());
            return new PostIdentity(author_id, pair.getPrivate(), certificate, der);
        } catch (Exception error) {
            throw new IllegalStateException("cannot create a post signing identity", error);
        }
    }

    /** Rebuild a stored identity and refuse it when it no longer fits this peer ID. */
    public static PostIdentity decode(byte[] blob, String expected_author_id) {
        try {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(blob));
            if (input.readInt() != MAGIC || input.readInt() != VERSION) {
                throw new IllegalArgumentException("identity header is invalid");
            }
            String author = input.readUTF();
            int key_length = input.readInt();
            int certificate_length = input.readInt();
            if (key_length < 32 || key_length > 4096
                    || certificate_length < 64 || certificate_length > 16 * 1024) {
                throw new IllegalArgumentException("identity sizes are invalid");
            }
            byte[] key_bytes = new byte[key_length];
            input.readFully(key_bytes);
            byte[] certificate_bytes = new byte[certificate_length];
            input.readFully(certificate_bytes);
            if (input.available() != 0) {
                throw new IllegalArgumentException("identity has trailing data");
            }
            if (!author.equals(expected_author_id)) {
                throw new IllegalArgumentException("identity author does not match");
            }
            X509Certificate certificate = parse(certificate_bytes);
            if (!Arrays.equals(certificate.getEncoded(), certificate_bytes)) {
                throw new IllegalArgumentException("identity certificate has trailing data");
            }
            if (!("CN=" + author).equals(
                    certificate.getSubjectX500Principal().getName(X500Principal.RFC2253))) {
                throw new IllegalArgumentException("identity certificate name is invalid");
            }
            if (!(certificate.getPublicKey() instanceof ECPublicKey)
                    || !PostSignatures.isP256(
                        ((ECPublicKey) certificate.getPublicKey()).getParams())) {
                throw new IllegalArgumentException("identity certificate key must be P-256");
            }
            certificate.verify(certificate.getPublicKey());
            PrivateKey key = KeyFactory.getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(key_bytes));
            Signature prover = Signature.getInstance("SHA256withECDSA");
            prover.initSign(key);
            prover.update(PROBE);
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(PROBE);
            if (!verifier.verify(prover.sign())) {
                throw new IllegalArgumentException("identity key does not match its certificate");
            }
            return new PostIdentity(author, key, certificate, certificate_bytes);
        } catch (IllegalArgumentException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalArgumentException("identity data is invalid", error);
        }
    }

    public byte[] encode() {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(buffer);
            output.writeInt(MAGIC);
            output.writeInt(VERSION);
            output.writeUTF(author_id);
            byte[] key_bytes = private_key.getEncoded();
            output.writeInt(key_bytes.length);
            output.writeInt(certificate_der.length);
            output.write(key_bytes);
            output.write(certificate_der);
            output.flush();
            return buffer.toByteArray();
        } catch (Exception error) {
            throw new IllegalStateException("cannot encode the post identity", error);
        }
    }

    public String author_id() {
        return author_id;
    }

    public byte[] certificate_der() {
        return certificate_der.clone();
    }

    public String fingerprint() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(certificate.getEncoded());
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte value : digest) hex.append(String.format("%02x", value & 0xff));
            return hex.toString();
        } catch (Exception error) {
            throw new IllegalStateException("cannot fingerprint the identity", error);
        }
    }

    /** Return a signed copy of a post authored by this identity. */
    public Map<String, Object> sign(Map<String, Object> post) {
        Map<String, Object> signed = copy(post);
        signed.remove("security");
        PostSignatures.validate(signed);
        if (!author_id.equals(signed.get("author_id"))) {
            throw new IllegalArgumentException("identity cannot sign another author");
        }
        try {
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(private_key);
            signer.update(PostSignatures.signingPayload(signed));
            Map<String, Object> security = new LinkedHashMap<>();
            security.put("version", 1);
            security.put("algorithm", "ecdsa-p256-sha256");
            security.put("certificate",
                Base64.getEncoder().encodeToString(certificate_der));
            security.put("signature", Base64.getEncoder().encodeToString(signer.sign()));
            signed.put("security", security);
        } catch (Exception error) {
            throw new IllegalStateException("cannot sign the post", error);
        }
        PostSignatures.validate(signed);
        if (PostSignatures.verify(signed).state != PostSignatures.State.SIGNED) {
            throw new IllegalStateException("identity produced an invalid signature");
        }
        return signed;
    }

    private static X509Certificate parse(byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(der));
    }

    private static Map<String, Object> copy(Map<String, Object> post) {
        Map<String, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : post.entrySet()) {
            copy.put(entry.getKey(), copy_value(entry.getValue()));
        }
        return copy;
    }

    private static Object copy_value(Object value) {
        if (value instanceof Map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                copy.put((String) entry.getKey(), copy_value(entry.getValue()));
            }
            return copy;
        }
        if (value instanceof java.util.List) {
            java.util.List<Object> copy = new java.util.ArrayList<>();
            for (Object item : (java.util.List<?>) value) copy.add(copy_value(item));
            return copy;
        }
        return value;
    }
}
