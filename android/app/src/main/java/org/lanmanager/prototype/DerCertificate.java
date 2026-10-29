package org.lanmanager.prototype;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/** Minimal DER encoder for one self-signed P-256 certificate. */
final class DerCertificate {
    private static final String ECDSA_SHA256 = "1.2.840.10045.4.3.2";
    private static final String COMMON_NAME = "2.5.4.3";
    private static final long DAY_MS = 86400000L;
    private static final DateTimeFormatter UTC_TIME =
        DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'");
    private static final DateTimeFormatter GENERALIZED_TIME =
        DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'");

    private DerCertificate() {}

    /** Build a version-three certificate naming common_name as both parties. */
    static byte[] self_signed(String common_name, PublicKey public_key, PrivateKey private_key)
            throws Exception {
        byte[] algorithm = sequence(oid(ECDSA_SHA256));
        byte[] name = sequence(set(sequence(oid(COMMON_NAME), utf8(common_name))));
        long now = System.currentTimeMillis();
        byte[] validity = sequence(utc_time(now - DAY_MS), utc_time(now + 3650 * DAY_MS));
        byte[] tbs = sequence(
            context(0, integer(BigInteger.valueOf(2))),
            integer(serial()),
            algorithm,
            name,
            validity,
            name,
            public_key.getEncoded());
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(private_key);
        signer.update(tbs);
        return sequence(tbs, algorithm, bit_string(signer.sign()));
    }

    private static BigInteger serial() {
        byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
        bytes[0] &= 0x7f;
        if (bytes[0] == 0) bytes[0] = 1;
        return new BigInteger(1, bytes);
    }

    private static byte[] utc_time(long epoch_ms) {
        ZonedDateTime moment = Instant.ofEpochMilli(epoch_ms).atZone(ZoneOffset.UTC);
        // UTCTime cannot express years from 2050 onward.
        if (moment.getYear() >= 2050) {
            return tlv(0x18, moment.format(GENERALIZED_TIME)
                .getBytes(StandardCharsets.US_ASCII));
        }
        return tlv(0x17, moment.format(UTC_TIME).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] oid(String dotted) {
        String[] parts = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        write_arc(out, Long.parseLong(parts[0]) * 40 + Long.parseLong(parts[1]));
        for (int index = 2; index < parts.length; index++) {
            write_arc(out, Long.parseLong(parts[index]));
        }
        return tlv(0x06, out.toByteArray());
    }

    private static void write_arc(ByteArrayOutputStream out, long value) {
        int groups = 1;
        while (value >= (1L << (7 * groups))) groups++;
        for (int index = groups - 1; index >= 0; index--) {
            int group = (int) ((value >> (7 * index)) & 0x7f);
            out.write(index > 0 ? group | 0x80 : group);
        }
    }

    private static byte[] integer(BigInteger value) {
        return tlv(0x02, value.toByteArray());
    }

    private static byte[] utf8(String value) {
        return tlv(0x0c, value.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] sequence(byte[]... parts) {
        return tlv(0x30, concat(parts));
    }

    private static byte[] set(byte[]... parts) {
        return tlv(0x31, concat(parts));
    }

    private static byte[] context(int number, byte[] content) {
        return tlv(0xa0 | number, content);
    }

    private static byte[] bit_string(byte[] value) {
        byte[] content = new byte[value.length + 1];
        System.arraycopy(value, 0, content, 1, value.length);
        return tlv(0x03, content);
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.write(part, 0, part.length);
        return out.toByteArray();
    }

    private static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int length = content.length;
        if (length < 0x80) {
            out.write(length);
        } else {
            int bytes = 0;
            for (int value = length; value > 0; value >>= 8) bytes++;
            out.write(0x80 | bytes);
            for (int shift = (bytes - 1) * 8; shift >= 0; shift -= 8) {
                out.write((length >> shift) & 0xff);
            }
        }
        out.write(content, 0, content.length);
        return out.toByteArray();
    }
}
