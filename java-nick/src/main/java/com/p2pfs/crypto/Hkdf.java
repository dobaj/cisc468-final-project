package com.p2pfs.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.nio.charset.StandardCharsets;

// HKDF-SHA256 key derivation (RFC 5869)
public final class Hkdf {

    private Hkdf() {}

    // ikm = shared secret, salt = optional nonces, info = protocol label, length = output bytes
    public static byte[] derive(byte[] ikm, byte[] salt, String info, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, salt, info.getBytes(StandardCharsets.UTF_8)));
        byte[] okm = new byte[length];
        hkdf.generateBytes(okm, 0, length);
        return okm;
    }
}
