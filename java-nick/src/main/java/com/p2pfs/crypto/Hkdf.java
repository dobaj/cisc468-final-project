package com.p2pfs.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.nio.charset.StandardCharsets;

/**
 * HKDF-SHA256 key derivation as defined in RFC 5869.
 */
public final class Hkdf {

    private Hkdf() {}

    /**
     * Derives a key using HKDF-SHA256.
     *
     * @param ikm   input keying material (e.g., X25519 shared secret)
     * @param salt  optional salt (nonce_initiator || nonce_responder)
     * @param info  context and application-specific info string
     * @param length desired output key length in bytes
     * @return derived key bytes
     */
    public static byte[] derive(byte[] ikm, byte[] salt, String info, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, salt, info.getBytes(StandardCharsets.UTF_8)));
        byte[] okm = new byte[length];
        hkdf.generateBytes(okm, 0, length);
        return okm;
    }
}
