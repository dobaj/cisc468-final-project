package com.p2pfs.crypto;

import com.p2pfs.protocol.ProtocolConstants;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * AES-256-GCM session encryption/decryption.
 * The GCM tag is appended to the ciphertext by the JCA implementation.
 */
public class SessionCipher {

    private static final int GCM_TAG_BITS = 128;
    private static final String ALGORITHM = "AES/GCM/NoPadding";

    private final SecretKeySpec keySpec;
    private final SecureRandom random = new SecureRandom();

    public SessionCipher(byte[] sessionKey) {
        if (sessionKey.length != ProtocolConstants.AES_KEY_BYTES) {
            throw new IllegalArgumentException("Session key must be " + ProtocolConstants.AES_KEY_BYTES + " bytes");
        }
        this.keySpec = new SecretKeySpec(sessionKey, "AES");
    }

    public record EncryptedPayload(byte[] iv, byte[] ciphertext) {}

    /**
     * Encrypts plaintext with a random IV. Returns IV and ciphertext (with appended GCM tag).
     */
    public EncryptedPayload encrypt(byte[] plaintext) throws GeneralSecurityException {
        byte[] iv = new byte[ProtocolConstants.GCM_IV_BYTES];
        random.nextBytes(iv);
        return encrypt(plaintext, iv);
    }

    public EncryptedPayload encrypt(byte[] plaintext, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);
        return new EncryptedPayload(iv, ciphertext);
    }

    /**
     * Decrypts ciphertext (with appended GCM tag) using the given IV.
     */
    public byte[] decrypt(byte[] iv, byte[] ciphertext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(ciphertext);
    }
}
