package com.p2pfs.crypto;

import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class SessionCipherTest {

    private byte[] randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    @Test
    void encryptAndDecrypt() throws GeneralSecurityException {
        byte[] key = randomKey();
        SessionCipher cipher = new SessionCipher(key);

        byte[] plaintext = "Hello, secure world!".getBytes();
        SessionCipher.EncryptedPayload encrypted = cipher.encrypt(plaintext);

        byte[] decrypted = cipher.decrypt(encrypted.iv(), encrypted.ciphertext());
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void differentIvsProduceDifferentCiphertexts() throws GeneralSecurityException {
        byte[] key = randomKey();
        SessionCipher cipher = new SessionCipher(key);
        byte[] plaintext = "same message".getBytes();

        SessionCipher.EncryptedPayload e1 = cipher.encrypt(plaintext);
        SessionCipher.EncryptedPayload e2 = cipher.encrypt(plaintext);

        assertFalse(java.util.Arrays.equals(e1.iv(), e2.iv()));
        assertFalse(java.util.Arrays.equals(e1.ciphertext(), e2.ciphertext()));
    }

    @Test
    void wrongKeyFailsDecryption() throws GeneralSecurityException {
        SessionCipher cipher1 = new SessionCipher(randomKey());
        SessionCipher cipher2 = new SessionCipher(randomKey());

        SessionCipher.EncryptedPayload encrypted = cipher1.encrypt("secret".getBytes());

        assertThrows(GeneralSecurityException.class, () ->
                cipher2.decrypt(encrypted.iv(), encrypted.ciphertext()));
    }

    @Test
    void tamperedCiphertextFailsDecryption() throws GeneralSecurityException {
        byte[] key = randomKey();
        SessionCipher cipher = new SessionCipher(key);

        SessionCipher.EncryptedPayload encrypted = cipher.encrypt("important data".getBytes());
        byte[] tampered = encrypted.ciphertext().clone();
        tampered[0] ^= 0xFF;

        assertThrows(GeneralSecurityException.class, () ->
                cipher.decrypt(encrypted.iv(), tampered));
    }

    @Test
    void invalidKeySizeThrows() {
        assertThrows(IllegalArgumentException.class, () -> new SessionCipher(new byte[16]));
    }
}
