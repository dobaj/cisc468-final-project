package com.p2pfs.crypto;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class HkdfTest {

    @Test
    void derivesCorrectLength() {
        byte[] ikm = new byte[32];
        new SecureRandom().nextBytes(ikm);
        byte[] salt = new byte[64];
        new SecureRandom().nextBytes(salt);

        byte[] key = Hkdf.derive(ikm, salt, "test-info", 32);
        assertEquals(32, key.length);
    }

    @Test
    void sameInputsProduceSameOutput() {
        byte[] ikm = "input-key-material".getBytes();
        byte[] salt = "salt-value".getBytes();

        byte[] key1 = Hkdf.derive(ikm, salt, "info", 32);
        byte[] key2 = Hkdf.derive(ikm, salt, "info", 32);

        assertArrayEquals(key1, key2);
    }

    @Test
    void differentSaltProducesDifferentOutput() {
        byte[] ikm = "same-ikm".getBytes();

        byte[] key1 = Hkdf.derive(ikm, "salt-a".getBytes(), "info", 32);
        byte[] key2 = Hkdf.derive(ikm, "salt-b".getBytes(), "info", 32);

        assertFalse(java.util.Arrays.equals(key1, key2));
    }

    @Test
    void differentInfoProducesDifferentOutput() {
        byte[] ikm = "same-ikm".getBytes();
        byte[] salt = "same-salt".getBytes();

        byte[] key1 = Hkdf.derive(ikm, salt, "info-a", 32);
        byte[] key2 = Hkdf.derive(ikm, salt, "info-b", 32);

        assertFalse(java.util.Arrays.equals(key1, key2));
    }

    @Test
    void canDeriveVariableLengths() {
        byte[] ikm = "ikm".getBytes();
        byte[] salt = "salt".getBytes();

        assertEquals(16, Hkdf.derive(ikm, salt, "info", 16).length);
        assertEquals(32, Hkdf.derive(ikm, salt, "info", 32).length);
        assertEquals(64, Hkdf.derive(ikm, salt, "info", 64).length);
    }
}
