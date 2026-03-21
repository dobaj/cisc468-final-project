package com.p2pfs.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyExchangeTest {

    @Test
    void sharedSecretMatchesBothSides() {
        KeyExchange alice = new KeyExchange();
        KeyExchange bob = new KeyExchange();

        byte[] secretAlice = alice.computeSharedSecret(bob.getPublicKeyBytes());
        byte[] secretBob = bob.computeSharedSecret(alice.getPublicKeyBytes());

        assertArrayEquals(secretAlice, secretBob);
    }

    @Test
    void differentKeypairsProduceDifferentSecrets() {
        KeyExchange alice = new KeyExchange();
        KeyExchange bob = new KeyExchange();
        KeyExchange eve = new KeyExchange();

        byte[] aliceBob = alice.computeSharedSecret(bob.getPublicKeyBytes());
        byte[] aliceEve = alice.computeSharedSecret(eve.getPublicKeyBytes());

        assertFalse(java.util.Arrays.equals(aliceBob, aliceEve));
    }

    @Test
    void publicKeyIs32Bytes() {
        KeyExchange kx = new KeyExchange();
        assertEquals(32, kx.getPublicKeyBytes().length);
    }

    @Test
    void freshKeypairEachTime() {
        KeyExchange kx1 = new KeyExchange();
        KeyExchange kx2 = new KeyExchange();
        assertFalse(java.util.Arrays.equals(kx1.getPublicKeyBytes(), kx2.getPublicKeyBytes()));
    }
}
