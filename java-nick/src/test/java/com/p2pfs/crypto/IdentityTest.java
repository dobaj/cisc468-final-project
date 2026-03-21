package com.p2pfs.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class IdentityTest {

    @Test
    void generateProducesValidKeypair() {
        Identity id = Identity.generate();
        assertNotNull(id.getPublicKeyBytes());
        assertEquals(32, id.getPublicKeyBytes().length);
        assertNotNull(id.getPrivateKeyBytes());
        assertEquals(32, id.getPrivateKeyBytes().length);
    }

    @Test
    void signAndVerify() {
        Identity id = Identity.generate();
        byte[] message = "hello world".getBytes();
        byte[] sig = id.sign(message);

        assertTrue(id.verify(message, sig));
    }

    @Test
    void verifyRejectsWrongMessage() {
        Identity id = Identity.generate();
        byte[] sig = id.sign("hello".getBytes());

        assertFalse(id.verify("wrong".getBytes(), sig));
    }

    @Test
    void verifyRejectsWrongKey() {
        Identity id1 = Identity.generate();
        Identity id2 = Identity.generate();
        byte[] message = "test".getBytes();
        byte[] sig = id1.sign(message);

        assertFalse(id2.verify(message, sig));
    }

    @Test
    void fingerprintIsDeterministic() {
        Identity id = Identity.generate();
        String fp1 = id.getFingerprint();
        String fp2 = Identity.fingerprint(id.getPublicKeyBytes());
        assertEquals(fp1, fp2);
        assertEquals(64, fp1.length()); // SHA-256 hex = 64 chars
    }

    @Test
    void formatFingerprintGroupsByFour() {
        String hex = "abcdef0123456789";
        String formatted = Identity.formatFingerprint(hex);
        assertEquals("ABCD EF01 2345 6789", formatted);
    }

    @Test
    void saveAndLoad(@TempDir Path tempDir) throws IOException {
        Identity original = Identity.generate();
        original.save(tempDir);

        Identity loaded = Identity.load(tempDir);
        assertArrayEquals(original.getPublicKeyBytes(), loaded.getPublicKeyBytes());
        assertArrayEquals(original.getPrivateKeyBytes(), loaded.getPrivateKeyBytes());

        // Verify loaded key can sign and verify
        byte[] msg = "test load".getBytes();
        byte[] sig = loaded.sign(msg);
        assertTrue(Identity.verify(original.getPublicKeyBytes(), msg, sig));
    }

    @Test
    void loadOrGenerateCreatesNewIfNotExists(@TempDir Path tempDir) throws IOException {
        Identity id = Identity.loadOrGenerate(tempDir);
        assertNotNull(id);
        assertTrue(tempDir.resolve("identity.key").toFile().exists());
        assertTrue(tempDir.resolve("identity.pub").toFile().exists());
    }

    @Test
    void loadOrGenerateReusesExisting(@TempDir Path tempDir) throws IOException {
        Identity first = Identity.loadOrGenerate(tempDir);
        Identity second = Identity.loadOrGenerate(tempDir);
        assertArrayEquals(first.getPublicKeyBytes(), second.getPublicKeyBytes());
    }
}
