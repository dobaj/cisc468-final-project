package com.p2pfs.integration;

import com.p2pfs.crypto.FileHash;
import com.p2pfs.crypto.Identity;
import com.p2pfs.net.PeerSession;
import com.p2pfs.net.TcpServer;
import com.p2pfs.protocol.Messages;
import com.p2pfs.protocol.MessageType;
import com.p2pfs.protocol.ProtocolConstants;
import com.p2pfs.trust.TrustStore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.p2pfs.InputProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class FileTransferTest {

    /**
     * Full file transfer: request -> consent -> chunked transfer -> hash verify.
     */
    @Test
    void fullFileTransferWithHashVerification(@TempDir Path tempDir) throws Exception {
        Identity alice = Identity.generate();
        Identity bob = Identity.generate();

        TrustStore aliceTrust = new TrustStore(tempDir.resolve("alice_trust.json"));
        TrustStore bobTrust = new TrustStore(tempDir.resolve("bob_trust.json"));
        aliceTrust.addContact("bob", bob.getPublicKeyBase64());
        bobTrust.addContact("alice", alice.getPublicKeyBase64());

        // Create a test file that Bob will share
        Path bobFile = tempDir.resolve("testfile.txt");
        byte[] fileContent = "This is the test file content for transfer verification.".getBytes();
        Files.write(bobFile, fileContent);
        String expectedHash = FileHash.hashFile(bobFile);

        BlockingQueue<String> q = new LinkedBlockingQueue<>();
        InputProvider noInput = () -> { try { return q.take(); } catch (InterruptedException e) { return "n"; } };

        TcpServer server = new TcpServer(0);
        int port = server.getPort();

        CompletableFuture<PeerSession> serverSession = new CompletableFuture<>();
        server.acceptAsync(socket -> {
            try {
                PeerSession session = new PeerSession(socket, bob, bobTrust, noInput);
                session.handshakeAsResponder();
                serverSession.complete(session);
            } catch (IOException e) {
                serverSession.completeExceptionally(e);
            }
        });

        // Client (Alice) connects
        Socket clientSocket = new Socket("127.0.0.1", port);
        PeerSession aliceSession = new PeerSession(clientSocket, alice, aliceTrust, noInput);
        aliceSession.handshakeAsInitiator();
        PeerSession bobSession = serverSession.get(5, TimeUnit.SECONDS);

        // Alice sends FILE_REQUEST
        Messages.FileRequest req = new Messages.FileRequest();
        req.hash = expectedHash;
        req.name = "testfile.txt";
        aliceSession.sendEncrypted(Messages.serialize(req));

        // Bob receives the request and accepts
        String reqJson = bobSession.receiveEncrypted();
        assertEquals(MessageType.FILE_REQUEST, Messages.typeOf(reqJson));
        Messages.FileResponse resp = new Messages.FileResponse();
        resp.hash = expectedHash;
        resp.accepted = true;
        bobSession.sendEncrypted(Messages.serialize(resp));

        // Bob sends file data in chunks
        int chunkSize = ProtocolConstants.MAX_CHUNK_BYTES;
        int totalChunks = (int) Math.ceil((double) fileContent.length / chunkSize);
        if (totalChunks == 0) totalChunks = 1;

        for (int i = 0; i < totalChunks; i++) {
            int offset = i * chunkSize;
            int len = Math.min(chunkSize, fileContent.length - offset);
            Messages.FileData data = new Messages.FileData();
            data.hash = expectedHash;
            data.chunk_index = i;
            data.total_chunks = totalChunks;
            data.data = Base64.getEncoder().encodeToString(
                    Arrays.copyOfRange(fileContent, offset, offset + len));
            bobSession.sendEncrypted(Messages.serialize(data));
        }

        // Alice receives consent response
        String respJson = aliceSession.receiveEncrypted();
        Messages.FileResponse parsedResp = Messages.deserialize(respJson, Messages.FileResponse.class);
        assertTrue(parsedResp.accepted);

        // Alice receives and reassembles chunks
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (int i = 0; i < totalChunks; i++) {
            String dataJson = aliceSession.receiveEncrypted();
            Messages.FileData chunk = Messages.deserialize(dataJson, Messages.FileData.class);
            bos.write(Base64.getDecoder().decode(chunk.data));
        }

        // Verify hash
        byte[] received = bos.toByteArray();
        assertTrue(FileHash.verify(received, expectedHash));
        assertArrayEquals(fileContent, received);

        aliceSession.close();
        bobSession.close();
        server.close();
    }

    /**
     * Tampered file data should fail hash verification.
     */
    @Test
    void tamperedFileDetected() {
        byte[] original = "original file content".getBytes();
        String originalHash = FileHash.hashBytes(original);

        byte[] tampered = "tampered file content".getBytes();
        assertFalse(FileHash.verify(tampered, originalHash));
    }

    /**
     * File hash is consistent.
     */
    @Test
    void fileHashDeterministic(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("test.bin");
        byte[] data = new byte[1024];
        new Random(42).nextBytes(data);
        Files.write(file, data);

        String hash1 = FileHash.hashFile(file);
        String hash2 = FileHash.hashFile(file);
        assertEquals(hash1, hash2);
        assertEquals(64, hash1.length());
    }

    /**
     * Tests encrypted storage round-trip.
     */
    @Test
    void encryptedStorageRoundTrip(@TempDir Path tempDir) throws Exception {
        com.p2pfs.storage.EncryptedFileStore store =
                new com.p2pfs.storage.EncryptedFileStore(tempDir.resolve("store"), "test-passphrase");

        byte[] data = "confidential file data".getBytes();
        String hash = FileHash.hashBytes(data);

        store.storeFile("secret.txt", hash, "origin-key", data);

        Optional<byte[]> retrieved = store.retrieveFile(hash);
        assertTrue(retrieved.isPresent());
        assertArrayEquals(data, retrieved.get());
    }

    /**
     * Wrong passphrase cannot decrypt stored files.
     */
    @Test
    void wrongPassphraseCannotDecrypt(@TempDir Path tempDir) throws Exception {
        com.p2pfs.storage.EncryptedFileStore store1 =
                new com.p2pfs.storage.EncryptedFileStore(tempDir.resolve("store"), "correct-passphrase");

        byte[] data = "secret data".getBytes();
        String hash = FileHash.hashBytes(data);
        store1.storeFile("file.txt", hash, "origin", data);

        // Different passphrase, same salt file -> different key -> decryption should fail
        assertThrows(Exception.class, () -> {
            com.p2pfs.storage.EncryptedFileStore store2 =
                    new com.p2pfs.storage.EncryptedFileStore(tempDir.resolve("store"), "wrong-passphrase");
            store2.retrieveFile(hash);
        });
    }

    /**
     * Tests key migration verification.
     */
    @Test
    void keyMigrationVerification() {
        Identity oldId = Identity.generate();
        Identity newId = Identity.generate();

        Messages.KeyMigration msg = com.p2pfs.trust.KeyMigration.createMigrationMessage(oldId, newId);

        assertTrue(com.p2pfs.trust.KeyMigration.verify(msg, oldId.getPublicKeyBase64()));
    }

    /**
     * Key migration with wrong current key fails.
     */
    @Test
    void keyMigrationRejectsWrongKey() {
        Identity oldId = Identity.generate();
        Identity newId = Identity.generate();
        Identity imposter = Identity.generate();

        Messages.KeyMigration msg = com.p2pfs.trust.KeyMigration.createMigrationMessage(oldId, newId);

        // Using imposter's key as the "current" key should fail
        assertFalse(com.p2pfs.trust.KeyMigration.verify(msg, imposter.getPublicKeyBase64()));
    }
}
