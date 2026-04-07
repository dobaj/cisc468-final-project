package com.p2pfs.integration;

import com.p2pfs.InputProvider;
import com.p2pfs.crypto.Identity;
import com.p2pfs.net.PeerSession;
import com.p2pfs.net.TcpServer;
import com.p2pfs.trust.TrustStore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.Socket;
import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class HandshakeTest {

    /**
     * Two peers perform a full handshake: AUTH_REQUEST -> AUTH_RESPONSE -> AUTH_SUCCESS,
     * then exchange an encrypted message to verify the session works.
     */
    @Test
    void fullHandshakeAndEncryptedExchange(@TempDir Path tempDir) throws Exception {
        Identity alice = Identity.generate();
        Identity bob = Identity.generate();

        Path aliceDir = tempDir.resolve("alice");
        Path bobDir = tempDir.resolve("bob");

        TrustStore aliceTrust = new TrustStore(aliceDir.resolve("trust.json"));
        TrustStore bobTrust = new TrustStore(bobDir.resolve("trust.json"));

        // Pre-trust each other (simulating out-of-band verification)
        aliceTrust.addContact("bob", bob.getPublicKeyBase64());
        bobTrust.addContact("alice", alice.getPublicKeyBase64());

        // Queue that auto-answers (not needed since keys are pre-trusted, but required as param)
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

        // Client side
        Socket clientSocket = new Socket("127.0.0.1", port);
        PeerSession clientSession = new PeerSession(clientSocket, alice, aliceTrust, noInput);
        clientSession.handshakeAsInitiator();

        assertTrue(clientSession.isAuthenticated());

        PeerSession bobSession = serverSession.get(5, TimeUnit.SECONDS);
        assertTrue(bobSession.isAuthenticated());

        // Exchange encrypted messages
        clientSession.sendEncrypted("{\"type\":\"FILE_LIST_REQUEST\"}");
        String received = bobSession.receiveEncrypted();
        assertEquals("{\"type\":\"FILE_LIST_REQUEST\"}", received);

        bobSession.sendEncrypted("{\"type\":\"FILE_LIST_RESPONSE\",\"files\":[]}");
        String response = clientSession.receiveEncrypted();
        assertTrue(response.contains("FILE_LIST_RESPONSE"));

        clientSession.close();
        bobSession.close();
        server.close();
    }

    /**
     * Handshake fails when the peer's identity is not trusted and no user input is available.
     */
    @Test
    void handshakeFailsWithUntrustedPeer(@TempDir Path tempDir) throws Exception {
        Identity alice = Identity.generate();
        Identity bob = Identity.generate();

        TrustStore aliceTrust = new TrustStore(tempDir.resolve("alice_trust.json"));
        TrustStore bobTrust = new TrustStore(tempDir.resolve("bob_trust.json"));

        // Alice does NOT trust Bob, Bob trusts Alice
        bobTrust.addContact("alice", alice.getPublicKeyBase64());

        // InputProvider returns 'n' to reject
        InputProvider rejectInput = () -> "n";
        InputProvider noInput = () -> { try { Thread.sleep(60000); } catch (InterruptedException e) {} return "n"; };

        TcpServer server = new TcpServer(0);
        int port = server.getPort();

        CompletableFuture<Void> serverDone = new CompletableFuture<>();
        server.acceptAsync(socket -> {
            try {
                PeerSession session = new PeerSession(socket, bob, bobTrust, noInput);
                session.handshakeAsResponder();
                serverDone.complete(null);
            } catch (IOException e) {
                serverDone.completeExceptionally(e);
            }
        });

        Socket clientSocket = new Socket("127.0.0.1", port);
        PeerSession clientSession = new PeerSession(clientSocket, alice, aliceTrust, rejectInput);

        // Alice should reject Bob since he's not trusted
        assertThrows(IOException.class, clientSession::handshakeAsInitiator);

        clientSocket.close();
        server.close();
    }
}
