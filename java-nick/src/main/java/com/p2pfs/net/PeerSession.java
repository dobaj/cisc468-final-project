package com.p2pfs.net;

import com.p2pfs.crypto.*;
import com.p2pfs.protocol.Messages;
import com.p2pfs.protocol.MessageType;
import com.p2pfs.protocol.ProtocolConstants;
import com.p2pfs.trust.TrustStore;

import com.p2pfs.InputProvider;

import java.io.Closeable;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * An authenticated, encrypted session with a remote peer.
 * Handles the full handshake lifecycle and encrypted message exchange.
 */
public class PeerSession implements Closeable {

    private final Socket socket;
    private final MessageFramer framer;
    private final Identity localIdentity;
    private final TrustStore trustStore;
    private final InputProvider input;

    private SessionCipher cipher;
    private String remoteIdentityPubBase64;
    private String remotePeerName;
    private boolean authenticated = false;

    public PeerSession(Socket socket, Identity localIdentity, TrustStore trustStore, InputProvider input) throws IOException {
        this.socket = socket;
        this.framer = new MessageFramer(socket);
        this.localIdentity = localIdentity;
        this.trustStore = trustStore;
        this.input = input;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public String getRemoteIdentityPubBase64() {
        return remoteIdentityPubBase64;
    }

    public String getRemotePeerName() {
        return remotePeerName;
    }

    public Socket getSocket() {
        return socket;
    }

    /**
     * Performs the handshake as the initiator (client side).
     */
    public void handshakeAsInitiator() throws IOException {
        SecureRandom random = new SecureRandom();
        byte[] nonceA = new byte[ProtocolConstants.NONCE_BYTES];
        random.nextBytes(nonceA);

        KeyExchange kx = new KeyExchange();

        // Send HELLO
        Messages.Hello hello = new Messages.Hello();
        hello.identity_pub = localIdentity.getPublicKeyBase64();
        hello.ephemeral_pub = Base64.getEncoder().encodeToString(kx.getPublicKeyBytes());
        hello.nonce = Base64.getEncoder().encodeToString(nonceA);
        framer.send(Messages.serialize(hello));

        // Receive HELLO_REPLY
        String replyJson = framer.receive();
        if (Messages.typeOf(replyJson) != MessageType.HELLO_REPLY) {
            throw new IOException("Expected HELLO_REPLY, got: " + replyJson);
        }
        Messages.HelloReply reply = Messages.deserialize(replyJson, Messages.HelloReply.class);

        byte[] remotePub = Base64.getDecoder().decode(reply.identity_pub);
        byte[] remoteEph = Base64.getDecoder().decode(reply.ephemeral_pub);
        byte[] nonceB = Base64.getDecoder().decode(reply.nonce);
        byte[] sigB = Base64.getDecoder().decode(reply.signature);

        // Verify responder's signature: Sign_B(nonce_a || eph_a || eph_b)
        byte[] localEph = kx.getPublicKeyBytes();
        byte[] sigMessageB = concat(nonceA, localEph, remoteEph);
        if (!Identity.verify(remotePub, sigMessageB, sigB)) {
            sendError("HANDSHAKE_FAILED", "Responder signature verification failed");
            throw new IOException("Responder signature verification failed");
        }

        // Trust check
        remoteIdentityPubBase64 = reply.identity_pub;
        if (!verifyTrust(remoteIdentityPubBase64)) {
            sendError("UNTRUSTED_KEY", "Peer not trusted");
            throw new IOException("Remote peer not trusted");
        }

        // Send AUTH: Sign_A(nonce_b || eph_b || eph_a)
        byte[] sigMessageA = concat(nonceB, remoteEph, localEph);
        byte[] sigA = localIdentity.sign(sigMessageA);
        Messages.Auth auth = new Messages.Auth();
        auth.signature = Base64.getEncoder().encodeToString(sigA);
        framer.send(Messages.serialize(auth));

        // Derive session key
        byte[] sharedSecret = kx.computeSharedSecret(remoteEph);
        byte[] salt = concat(nonceA, nonceB);
        byte[] sessionKey = Hkdf.derive(sharedSecret, salt, ProtocolConstants.HKDF_INFO, ProtocolConstants.AES_KEY_BYTES);
        this.cipher = new SessionCipher(sessionKey);
        this.authenticated = true;

        var contact = trustStore.findByPublicKey(remoteIdentityPubBase64);
        this.remotePeerName = contact.map(c -> c.name).orElse("unknown");
    }

    /**
     * Performs the handshake as the responder (server side).
     */
    public void handshakeAsResponder() throws IOException {
        // Receive HELLO
        String helloJson = framer.receive();
        if (Messages.typeOf(helloJson) != MessageType.HELLO) {
            throw new IOException("Expected HELLO, got: " + helloJson);
        }
        Messages.Hello hello = Messages.deserialize(helloJson, Messages.Hello.class);

        byte[] remotePub = Base64.getDecoder().decode(hello.identity_pub);
        byte[] remoteEph = Base64.getDecoder().decode(hello.ephemeral_pub);
        byte[] nonceA = Base64.getDecoder().decode(hello.nonce);

        // Trust check
        remoteIdentityPubBase64 = hello.identity_pub;
        if (!verifyTrust(remoteIdentityPubBase64)) {
            sendError("UNTRUSTED_KEY", "Peer not trusted");
            throw new IOException("Remote peer not trusted");
        }

        SecureRandom random = new SecureRandom();
        byte[] nonceB = new byte[ProtocolConstants.NONCE_BYTES];
        random.nextBytes(nonceB);

        KeyExchange kx = new KeyExchange();
        byte[] localEph = kx.getPublicKeyBytes();

        // Sign: Sign_B(nonce_a || eph_a || eph_b)
        byte[] sigMessage = concat(nonceA, remoteEph, localEph);
        byte[] sig = localIdentity.sign(sigMessage);

        // Send HELLO_REPLY
        Messages.HelloReply reply = new Messages.HelloReply();
        reply.identity_pub = localIdentity.getPublicKeyBase64();
        reply.ephemeral_pub = Base64.getEncoder().encodeToString(localEph);
        reply.nonce = Base64.getEncoder().encodeToString(nonceB);
        reply.signature = Base64.getEncoder().encodeToString(sig);
        framer.send(Messages.serialize(reply));

        // Receive AUTH
        String authJson = framer.receive();
        if (Messages.typeOf(authJson) != MessageType.AUTH) {
            throw new IOException("Expected AUTH, got: " + authJson);
        }
        Messages.Auth auth = Messages.deserialize(authJson, Messages.Auth.class);

        // Verify initiator's signature: Sign_A(nonce_b || eph_b || eph_a)
        byte[] sigMessageA = concat(nonceB, localEph, remoteEph);
        byte[] sigA = Base64.getDecoder().decode(auth.signature);
        if (!Identity.verify(remotePub, sigMessageA, sigA)) {
            sendError("HANDSHAKE_FAILED", "Initiator signature verification failed");
            throw new IOException("Initiator signature verification failed");
        }

        // Derive session key
        byte[] sharedSecret = kx.computeSharedSecret(remoteEph);
        byte[] salt = concat(nonceA, nonceB);
        byte[] sessionKey = Hkdf.derive(sharedSecret, salt, ProtocolConstants.HKDF_INFO, ProtocolConstants.AES_KEY_BYTES);
        this.cipher = new SessionCipher(sessionKey);
        this.authenticated = true;

        var contact = trustStore.findByPublicKey(remoteIdentityPubBase64);
        this.remotePeerName = contact.map(c -> c.name).orElse("unknown");
    }

    /**
     * Sends an encrypted message (wraps in ENCRYPTED envelope).
     */
    public void sendEncrypted(String json) throws IOException {
        if (cipher == null) throw new IOException("Session not established");
        try {
            SessionCipher.EncryptedPayload payload = cipher.encrypt(json.getBytes(StandardCharsets.UTF_8));
            Messages.Encrypted env = new Messages.Encrypted();
            env.iv = Base64.getEncoder().encodeToString(payload.iv());
            env.ciphertext = Base64.getEncoder().encodeToString(payload.ciphertext());
            framer.send(Messages.serialize(env));
        } catch (GeneralSecurityException e) {
            throw new IOException("Encryption failed", e);
        }
    }

    /**
     * Receives and decrypts an ENCRYPTED envelope, returning the inner JSON.
     */
    public String receiveEncrypted() throws IOException {
        if (cipher == null) throw new IOException("Session not established");
        String envJson = framer.receive();
        if (Messages.typeOf(envJson) != MessageType.ENCRYPTED) {
            throw new IOException("Expected ENCRYPTED, got: " + envJson);
        }
        Messages.Encrypted env = Messages.deserialize(envJson, Messages.Encrypted.class);
        try {
            byte[] iv = Base64.getDecoder().decode(env.iv);
            byte[] ciphertext = Base64.getDecoder().decode(env.ciphertext);
            byte[] plaintext = cipher.decrypt(iv, ciphertext);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IOException("Decryption failed (possible tampering)", e);
        }
    }

    /**
     * Sends a plaintext (unencrypted) error message.
     */
    public void sendError(String code, String message) {
        try {
            framer.send(Messages.serialize(new Messages.Error(code, message)));
        } catch (IOException ignored) {}
    }

    private boolean verifyTrust(String identityPubBase64) {
        if (trustStore.isTrusted(identityPubBase64)) {
            return true;
        }
        byte[] pubBytes = Base64.getDecoder().decode(identityPubBase64);
        String fp = Identity.formatFingerprint(Identity.fingerprint(pubBytes));
        System.out.println("\n[!] Unknown peer with fingerprint:");
        System.out.println("    " + fp);
        System.out.print("Trust this peer? Enter a name to trust, or 'n' to reject: ");
        System.out.flush();
        String response = input.readLine().trim();
        if (response.isEmpty() || response.equalsIgnoreCase("n")) {
            return false;
        }
        try {
            trustStore.addContact(response, identityPubBase64);
            System.out.println("[+] Trusted '" + response + "'");
            return true;
        } catch (IOException e) {
            System.err.println("Failed to save trust store: " + e.getMessage());
            return false;
        }
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
