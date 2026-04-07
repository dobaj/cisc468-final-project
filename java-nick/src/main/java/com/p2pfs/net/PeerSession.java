package com.p2pfs.net;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
import java.util.HexFormat;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * An authenticated, encrypted session with a remote peer.
 *
 * Supports two handshake modes:
 *   - Java protocol: AUTH_REQUEST → AUTH_RESPONSE → AUTH_SUCCESS (Ed25519-signed DH)
 *   - Native protocol: key_exchange → key_exchange → hello → hello (TOFU, used by Go/Python)
 *
 * After the handshake, session traffic is wrapped in:
 *   - Java:   {"type":"ENCRYPTED","iv":"<b64>","ciphertext":"<b64>"}
 *   - Native: {"type":"data","nonce":"<hex>","payload":"<hex>"}
 *
 * receiveEncrypted() detects both formats automatically.
 * sendEncrypted()    uses the format negotiated during handshake.
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
    private boolean nativeProtocol = false;

    /**
     * When non-null, receiveEncrypted() pulls from this queue instead of the socket.
     * Used by outgoing sessions so a background handlePeerMessages thread owns the socket
     * and routes incoming request/response messages appropriately.
     */
    private volatile BlockingQueue<String> receiveQueue;

    private static final HexFormat HEX = HexFormat.of();

    public PeerSession(Socket socket, Identity localIdentity, TrustStore trustStore, InputProvider input) throws IOException {
        this.socket = socket;
        this.framer = new MessageFramer(socket);
        this.localIdentity = localIdentity;
        this.trustStore = trustStore;
        this.input = input;
    }

    public boolean isAuthenticated()      { return authenticated; }
    public boolean isNativeProtocol()     { return nativeProtocol; }
    public String getRemoteIdentityPubBase64() { return remoteIdentityPubBase64; }
    public String getRemotePeerName()     { return remotePeerName; }
    public Socket getSocket()             { return socket; }

    /** Attach a queue so receiveEncrypted() reads from it instead of the socket. */
    public void setReceiveQueue(BlockingQueue<String> queue) { this.receiveQueue = queue; }

    /** Enqueue a pre-decrypted message for receiveEncrypted() to return. */
    public void enqueueReceived(String json) throws InterruptedException { receiveQueue.put(json); }

    // ── Incoming auto-detection ──────────────────────────────────────────────

    /**
     * Called on the server side when we don't yet know the remote peer's protocol.
     * Reads the first message and routes to the appropriate handshake.
     *
     * @param localPeerName  The local peer's display name (sent in the native "hello" message).
     */
    public void handshakeAutoDetect(String localPeerName) throws IOException {
        String firstMsg = framer.receive();
        String msgType = rawType(firstMsg);
        if ("key_exchange".equals(msgType)) {
            nativeProtocol = true;
            handshakeNativeAsResponder(firstMsg, localPeerName);
        } else if ("AUTH_REQUEST".equals(msgType)) {
            nativeProtocol = false;
            handshakeAsResponderInternal(firstMsg);
        } else {
            throw new IOException("Unknown handshake first message: " + msgType);
        }
    }

    // ── Java protocol handshake ──────────────────────────────────────────────

    /**
     * Performs the Java handshake as the initiator.
     * Flow: AUTH_REQUEST → AUTH_RESPONSE → AUTH_SUCCESS
     */
    public void handshakeAsInitiator() throws IOException {
        nativeProtocol = false;
        SecureRandom random = new SecureRandom();
        byte[] nonceA = new byte[ProtocolConstants.NONCE_BYTES];
        random.nextBytes(nonceA);

        KeyExchange kx = new KeyExchange();

        Messages.AuthRequest req = new Messages.AuthRequest();
        req.identity_pub = localIdentity.getPublicKeyBase64();
        req.ephemeral_pub = Base64.getEncoder().encodeToString(kx.getPublicKeyBytes());
        req.nonce = Base64.getEncoder().encodeToString(nonceA);
        framer.send(Messages.serialize(req));

        String replyJson = framer.receive();
        if (Messages.typeOf(replyJson) != MessageType.AUTH_RESPONSE) {
            throw new IOException("Expected AUTH_RESPONSE, got: " + replyJson);
        }
        Messages.AuthResponse reply = Messages.deserialize(replyJson, Messages.AuthResponse.class);

        byte[] remotePub = Base64.getDecoder().decode(reply.identity_pub);
        byte[] remoteEph = Base64.getDecoder().decode(reply.ephemeral_pub);
        byte[] nonceB   = Base64.getDecoder().decode(reply.nonce);
        byte[] sigB     = Base64.getDecoder().decode(reply.signature);

        byte[] localEph    = kx.getPublicKeyBytes();
        byte[] sigMessageB = concat(nonceA, localEph, remoteEph);
        if (!Identity.verify(remotePub, sigMessageB, sigB)) {
            sendError("HANDSHAKE_FAILED", "Responder signature verification failed");
            throw new IOException("Responder signature verification failed");
        }

        remoteIdentityPubBase64 = reply.identity_pub;
        if (!verifyTrust(remoteIdentityPubBase64)) {
            framer.send(Messages.serialize(new Messages.AuthFail("Peer not trusted")));
            throw new IOException("Remote peer not trusted");
        }

        byte[] sigMessageA = concat(nonceB, remoteEph, localEph);
        byte[] sigA = localIdentity.sign(sigMessageA);
        Messages.AuthSuccess auth = new Messages.AuthSuccess();
        auth.signature = Base64.getEncoder().encodeToString(sigA);
        framer.send(Messages.serialize(auth));

        byte[] sharedSecret = kx.computeSharedSecret(remoteEph);
        byte[] salt = concat(nonceA, nonceB);
        byte[] sessionKey = Hkdf.derive(sharedSecret, salt, ProtocolConstants.HKDF_INFO, ProtocolConstants.AES_KEY_BYTES);
        this.cipher = new SessionCipher(sessionKey);
        this.authenticated = true;

        var contact = trustStore.findByPublicKey(remoteIdentityPubBase64);
        this.remotePeerName = contact.map(c -> c.name).orElse("unknown");
    }

    /**
     * Java-protocol responder: reads the first message (expects AUTH_REQUEST) and completes the handshake.
     * Kept for tests and direct use; normally replaced by handshakeAutoDetect() on the server path.
     */
    public void handshakeAsResponder() throws IOException {
        nativeProtocol = false;
        handshakeAsResponderInternal(framer.receive());
    }

    // Internal responder path (first message already buffered).
    private void handshakeAsResponderInternal(String firstMsgJson) throws IOException {
        Messages.AuthRequest req = Messages.deserialize(firstMsgJson, Messages.AuthRequest.class);

        byte[] remotePub = Base64.getDecoder().decode(req.identity_pub);
        byte[] remoteEph = Base64.getDecoder().decode(req.ephemeral_pub);
        byte[] nonceA    = Base64.getDecoder().decode(req.nonce);

        remoteIdentityPubBase64 = req.identity_pub;
        if (!verifyTrust(remoteIdentityPubBase64)) {
            framer.send(Messages.serialize(new Messages.AuthFail("Peer not trusted")));
            throw new IOException("Remote peer not trusted");
        }

        SecureRandom random = new SecureRandom();
        byte[] nonceB  = new byte[ProtocolConstants.NONCE_BYTES];
        random.nextBytes(nonceB);

        KeyExchange kx = new KeyExchange();
        byte[] localEph = kx.getPublicKeyBytes();

        byte[] sigMessage = concat(nonceA, remoteEph, localEph);
        byte[] sig = localIdentity.sign(sigMessage);

        Messages.AuthResponse response = new Messages.AuthResponse();
        response.identity_pub = localIdentity.getPublicKeyBase64();
        response.ephemeral_pub = Base64.getEncoder().encodeToString(localEph);
        response.nonce = Base64.getEncoder().encodeToString(nonceB);
        response.signature = Base64.getEncoder().encodeToString(sig);
        framer.send(Messages.serialize(response));

        String authJson = framer.receive();
        if (Messages.typeOf(authJson) != MessageType.AUTH_SUCCESS) {
            throw new IOException("Expected AUTH_SUCCESS, got: " + authJson);
        }
        Messages.AuthSuccess auth = Messages.deserialize(authJson, Messages.AuthSuccess.class);

        byte[] sigMessageA = concat(nonceB, localEph, remoteEph);
        byte[] sigA = Base64.getDecoder().decode(auth.signature);
        if (!Identity.verify(remotePub, sigMessageA, sigA)) {
            sendError("HANDSHAKE_FAILED", "Initiator signature verification failed");
            throw new IOException("Initiator signature verification failed");
        }

        byte[] sharedSecret = kx.computeSharedSecret(remoteEph);
        byte[] salt = concat(nonceA, nonceB);
        byte[] sessionKey = Hkdf.derive(sharedSecret, salt, ProtocolConstants.HKDF_INFO, ProtocolConstants.AES_KEY_BYTES);
        this.cipher = new SessionCipher(sessionKey);
        this.authenticated = true;

        var contact = trustStore.findByPublicKey(remoteIdentityPubBase64);
        this.remotePeerName = contact.map(c -> c.name).orElse("unknown");
    }

    // ── Native protocol handshake (Go / Python) ──────────────────────────────

    /**
     * Native initiator: send key_exchange first, receive theirs, exchange hellos.
     * HKDF uses no salt and info="session key" (Go/Python default).
     *
     * @param localPeerName  The local peer's display name sent in the hello message.
     */
    public void handshakeNativeAsInitiator(String localPeerName) throws IOException {
        nativeProtocol = true;
        KeyExchange kx = new KeyExchange();

        Messages.NativeKeyExchange kxMsg = new Messages.NativeKeyExchange();
        kxMsg.pub = HEX.formatHex(kx.getPublicKeyBytes());
        framer.send(Messages.serialize(kxMsg));

        String theirKxJson = framer.receive();
        if (!"key_exchange".equals(rawType(theirKxJson))) {
            throw new IOException("Expected key_exchange, got: " + theirKxJson);
        }
        Messages.NativeKeyExchange theirKx = Messages.deserialize(theirKxJson, Messages.NativeKeyExchange.class);
        byte[] remoteEph = HEX.parseHex(theirKx.pub);

        byte[] sharedSecret = kx.computeSharedSecret(remoteEph);
        byte[] sessionKey = Hkdf.derive(sharedSecret, null, ProtocolConstants.NATIVE_HKDF_INFO, ProtocolConstants.AES_KEY_BYTES);
        this.cipher = new SessionCipher(sessionKey);

        sendNativeHello(localPeerName);

        String theirHelloJson = framer.receive();
        if (!"hello".equals(rawType(theirHelloJson))) {
            throw new IOException("Expected hello, got: " + theirHelloJson);
        }
        Messages.NativeHello theirHello = Messages.deserialize(theirHelloJson, Messages.NativeHello.class);

        verifyNativeHello(theirHello);
        this.authenticated = true;
        this.remotePeerName = theirHello.name;
    }

    /**
     * Native responder: already received the first key_exchange, respond with ours, then exchange hellos.
     */
    private void handshakeNativeAsResponder(String firstMsgJson, String localPeerName) throws IOException {
        Messages.NativeKeyExchange theirKx = Messages.deserialize(firstMsgJson, Messages.NativeKeyExchange.class);
        byte[] remoteEph = HEX.parseHex(theirKx.pub);

        KeyExchange kx = new KeyExchange();
        Messages.NativeKeyExchange kxMsg = new Messages.NativeKeyExchange();
        kxMsg.pub = HEX.formatHex(kx.getPublicKeyBytes());
        framer.send(Messages.serialize(kxMsg));

        byte[] sharedSecret = kx.computeSharedSecret(remoteEph);
        byte[] sessionKey = Hkdf.derive(sharedSecret, null, ProtocolConstants.NATIVE_HKDF_INFO, ProtocolConstants.AES_KEY_BYTES);
        this.cipher = new SessionCipher(sessionKey);

        sendNativeHello(localPeerName);

        String theirHelloJson = framer.receive();
        if (!"hello".equals(rawType(theirHelloJson))) {
            throw new IOException("Expected hello, got: " + theirHelloJson);
        }
        Messages.NativeHello theirHello = Messages.deserialize(theirHelloJson, Messages.NativeHello.class);

        verifyNativeHello(theirHello);
        this.authenticated = true;
        this.remotePeerName = theirHello.name;
    }

    private void sendNativeHello(String localPeerName) throws IOException {
        Messages.NativeHello helloMsg = new Messages.NativeHello();
        helloMsg.name         = localPeerName;
        helloMsg.identity_pub = HEX.formatHex(localIdentity.getPublicKeyBytes());
        helloMsg.fingerprint  = Identity.fingerprint(localIdentity.getPublicKeyBytes());
        framer.send(Messages.serialize(helloMsg));
    }

    /**
     * Checks the hello fingerprint and trust-stores the remote peer.
     * Converts hex pub key → base64 for trust store compatibility.
     */
    private void verifyNativeHello(Messages.NativeHello hello) throws IOException {
        byte[] remotePubBytes = HEX.parseHex(hello.identity_pub);
        String derivedFp = Identity.fingerprint(remotePubBytes); // already hex string

        if (!derivedFp.equals(hello.fingerprint)) {
            throw new IOException("Native hello fingerprint mismatch");
        }

        // Store as base64 in trust store for uniform handling
        remoteIdentityPubBase64 = Base64.getEncoder().encodeToString(remotePubBytes);
        if (!verifyTrust(remoteIdentityPubBase64)) {
            throw new IOException("Native peer not trusted");
        }
    }

    // ── Encrypted send / receive ─────────────────────────────────────────────

    /**
     * Wraps json in the appropriate encryption envelope and sends it.
     * Native sessions use {"type":"data","nonce":"<hex>","payload":"<hex>"}.
     * Java sessions use  {"type":"ENCRYPTED","iv":"<b64>","ciphertext":"<b64>"}.
     */
    public void sendEncrypted(String json) throws IOException {
        if (cipher == null) throw new IOException("Session not established");
        try {
            SessionCipher.EncryptedPayload payload = cipher.encrypt(json.getBytes(StandardCharsets.UTF_8));
            if (nativeProtocol) {
                Messages.NativeData env = new Messages.NativeData();
                env.nonce   = HEX.formatHex(payload.iv());
                env.payload = HEX.formatHex(payload.ciphertext());
                framer.send(Messages.serialize(env));
            } else {
                Messages.Encrypted env = new Messages.Encrypted();
                env.iv         = Base64.getEncoder().encodeToString(payload.iv());
                env.ciphertext = Base64.getEncoder().encodeToString(payload.ciphertext());
                framer.send(Messages.serialize(env));
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("Encryption failed", e);
        }
    }

    /**
     * Reads the next encrypted envelope and returns the decrypted inner JSON.
     * When a receiveQueue is attached (outgoing sessions with a background reader),
     * blocks on the queue instead of reading the socket directly.
     */
    public String receiveEncrypted() throws IOException {
        BlockingQueue<String> q = receiveQueue;
        if (q != null) {
            try {
                String msg = q.poll(30, TimeUnit.SECONDS);
                if (msg == null) throw new IOException("Timeout waiting for response from peer");
                return msg;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted waiting for response");
            }
        }
        return receiveEncryptedDirect();
    }

    /**
     * Reads and decrypts the next message directly from the socket.
     * Used by the background handlePeerMessages thread which owns the socket read side.
     */
    public String receiveEncryptedDirect() throws IOException {
        if (cipher == null) throw new IOException("Session not established");
        String envJson = framer.receive();
        String outerType = rawType(envJson);

        byte[] iv, ciphertext;
        JsonObject outer = JsonParser.parseString(envJson).getAsJsonObject();

        if ("ENCRYPTED".equals(outerType)) {
            iv         = Base64.getDecoder().decode(outer.get("iv").getAsString());
            ciphertext = Base64.getDecoder().decode(outer.get("ciphertext").getAsString());
        } else if ("data".equals(outerType)) {
            iv         = HEX.parseHex(outer.get("nonce").getAsString());
            ciphertext = HEX.parseHex(outer.get("payload").getAsString());
        } else {
            throw new IOException("Expected encrypted envelope, got: " + outerType);
        }

        try {
            byte[] plaintext = cipher.decrypt(iv, ciphertext);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IOException("Decryption failed (possible tampering)", e);
        }
    }

    /**
     * Sends a plaintext (unencrypted) error message. Used only during handshake.
     */
    public void sendError(String code, String message) {
        try {
            framer.send(Messages.serialize(new Messages.Error(code, message)));
        } catch (IOException ignored) {}
    }

    // ── Trust helpers ────────────────────────────────────────────────────────

    private boolean verifyTrust(String identityPubBase64) {
        if (trustStore.isTrusted(identityPubBase64)) {
            return true;
        }
        byte[] pubBytes = Base64.getDecoder().decode(identityPubBase64);
        String fp = Identity.formatFingerprint(Identity.fingerprint(pubBytes));
        System.out.println("\n[!] Unknown peer with fingerprint:");
        System.out.println("    " + fp);
        // Use println so async test harnesses can detect this line immediately
        // (System.out.print has no newline and won't be flushed to async readers promptly).
        System.out.println("Trust this peer? Enter a name to trust, or 'n' to reject:");
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

    // ── Utilities ────────────────────────────────────────────────────────────

    /** Returns the raw "type" string from a JSON message without requiring it to match a known enum. */
    public static String rawType(String json) {
        JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
        return obj.get("type").getAsString();
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
