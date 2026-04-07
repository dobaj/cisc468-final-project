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

// encrypted peer session; Java (AUTH_REQUEST->AUTH_SUCCESS) or native Go/Python (key_exchange->hello, TOFU)
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

    // when set, receiveEncrypted() reads from this queue instead of the socket (background reader owns the socket)
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

    public void setReceiveQueue(BlockingQueue<String> queue) { this.receiveQueue = queue; }

    public void enqueueReceived(String json) throws InterruptedException { receiveQueue.put(json); }

    // --- Incoming auto-detection ---

    // sniffs the first message to pick Java vs native handshake path
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

    // --- Java protocol handshake ---

    // AUTH_REQUEST -> AUTH_RESPONSE -> AUTH_SUCCESS
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

    // direct responder entry point, normally handshakeAutoDetect() is used instead
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

    // --- Native protocol handshake (Go / Python) ---

    // key_exchange -> key_exchange -> hello -> hello; HKDF info="session key" (Go/Python convention)
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

    // validates the hello fingerprint and stores the peer in base64 (trust store format)
    private void verifyNativeHello(Messages.NativeHello hello) throws IOException {
        byte[] remotePubBytes = HEX.parseHex(hello.identity_pub);
        String derivedFp = Identity.fingerprint(remotePubBytes); // already hex string

        if (!derivedFp.equals(hello.fingerprint)) {
            throw new IOException("Native hello fingerprint mismatch");
        }

        remoteIdentityPubBase64 = Base64.getEncoder().encodeToString(remotePubBytes);
        if (!verifyTrust(remoteIdentityPubBase64)) {
            throw new IOException("Native peer not trusted");
        }
    }

    // --- Encrypted send / receive ---

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

    // reads from the queue if one is attached (background reader owns the socket), else reads directly
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

    // reads directly from the socket, only the background dispatch thread should call this
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

    // plaintext error, only valid during handshake before cipher is established
    public void sendError(String code, String message) {
        try {
            framer.send(Messages.serialize(new Messages.Error(code, message)));
        } catch (IOException ignored) {}
    }

    // --- Trust helpers ---

    private boolean verifyTrust(String identityPubBase64) {
        if (trustStore.isTrusted(identityPubBase64)) {
            return true;
        }
        byte[] pubBytes = Base64.getDecoder().decode(identityPubBase64);
        String fp = Identity.formatFingerprint(Identity.fingerprint(pubBytes));
        System.out.println("\n[!] Unknown peer with fingerprint:");
        System.out.println("    " + fp);
        // println (not print) so async readers get the line immediately
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

    // --- Utilities ---

    // extracts "type" without needing it to be a known enum value
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
