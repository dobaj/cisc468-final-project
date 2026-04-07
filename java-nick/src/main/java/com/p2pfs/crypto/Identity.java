package com.p2pfs.crypto;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

// Ed25519 long-term identity keypair, sign, verify, fingerprint
public class Identity {

    private final Ed25519PrivateKeyParameters privateKey;
    private final Ed25519PublicKeyParameters publicKey;

    public Identity(Ed25519PrivateKeyParameters privateKey) {
        this.privateKey = privateKey;
        this.publicKey = privateKey.generatePublicKey();
    }

    public Identity(Ed25519PrivateKeyParameters privateKey, Ed25519PublicKeyParameters publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public static Identity generate() {
        SecureRandom random = new SecureRandom();
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(random);
        return new Identity(priv);
    }

    public byte[] getPublicKeyBytes() {
        return publicKey.getEncoded();
    }

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(getPublicKeyBytes());
    }

    public byte[] getPrivateKeyBytes() {
        return privateKey.getEncoded();
    }

    // SHA-256 of the public key as a hex string
    public String getFingerprint() {
        return fingerprint(getPublicKeyBytes());
    }

    public static String fingerprint(byte[] publicKeyBytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(publicKeyBytes);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // breaks a hex fingerprint into spaced groups of 4 for display
    public static String formatFingerprint(String hex) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 4) {
            if (i > 0) sb.append(' ');
            sb.append(hex, i, Math.min(i + 4, hex.length()));
        }
        return sb.toString().toUpperCase();
    }

    public byte[] sign(byte[] message) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    public static boolean verify(byte[] publicKeyBytes, byte[] message, byte[] signature) {
        Ed25519PublicKeyParameters pubKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, pubKey);
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signature);
    }

    public boolean verify(byte[] message, byte[] signature) {
        return verify(getPublicKeyBytes(), message, signature);
    }

    public void save(Path directory) throws IOException {
        Files.createDirectories(directory);
        Files.write(directory.resolve("identity.key"), getPrivateKeyBytes());
        Files.write(directory.resolve("identity.pub"), getPublicKeyBytes());
    }

    public static Identity load(Path directory) throws IOException {
        byte[] privBytes = Files.readAllBytes(directory.resolve("identity.key"));
        byte[] pubBytes = Files.readAllBytes(directory.resolve("identity.pub"));
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(privBytes, 0);
        Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(pubBytes, 0);
        return new Identity(priv, pub);
    }

    public static Identity loadOrGenerate(Path directory) throws IOException {
        if (Files.exists(directory.resolve("identity.key"))) {
            return load(directory);
        }
        Identity id = generate();
        id.save(directory);
        return id;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
