package com.p2pfs.crypto;

import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.security.SecureRandom;

/**
 * X25519 ephemeral key exchange.
 * Each instance represents one side of a Diffie-Hellman exchange.
 */
public class KeyExchange {

    private final X25519PrivateKeyParameters privateKey;
    private final X25519PublicKeyParameters publicKey;

    public KeyExchange() {
        SecureRandom random = new SecureRandom();
        this.privateKey = new X25519PrivateKeyParameters(random);
        this.publicKey = privateKey.generatePublicKey();
    }

    public byte[] getPublicKeyBytes() {
        return publicKey.getEncoded();
    }

    /**
     * Computes the shared secret using this side's private key and the remote side's public key.
     */
    public byte[] computeSharedSecret(byte[] remotePublicKeyBytes) {
        X25519PublicKeyParameters remotePub = new X25519PublicKeyParameters(remotePublicKeyBytes, 0);
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(privateKey);
        byte[] secret = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(remotePub, secret, 0);
        return secret;
    }
}
