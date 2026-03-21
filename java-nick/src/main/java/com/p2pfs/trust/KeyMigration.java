package com.p2pfs.trust;

import com.p2pfs.crypto.Identity;
import com.p2pfs.protocol.Messages;

import java.io.IOException;
import java.util.Base64;

/**
 * Handles key migration: generating migration messages and
 * verifying incoming migration requests.
 */
public class KeyMigration {

    /**
     * Creates a KEY_MIGRATION message from the old identity to a new one.
     * The old key signs the new public key, and the new key signs the old public key.
     */
    public static Messages.KeyMigration createMigrationMessage(Identity oldIdentity, Identity newIdentity) {
        byte[] oldPub = oldIdentity.getPublicKeyBytes();
        byte[] newPub = newIdentity.getPublicKeyBytes();

        byte[] sigOld = oldIdentity.sign(newPub);
        byte[] sigNew = newIdentity.sign(oldPub);

        Messages.KeyMigration msg = new Messages.KeyMigration();
        msg.new_identity_pub = Base64.getEncoder().encodeToString(newPub);
        msg.signature_old = Base64.getEncoder().encodeToString(sigOld);
        msg.signature_new = Base64.getEncoder().encodeToString(sigNew);
        return msg;
    }

    /**
     * Verifies a KEY_MIGRATION message.
     *
     * @param msg the migration message
     * @param currentPubBase64 the sender's currently trusted public key (Base64)
     * @return true if both signatures verify correctly
     */
    public static boolean verify(Messages.KeyMigration msg, String currentPubBase64) {
        byte[] oldPub = Base64.getDecoder().decode(currentPubBase64);
        byte[] newPub = Base64.getDecoder().decode(msg.new_identity_pub);
        byte[] sigOld = Base64.getDecoder().decode(msg.signature_old);
        byte[] sigNew = Base64.getDecoder().decode(msg.signature_new);

        boolean oldVerifies = Identity.verify(oldPub, newPub, sigOld);
        boolean newVerifies = Identity.verify(newPub, oldPub, sigNew);

        return oldVerifies && newVerifies;
    }

    /**
     * Applies a verified migration to the trust store.
     */
    public static void applyMigration(TrustStore trustStore, String oldPubBase64, String newPubBase64) throws IOException {
        trustStore.updatePublicKey(oldPubBase64, newPubBase64);
    }
}
