package com.p2pfs.trust;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.p2pfs.crypto.Identity;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

// persists trusted peer identities (name -> Ed25519 pub key + fingerprint)
public class TrustStore {

    public static class Contact {
        public String name;
        public String identity_pub; // Base64
        public String fingerprint;  // hex SHA-256
        public String trusted_at;

        public Contact() {}

        public Contact(String name, String identityPubBase64) {
            this.name = name;
            this.identity_pub = identityPubBase64;
            byte[] pubBytes = Base64.getDecoder().decode(identityPubBase64);
            this.fingerprint = Identity.fingerprint(pubBytes);
            this.trusted_at = Instant.now().toString();
        }
    }

    private final Path filePath;
    private final List<Contact> contacts;
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    public TrustStore(Path filePath) throws IOException {
        this.filePath = filePath;
        if (Files.exists(filePath)) {
            String json = Files.readString(filePath, StandardCharsets.UTF_8);
            Type listType = new TypeToken<List<Contact>>() {}.getType();
            List<Contact> loaded = GSON.fromJson(json, listType);
            this.contacts = loaded != null ? new ArrayList<>(loaded) : new ArrayList<>();
        } else {
            this.contacts = new ArrayList<>();
        }
    }

    public void addContact(String name, String identityPubBase64) throws IOException {
        contacts.removeIf(c -> c.identity_pub.equals(identityPubBase64));
        contacts.add(new Contact(name, identityPubBase64));
        save();
    }

    public boolean isTrusted(String identityPubBase64) {
        return contacts.stream().anyMatch(c -> c.identity_pub.equals(identityPubBase64));
    }

    public Optional<Contact> findByPublicKey(String identityPubBase64) {
        return contacts.stream().filter(c -> c.identity_pub.equals(identityPubBase64)).findFirst();
    }

    public Optional<Contact> findByName(String name) {
        return contacts.stream().filter(c -> c.name.equalsIgnoreCase(name)).findFirst();
    }

    // swaps in a new public key during key migration
    public void updatePublicKey(String oldPubBase64, String newPubBase64) throws IOException {
        for (Contact c : contacts) {
            if (c.identity_pub.equals(oldPubBase64)) {
                c.identity_pub = newPubBase64;
                byte[] pubBytes = Base64.getDecoder().decode(newPubBase64);
                c.fingerprint = Identity.fingerprint(pubBytes);
                c.trusted_at = Instant.now().toString();
                break;
            }
        }
        save();
    }

    public List<Contact> getAllContacts() {
        return Collections.unmodifiableList(contacts);
    }

    public void removeContact(String identityPubBase64) throws IOException {
        contacts.removeIf(c -> c.identity_pub.equals(identityPubBase64));
        save();
    }

    private void save() throws IOException {
        Files.createDirectories(filePath.getParent());
        Files.writeString(filePath, GSON.toJson(contacts), StandardCharsets.UTF_8);
    }
}
