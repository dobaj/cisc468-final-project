package com.p2pfs.storage;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.p2pfs.protocol.ProtocolConstants;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.*;

// AES-256-GCM file storage; key from PBKDF2; each file is [12-byte IV][ciphertext+tag]; index is also encrypted
public class EncryptedFileStore {

    private static final int GCM_TAG_BITS = 128;
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final String CIPHER_ALG = "AES/GCM/NoPadding";
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private final Path storeDir;
    private final SecretKeySpec storageKey;
    private final SecureRandom random = new SecureRandom();

    public static class FileMetadata {
        public String hash;
        public String name;
        public String origin;
        public String encrypted_path;
        public String stored_at;
    }

    public EncryptedFileStore(Path storeDir, String passphrase) throws IOException, GeneralSecurityException {
        this.storeDir = storeDir;
        Files.createDirectories(storeDir);

        Path saltFile = storeDir.resolve(".salt");
        byte[] salt;
        if (Files.exists(saltFile)) {
            salt = Files.readAllBytes(saltFile);
        } else {
            salt = new byte[SALT_BYTES];
            random.nextBytes(salt);
            Files.write(saltFile, salt);
        }

        PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        spec.clearPassword();
        this.storageKey = new SecretKeySpec(keyBytes, "AES");
    }

    public String storeFile(String name, String hash, String origin, byte[] plaintext) throws IOException, GeneralSecurityException {
        byte[] iv = new byte[ProtocolConstants.GCM_IV_BYTES];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_ALG);
        cipher.init(Cipher.ENCRYPT_MODE, storageKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        String encFilename = UUID.randomUUID().toString() + ".enc";
        Path encPath = storeDir.resolve(encFilename);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(iv);
        out.write(ciphertext);
        Files.write(encPath, out.toByteArray());

        List<FileMetadata> index = loadIndex();
        index.removeIf(m -> m.hash.equals(hash));
        FileMetadata meta = new FileMetadata();
        meta.hash = hash;
        meta.name = name;
        meta.origin = origin;
        meta.encrypted_path = encFilename;
        meta.stored_at = java.time.Instant.now().toString();
        index.add(meta);
        saveIndex(index);

        return encFilename;
    }

    public Optional<byte[]> retrieveFile(String hash) throws IOException, GeneralSecurityException {
        List<FileMetadata> index = loadIndex();
        Optional<FileMetadata> meta = index.stream().filter(m -> m.hash.equals(hash)).findFirst();
        if (meta.isEmpty()) return Optional.empty();

        Path encPath = storeDir.resolve(meta.get().encrypted_path);
        if (!Files.exists(encPath)) return Optional.empty();

        byte[] raw = Files.readAllBytes(encPath);
        byte[] iv = Arrays.copyOfRange(raw, 0, ProtocolConstants.GCM_IV_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(raw, ProtocolConstants.GCM_IV_BYTES, raw.length);

        Cipher cipher = Cipher.getInstance(CIPHER_ALG);
        cipher.init(Cipher.DECRYPT_MODE, storageKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return Optional.of(cipher.doFinal(ciphertext));
    }

    public List<FileMetadata> listFiles() throws IOException, GeneralSecurityException {
        return loadIndex();
    }

    private List<FileMetadata> loadIndex() throws IOException, GeneralSecurityException {
        Path indexPath = storeDir.resolve(".index.enc");
        if (!Files.exists(indexPath)) return new ArrayList<>();

        byte[] raw = Files.readAllBytes(indexPath);
        if (raw.length < ProtocolConstants.GCM_IV_BYTES) return new ArrayList<>();

        byte[] iv = Arrays.copyOfRange(raw, 0, ProtocolConstants.GCM_IV_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(raw, ProtocolConstants.GCM_IV_BYTES, raw.length);

        Cipher cipher = Cipher.getInstance(CIPHER_ALG);
        cipher.init(Cipher.DECRYPT_MODE, storageKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] plaintext = cipher.doFinal(ciphertext);

        String json = new String(plaintext, StandardCharsets.UTF_8);
        Type listType = new TypeToken<List<FileMetadata>>() {}.getType();
        List<FileMetadata> result = GSON.fromJson(json, listType);
        return result != null ? new ArrayList<>(result) : new ArrayList<>();
    }

    private void saveIndex(List<FileMetadata> index) throws IOException, GeneralSecurityException {
        String json = GSON.toJson(index);
        byte[] plaintext = json.getBytes(StandardCharsets.UTF_8);

        byte[] iv = new byte[ProtocolConstants.GCM_IV_BYTES];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_ALG);
        cipher.init(Cipher.ENCRYPT_MODE, storageKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(iv);
        out.write(ciphertext);
        Files.write(storeDir.resolve(".index.enc"), out.toByteArray());
    }
}
