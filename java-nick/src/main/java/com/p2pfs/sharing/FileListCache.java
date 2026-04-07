package com.p2pfs.sharing;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.p2pfs.protocol.Messages;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Caches file lists received from remote peers.
 * Enables offline peer lookup for requirement #5: when a peer is offline,
 * their cached file list lets us find files from third-party peers and
 * verify hashes against the original owner's advertised values.
 */
public class FileListCache {

    public static class CachedFileList {
        public String peer_identity;
        public String peer_name;
        public List<Messages.FileEntry> files;
        public String cached_at;
    }

    private final Path cacheDir;
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    public FileListCache(Path cacheDir) throws IOException {
        this.cacheDir = cacheDir;
        Files.createDirectories(cacheDir);
    }

    /**
     * Saves a peer's file list to the cache.
     */
    public void cache(String peerIdentityPubBase64, String peerName, List<Messages.FileEntry> files) throws IOException {
        CachedFileList entry = new CachedFileList();
        entry.peer_identity = peerIdentityPubBase64;
        entry.peer_name = peerName;
        entry.files = files;
        entry.cached_at = Instant.now().toString();

        String filename = safeFilename(peerIdentityPubBase64) + ".json";
        Files.writeString(cacheDir.resolve(filename), GSON.toJson(entry), StandardCharsets.UTF_8);
    }

    /**
     * Loads a cached file list for a given peer identity.
     */
    public Optional<CachedFileList> load(String peerIdentityPubBase64) {
        String filename = safeFilename(peerIdentityPubBase64) + ".json";
        Path file = cacheDir.resolve(filename);
        if (!Files.exists(file)) return Optional.empty();
        try {
            String json = Files.readString(file, StandardCharsets.UTF_8);
            return Optional.of(GSON.fromJson(json, CachedFileList.class));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /**
     * Loads all cached file lists.
     */
    public List<CachedFileList> loadAll() {
        List<CachedFileList> result = new ArrayList<>();
        try (var stream = Files.list(cacheDir)) {
            stream.filter(p -> p.toString().endsWith(".json")).forEach(p -> {
                try {
                    String json = Files.readString(p, StandardCharsets.UTF_8);
                    result.add(GSON.fromJson(json, CachedFileList.class));
                } catch (IOException ignored) {}
            });
        } catch (IOException ignored) {}
        return result;
    }

    /**
     * Finds which cached peers have a file with the given hash and origin.
     */
    public List<CachedFileList> findPeersWithFile(String hash, String originPubBase64) {
        List<CachedFileList> matches = new ArrayList<>();
        for (CachedFileList cached : loadAll()) {
            for (Messages.FileEntry f : cached.files) {
                if (f.hash.equals(hash) && f.origin.equals(originPubBase64)) {
                    matches.add(cached);
                    break;
                }
            }
        }
        return matches;
    }

    private static String safeFilename(String base64) {
        return base64.replaceAll("[^a-zA-Z0-9]", "_");
    }
}
