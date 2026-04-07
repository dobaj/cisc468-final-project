package com.p2pfs.sharing;

import com.p2pfs.crypto.FileHash;
import com.p2pfs.protocol.Messages;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

// tracks shared files, computes hashes, and builds file list responses
public class FileManager {

    private final Path sharedDir;
    private final String localIdentityPubBase64;
    private final List<Messages.FileEntry> receivedFiles = new ArrayList<>();

    public FileManager(Path sharedDir, String localIdentityPubBase64) throws IOException {
        this.sharedDir = sharedDir;
        this.localIdentityPubBase64 = localIdentityPubBase64;
        Files.createDirectories(sharedDir);
    }

    public List<Messages.FileEntry> getFileList() throws IOException {
        List<Messages.FileEntry> entries = new ArrayList<>();

        try (var stream = Files.list(sharedDir)) {
            stream.filter(Files::isRegularFile).forEach(path -> {
                try {
                    String hash = FileHash.hashFile(path);
                    long size = Files.size(path);
                    entries.add(new Messages.FileEntry(
                            path.getFileName().toString(), size, hash, localIdentityPubBase64));
                } catch (IOException e) {
                    System.err.println("Error hashing file " + path + ": " + e.getMessage());
                }
            });
        }

        entries.addAll(receivedFiles); // include files received from peers (origin preserved)

        return Collections.unmodifiableList(entries);
    }

    public void addReceivedFile(String name, long size, String hash, String originPubBase64) {
        receivedFiles.add(new Messages.FileEntry(name, size, hash, originPubBase64));
    }

    // native protocol requests use filename only (no hash upfront)
    public Optional<Path> getFileByName(String filename) {
        Path candidate = sharedDir.resolve(filename);
        return Files.isRegularFile(candidate) ? Optional.of(candidate) : Optional.empty();
    }

    public Optional<Path> getFileByHash(String hash) throws IOException {
        try (var stream = Files.list(sharedDir)) {
            return stream.filter(Files::isRegularFile).filter(p -> {
                try {
                    return FileHash.hashFile(p).equals(hash);
                } catch (IOException e) {
                    return false;
                }
            }).findFirst();
        }
    }

    public Path saveFile(String name, byte[] data) throws IOException {
        Path target = sharedDir.resolve(name);
        int count = 1; // append _N suffix if a file with this name already exists
        while (Files.exists(target)) {
            String baseName = name.contains(".")
                    ? name.substring(0, name.lastIndexOf('.'))
                    : name;
            String ext = name.contains(".")
                    ? name.substring(name.lastIndexOf('.'))
                    : "";
            target = sharedDir.resolve(baseName + "_" + count + ext);
            count++;
        }
        Files.write(target, data);
        return target;
    }

    public Path getSharedDir() {
        return sharedDir;
    }
}
