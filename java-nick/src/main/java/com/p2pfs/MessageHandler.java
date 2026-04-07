package com.p2pfs;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.p2pfs.crypto.*;
import com.p2pfs.net.PeerSession;
import com.p2pfs.protocol.*;
import com.p2pfs.sharing.*;
import com.p2pfs.storage.EncryptedFileStore;
import com.p2pfs.trust.*;

import java.io.*;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.util.*;

// per-session message loop and file transfer helpers; used for both incoming and outgoing sessions
class MessageHandler {

    private Identity identity;
    private final String localPeerName;
    private final FileManager fileManager;
    private final FileListCache fileListCache;
    private final ConsentManager consentManager;
    private final EncryptedFileStore encryptedStore;
    private final Map<String, PeerSession> activeSessions;
    private final TrustStore trustStore;

    private static final HexFormat HEX = HexFormat.of();
    private static final com.google.gson.Gson RECORD_GSON =
            new GsonBuilder().disableHtmlEscaping().create();

    MessageHandler(Identity identity, String localPeerName,
                   FileManager fileManager, FileListCache fileListCache,
                   ConsentManager consentManager, EncryptedFileStore encryptedStore,
                   Map<String, PeerSession> activeSessions, TrustStore trustStore) {
        this.identity       = identity;
        this.localPeerName  = localPeerName;
        this.fileManager    = fileManager;
        this.fileListCache  = fileListCache;
        this.consentManager = consentManager;
        this.encryptedStore = encryptedStore;
        this.activeSessions = activeSessions;
        this.trustStore     = trustStore;
    }

    void setIdentity(Identity identity) { this.identity = identity; }

    // --- Main dispatch loop ---

    void dispatch(PeerSession session, String peerName) {
        try {
            while (!session.getSocket().isClosed()) {
                String json    = session.receiveEncryptedDirect();
                String rawType = PeerSession.rawType(json);

                if ("FILE_LIST_REQUEST".equals(rawType) || "file_list_request".equals(rawType)) {
                    if (session.isNativeProtocol()) {
                        sendNativeFileListResponse(session);
                    } else {
                        Messages.FileListResponse resp = new Messages.FileListResponse();
                        resp.files = fileManager.getFileList();
                        session.sendEncrypted(Messages.serialize(resp));
                    }
                    continue;
                }
                if ("FILE_REQUEST".equals(rawType) || "file_request".equals(rawType)) {
                    handleIncomingFileRequest(session, peerName, json, rawType);
                    continue;
                }
                if ("FILE_OFFER".equals(rawType) || "file_offer".equals(rawType)) {
                    handleIncomingFileOffer(session, peerName, json, rawType);
                    continue;
                }
                if ("KEY_MIGRATION".equals(rawType) || "key_migration".equals(rawType)) {
                    handleIncomingKeyMigration(session, peerName, json, rawType);
                    continue;
                }
                // not a request, forward to the command queue so receiveEncrypted() can pick it up
                try {
                    session.enqueueReceived(json);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        } catch (IOException e) {
            if (!session.getSocket().isClosed()) {
                System.err.println("[!] Connection lost with '" + peerName + "': " + e.getMessage());
            }
            activeSessions.remove(peerName);
        }
    }

    // --- Incoming handlers ---

    void sendNativeFileListResponse(PeerSession session) throws IOException {
        Messages.NativeFileListResponse resp = new Messages.NativeFileListResponse();
        resp.files = new ArrayList<>();
        for (Messages.FileEntry e : fileManager.getFileList()) {
            Messages.NativeFileRecord r = new Messages.NativeFileRecord();
            r.filename  = e.name;
            r.sha256    = e.hash;
            r.size      = (int) e.size;
            r.owner     = localPeerName;
            r.owner_pub = HEX.formatHex(identity.getPublicKeyBytes());
            r.signature = HEX.formatHex(identity.sign(nativeFileRecordPayload(r)));
            resp.files.add(r);
        }
        session.sendEncrypted(Messages.serialize(resp));
    }

    private void handleIncomingFileRequest(PeerSession session, String peerName,
                                            String json, String rawType) throws IOException {
        String filename;
        String requestedHash = null;
        if ("file_request".equals(rawType)) {
            filename = Messages.deserialize(json, Messages.NativeFileRequest.class).filename;
        } else {
            Messages.FileRequest req = Messages.deserialize(json, Messages.FileRequest.class);
            filename = req.name;
            requestedHash = req.hash;
        }

        boolean accepted = consentManager.promptFileRequest(peerName, filename, requestedHash);

        if ("file_request".equals(rawType)) {
            if (!accepted) {
                session.sendEncrypted(Messages.serialize(
                        new Messages.NativeError("File request rejected for " + filename)));
                return;
            }
            Optional<Path> file = fileManager.getFileByName(filename);
            if (file.isEmpty()) {
                session.sendEncrypted(Messages.serialize(
                        new Messages.NativeError("File not found: " + filename)));
                return;
            }
            sendNativeFileChunk(session, file.get(), FileHash.hashFile(file.get()));
        } else {
            if (accepted) {
                Messages.FileAccept accept = new Messages.FileAccept();
                accept.hash = requestedHash;
                session.sendEncrypted(Messages.serialize(accept));
                Optional<Path> file = fileManager.getFileByHash(requestedHash);
                if (file.isPresent()) {
                    sendFileData(session, file.get(), requestedHash);
                } else {
                    session.sendEncrypted(Messages.serialize(
                            new Messages.Error("FILE_NOT_FOUND", "File not available")));
                }
            } else {
                session.sendEncrypted(Messages.serialize(
                        new Messages.FileDeny(requestedHash, "Request denied")));
            }
        }
    }

    private void handleIncomingFileOffer(PeerSession session, String peerName,
                                          String json, String rawType) throws IOException {
        String filename;
        long size = 0;
        String hash = null;

        if ("file_offer".equals(rawType)) {
            Messages.NativeFileOffer offer = Messages.deserialize(json, Messages.NativeFileOffer.class);
            filename = offer.filename;
            if (offer.record != null) { size = offer.record.size; hash = offer.record.sha256; }
        } else {
            Messages.FileOffer offer = Messages.deserialize(json, Messages.FileOffer.class);
            filename = offer.name; size = offer.size; hash = offer.hash;
        }

        boolean accepted = consentManager.promptFileOffer(peerName, filename, size, hash);

        if ("file_offer".equals(rawType)) {
            Messages.NativeFileOfferResponse resp = new Messages.NativeFileOfferResponse();
            resp.filename = filename;
            resp.accepted = accepted;
            if (!accepted) resp.message = "Receiver rejected file offer";
            session.sendEncrypted(Messages.serialize(resp));
            if (accepted) {
                // dispatch() owns the socket, so read directly rather than via the queue
                String chunkJson = session.receiveEncryptedDirect();
                if ("file_chunk".equals(PeerSession.rawType(chunkJson))) {
                    receiveNativeFileChunk(session, chunkJson);
                }
            }
        } else {
            if (accepted) {
                Messages.FileOfferAccept accept = new Messages.FileOfferAccept();
                accept.hash = hash;
                session.sendEncrypted(Messages.serialize(accept));
                receiveFileData(session, hash, filename, session.getRemoteIdentityPubBase64(), true);
            } else {
                Messages.FileOfferDeny deny = new Messages.FileOfferDeny();
                deny.hash = hash;
                session.sendEncrypted(Messages.serialize(deny));
            }
        }
    }

    private void handleIncomingKeyMigration(PeerSession session, String peerName,
                                             String json, String rawType) {
        try {
            boolean verified;
            String newIdentityPubBase64;

            if ("key_migration".equals(rawType)) {
                Messages.NativeKeyMigration m = Messages.deserialize(json, Messages.NativeKeyMigration.class);
                byte[] newPubBytes = HEX.parseHex(m.new_pub);
                newIdentityPubBase64 = Base64.getEncoder().encodeToString(newPubBytes);
                verified = KeyMigration.verify(
                        Messages.deserialize(buildJavaStyleMigration(m), Messages.KeyMigration.class),
                        session.getRemoteIdentityPubBase64());
            } else {
                Messages.KeyMigration m = Messages.deserialize(json, Messages.KeyMigration.class);
                verified = KeyMigration.verify(m, session.getRemoteIdentityPubBase64());
                newIdentityPubBase64 = m.new_identity_pub;
            }

            if (verified) {
                KeyMigration.applyMigration(trustStore, session.getRemoteIdentityPubBase64(), newIdentityPubBase64);
                System.out.println("[+] Key migration accepted for '" + peerName + "'");
            } else {
                System.out.println("[!] Key migration REJECTED for '" + peerName + "'");
            }
        } catch (Exception e) {
            System.err.println("[!] Key migration error: " + e.getMessage());
        }
    }

    private static String buildJavaStyleMigration(Messages.NativeKeyMigration m) {
        String b64New  = Base64.getEncoder().encodeToString(HEX.parseHex(m.new_pub));
        String b64Old  = Base64.getEncoder().encodeToString(HEX.parseHex(m.old_sig));
        String b64New2 = Base64.getEncoder().encodeToString(HEX.parseHex(m.new_sig));
        return "{\"type\":\"KEY_MIGRATION\",\"new_identity_pub\":\"" + b64New +
               "\",\"signature_old\":\"" + b64Old + "\",\"signature_new\":\"" + b64New2 + "\"}";
    }

    // --- File send helpers ---

    void sendNativeFileChunk(PeerSession session, Path path, String hash) throws IOException {
        byte[] fileBytes = Files.readAllBytes(path);

        Messages.NativeFileRecord record = new Messages.NativeFileRecord();
        record.filename  = path.getFileName().toString();
        record.sha256    = hash;
        record.size      = fileBytes.length;
        record.owner     = localPeerName;
        record.owner_pub = HEX.formatHex(identity.getPublicKeyBytes());
        record.signature = HEX.formatHex(identity.sign(nativeFileRecordPayload(record)));

        Messages.NativeFileChunk chunk = new Messages.NativeFileChunk();
        chunk.filename = record.filename;
        chunk.data     = HEX.formatHex(fileBytes);
        chunk.record   = record;
        chunk.done     = true;
        session.sendEncrypted(Messages.serialize(chunk));
    }

    void sendFileData(PeerSession session, Path path, String hash) throws IOException {
        byte[] fileBytes   = Files.readAllBytes(path);
        int chunkSize      = ProtocolConstants.MAX_CHUNK_BYTES;
        int totalChunks    = Math.max(1, (int) Math.ceil((double) fileBytes.length / chunkSize));

        for (int i = 0; i < totalChunks; i++) {
            int offset = i * chunkSize;
            Messages.FileTransfer data = new Messages.FileTransfer();
            data.hash         = hash;
            data.chunk_index  = i;
            data.total_chunks = totalChunks;
            data.data         = Base64.getEncoder().encodeToString(
                    Arrays.copyOfRange(fileBytes, offset, Math.min(offset + chunkSize, fileBytes.length)));
            session.sendEncrypted(Messages.serialize(data));
        }
        session.sendEncrypted(Messages.serialize(new Messages.FileComplete(hash)));
    }

    // --- File receive helpers ---

    void receiveNativeFileChunk(PeerSession session, String chunkJson) throws IOException {
        Messages.NativeFileChunk chunk = Messages.deserialize(chunkJson, Messages.NativeFileChunk.class);
        byte[] fileBytes  = HEX.parseHex(chunk.data);
        String actualHash = FileHash.hashBytes(fileBytes);

        String expectedHash = chunk.record != null ? chunk.record.sha256 : null;
        if (expectedHash != null && !actualHash.equals(expectedHash)) {
            System.out.println("[!] Hash mismatch - file discarded.");
            return;
        }
        System.out.println("[+] Hash verified: " + truncHash(actualHash));

        if (chunk.record != null
                && chunk.record.owner_pub != null && !chunk.record.owner_pub.isEmpty()
                && chunk.record.signature != null && !chunk.record.signature.isEmpty()) {
            byte[] ownerPub = HEX.parseHex(chunk.record.owner_pub);
            byte[] sig      = HEX.parseHex(chunk.record.signature);
            if (!Identity.verify(ownerPub, nativeFileRecordPayload(chunk.record), sig)) {
                System.out.println("[!] Signature invalid - file discarded.");
                return;
            }
            System.out.println("[+] Signature verified: " + truncHash(chunk.record.owner_pub));
        }

        String originPub = (chunk.record != null && chunk.record.owner_pub != null)
                ? Base64.getEncoder().encodeToString(HEX.parseHex(chunk.record.owner_pub))
                : session.getRemoteIdentityPubBase64();

        Path saved = fileManager.saveFile(chunk.filename, fileBytes);
        fileManager.addReceivedFile(chunk.filename, fileBytes.length, actualHash, originPub);
        System.out.println("[+] Saved to " + saved);
        try {
            encryptedStore.storeFile(chunk.filename, actualHash, originPub, fileBytes);
        } catch (GeneralSecurityException e) {
            System.err.println("[!] Failed to store encrypted copy: " + e.getMessage());
        }
    }

    void receiveFileData(PeerSession session, String expectedHash,
                         String fileName, String origin) throws IOException {
        receiveFileData(session, expectedHash, fileName, origin, false);
    }

    void receiveFileData(PeerSession session, String expectedHash,
                         String fileName, String origin, boolean direct) throws IOException {
        System.out.println("[*] Receiving '" + fileName + "'...");
        Map<Integer, byte[]> chunks = new TreeMap<>();
        int totalChunks = -1;

        while (true) {
            String dataJson = direct ? session.receiveEncryptedDirect() : session.receiveEncrypted();
            MessageType type = Messages.typeOf(dataJson);
            if (type == MessageType.ERROR) {
                System.out.println("[!] Transfer error: " +
                        Messages.deserialize(dataJson, Messages.Error.class).message);
                return;
            }
            if (type == MessageType.FILE_COMPLETE) break;
            Messages.FileTransfer data = Messages.deserialize(dataJson, Messages.FileTransfer.class);
            totalChunks = data.total_chunks;
            chunks.put(data.chunk_index, Base64.getDecoder().decode(data.data));
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (int i = 0; i < totalChunks; i++) {
            byte[] c = chunks.get(i);
            if (c == null) { System.out.println("[!] Missing chunk " + i + "."); return; }
            bos.write(c);
        }
        byte[] fileBytes  = bos.toByteArray();
        String actualHash = FileHash.hashBytes(fileBytes);

        if (!actualHash.equals(expectedHash)) {
            System.out.println("[!] Hash mismatch - file discarded.");
            return;
        }
        System.out.println("[+] Hash verified: " + truncHash(actualHash));

        Path saved = fileManager.saveFile(fileName, fileBytes);
        fileManager.addReceivedFile(fileName, fileBytes.length, actualHash, origin);
        System.out.println("[+] Saved to " + saved);
        try {
            encryptedStore.storeFile(fileName, actualHash, origin, fileBytes);
        } catch (GeneralSecurityException e) {
            System.err.println("[!] Failed to store encrypted copy: " + e.getMessage());
        }
    }

    // --- Utilities ---

    // sorted keys match Python's json.dumps(sort_keys=True) for signature compatibility
    static byte[] nativeFileRecordPayload(Messages.NativeFileRecord r) {
        TreeMap<String, Object> m = new TreeMap<>();
        m.put("filename", r.filename);
        m.put("owner",    r.owner);
        m.put("sha256",   r.sha256);
        m.put("size",     r.size);
        return RECORD_GSON.toJson(m).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    static String truncHash(String hash) {
        return hash != null && hash.length() > 16 ? hash.substring(0, 16) + "..." : hash;
    }
}
