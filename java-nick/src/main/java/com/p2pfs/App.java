package com.p2pfs;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.p2pfs.crypto.*;
import com.p2pfs.discovery.MdnsService;
import com.p2pfs.net.*;
import com.p2pfs.protocol.*;
import com.p2pfs.sharing.*;
import com.p2pfs.storage.EncryptedFileStore;
import com.p2pfs.trust.*;

import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicReference;

public class App implements InputProvider {

    private Identity identity;
    private TrustStore trustStore;
    private FileManager fileManager;
    private FileListCache fileListCache;
    private EncryptedFileStore encryptedStore;
    private ConsentManager consentManager;
    private MdnsService mdnsService;
    private TcpServer tcpServer;
    private String peerName; // local peer's display name (needed for native hello)

    // Commands go here (read by the command loop)
    private final BlockingQueue<String> commandQueue = new LinkedBlockingQueue<>();
    // When a consent/trust prompt is active, its dedicated response queue is registered here.
    private final AtomicReference<BlockingQueue<String>> promptReceiver = new AtomicReference<>(null);
    private final Map<String, PeerSession> activeSessions = new ConcurrentHashMap<>();
    private Path dataDir;

    private static final HexFormat HEX = HexFormat.of();

    @Override
    public String readLine() {
        BlockingQueue<String> q = new LinkedBlockingQueue<>();
        promptReceiver.set(q);
        try {
            return q.take();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "";
        } finally {
            promptReceiver.compareAndSet(q, null);
        }
    }

    public static void main(String[] args) {
        new App().run();
    }

    private void run() {
        Scanner stdinScanner = new Scanner(System.in);
        Thread stdinThread = new Thread(() -> {
            while (stdinScanner.hasNextLine()) {
                String line = stdinScanner.nextLine();
                BlockingQueue<String> pr = promptReceiver.get();
                if (pr != null) {
                    pr.offer(line);
                } else {
                    commandQueue.offer(line);
                }
            }
        });
        stdinThread.setDaemon(true);
        stdinThread.start();

        try {
            System.out.println("=== P2P Secure File Sharing ===\n");

            System.out.print("Enter your peer name: ");
            peerName = commandQueue.take().trim();
            if (peerName.isEmpty()) peerName = "java-peer";

            System.out.print("Enter storage passphrase: ");
            String passphrase = commandQueue.take().trim();
            if (passphrase.isEmpty()) {
                System.err.println("[!] Passphrase cannot be empty.");
                return;
            }

            dataDir = Path.of("data", peerName);
            Files.createDirectories(dataDir);

            identity = Identity.loadOrGenerate(dataDir);
            System.out.println("[+] Identity fingerprint: " + Identity.formatFingerprint(identity.getFingerprint()));

            trustStore = new TrustStore(dataDir.resolve("truststore.json"));
            fileManager = new FileManager(dataDir.resolve("shared"), identity.getPublicKeyBase64());
            fileListCache = new FileListCache(dataDir.resolve("cache"));
            encryptedStore = new EncryptedFileStore(dataDir.resolve("store"), passphrase);
            consentManager = new ConsentManager((InputProvider) this);

            try {
                tcpServer = new TcpServer(ProtocolConstants.DEFAULT_PORT);
            } catch (java.net.BindException e) {
                tcpServer = new TcpServer(0);
            }
            int port = tcpServer.getPort();
            System.out.println("[+] Listening on port " + port);

            tcpServer.acceptAsync(this::handleIncomingConnection);

            mdnsService = new MdnsService();
            mdnsService.setPeerListener(new MdnsService.PeerListener() {
                @Override
                public void onPeerDiscovered(MdnsService.PeerInfo peer) {
                    String proto = peer.isJavaPeer() ? "java" : "native";
                    System.out.printf("[*] Discovered peer: %s at %s:%d [%s] (fp: %s)%n",
                            peer.name(), peer.host(), peer.port(), proto,
                            peer.fingerprint().length() > 16 ? peer.fingerprint().substring(0, 16) + "..." : peer.fingerprint());
                }

                @Override
                public void onPeerRemoved(String name) {
                    System.out.println("[*] Peer departed: " + name);
                    activeSessions.remove(name);
                }
            });
            mdnsService.start(peerName, port, identity.getFingerprint());
            System.out.println("[+] mDNS registered as '" + peerName + "'");

            commandLoop();
        } catch (Exception e) {
            System.err.println("[!] Fatal error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            cleanup();
        }
    }

    private void commandLoop() {
        System.out.println("\nCommands: peers, connect <name>, list <name>, request <name> <file>,");
        System.out.println("          send <name> <file>, migrate, contacts, help, exit\n");

        while (true) {
            System.out.print("> ");
            System.out.flush();
            String line;
            try {
                line = commandQueue.take().trim();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            if (line.isEmpty()) continue;

            String[] cmdRest = line.split("\\s+", 2);
            String cmd = cmdRest[0].toLowerCase();
            String rest = cmdRest.length > 1 ? cmdRest[1].trim() : "";

            try {
                switch (cmd) {
                    case "peers" -> listPeers();
                    case "connect" -> {
                        if (rest.isEmpty()) { System.out.println("Usage: connect <name>"); break; }
                        connectToPeer(rest);
                    }
                    case "list" -> {
                        if (rest.isEmpty()) { System.out.println("Usage: list <name>"); break; }
                        requestFileList(rest);
                    }
                    case "request" -> {
                        int lastSpace = rest.lastIndexOf(' ');
                        if (lastSpace < 0) { System.out.println("Usage: request <name> <filename>"); break; }
                        requestFile(rest.substring(0, lastSpace).trim(), rest.substring(lastSpace + 1).trim());
                    }
                    case "send" -> {
                        int lastSpace = rest.lastIndexOf(' ');
                        if (lastSpace < 0) { System.out.println("Usage: send <name> <filepath>"); break; }
                        sendFile(rest.substring(0, lastSpace).trim(), rest.substring(lastSpace + 1).trim());
                    }
                    case "migrate" -> migrateKey();
                    case "contacts" -> showContacts();
                    case "stored" -> showStoredFiles();
                    case "help" -> printHelp();
                    case "exit", "quit" -> { System.out.println("Goodbye."); return; }
                    default -> System.out.println("Unknown command. Type 'help' for usage.");
                }
            } catch (Exception e) {
                System.err.println("[!] Error: " + e.getMessage());
            }
        }
    }

    private void listPeers() {
        var peers = mdnsService.getDiscoveredPeers();
        if (peers.isEmpty()) {
            System.out.println("No peers discovered.");
            return;
        }
        System.out.println("Discovered peers:");
        for (var entry : peers.entrySet()) {
            var p = entry.getValue();
            System.out.printf("  %-20s %s:%d [%s]%n", p.name(), p.host(), p.port(),
                    p.isJavaPeer() ? "java" : "native");
        }
    }

    private void connectToPeer(String name) throws IOException {
        var peers = mdnsService.getDiscoveredPeers();
        var peerInfo = peers.get(name);
        if (peerInfo == null) {
            System.out.println("[!] Peer '" + name + "' not found. Run 'peers' to see available peers.");
            return;
        }
        Socket sock = TcpClient.connect(peerInfo.host(), peerInfo.port());
        PeerSession session = new PeerSession(sock, identity, trustStore, this);

        if (peerInfo.isJavaPeer()) {
            session.handshakeAsInitiator();
        } else {
            session.handshakeNativeAsInitiator(peerName);
        }

        activeSessions.put(name, session);
        System.out.println("[+] Connected and authenticated with '" + name + "' [" +
                (session.isNativeProtocol() ? "native" : "java") + "]");
    }

    private PeerSession getSession(String name) throws IOException {
        PeerSession session = activeSessions.get(name);
        if (session == null || session.getSocket().isClosed()) {
            activeSessions.remove(name);
            connectToPeer(name);
            session = activeSessions.get(name);
        }
        if (session == null) {
            throw new IOException("No active session with '" + name + "'");
        }
        return session;
    }

    // ── File list ────────────────────────────────────────────────────────────

    private void requestFileList(String name) throws IOException {
        PeerSession session = getSession(name);

        if (session.isNativeProtocol()) {
            session.sendEncrypted(Messages.serialize(new Messages.NativeFileListRequest()));
            String responseJson = session.receiveEncrypted();
            if (!"file_list_response".equals(PeerSession.rawType(responseJson))) {
                System.out.println("[!] Unexpected response: " + responseJson);
                return;
            }
            Messages.NativeFileListResponse response =
                    Messages.deserialize(responseJson, Messages.NativeFileListResponse.class);

            System.out.println("Files available from '" + name + "':");
            if (response.files == null || response.files.isEmpty()) {
                System.out.println("  (none)");
            } else {
                List<Messages.FileEntry> entries = new ArrayList<>();
                for (Messages.NativeFileRecord r : response.files) {
                    System.out.printf("  %-30s %8d bytes  hash:%s%n",
                            r.filename, r.size, truncHash(r.sha256));
                    entries.add(new Messages.FileEntry(r.filename, r.size, r.sha256,
                            r.owner_pub != null ? HEX.formatHex(HEX.parseHex(r.owner_pub)) : ""));
                }
                fileListCache.cache(session.getRemoteIdentityPubBase64(), name, entries);
            }
        } else {
            session.sendEncrypted(Messages.serialize(new Messages.FileListRequest()));
            String responseJson = session.receiveEncrypted();
            Messages.FileListResponse response =
                    Messages.deserialize(responseJson, Messages.FileListResponse.class);

            System.out.println("Files available from '" + name + "':");
            if (response.files == null || response.files.isEmpty()) {
                System.out.println("  (none)");
            } else {
                for (Messages.FileEntry f : response.files) {
                    System.out.printf("  %-30s %8d bytes  hash:%s%n", f.name, f.size, truncHash(f.hash));
                }
                fileListCache.cache(session.getRemoteIdentityPubBase64(), name, response.files);
            }
        }
    }

    // ── File request (pull) ──────────────────────────────────────────────────

    private void requestFile(String name, String fileName) throws IOException {
        PeerSession session;
        try {
            session = getSession(name);
        } catch (IOException e) {
            System.out.println("[*] Peer '" + name + "' is offline. Searching cached file lists...");
            requestFileFromThirdParty(name, fileName);
            return;
        }

        if (session.isNativeProtocol()) {
            // Native protocol: send file_request with filename only; peer responds with file_chunk or error
            Messages.NativeFileRequest req = new Messages.NativeFileRequest();
            req.filename = fileName;
            session.sendEncrypted(Messages.serialize(req));

            String respJson = session.receiveEncrypted();
            String respType = PeerSession.rawType(respJson);
            if ("error".equals(respType)) {
                JsonObject err = JsonParser.parseString(respJson).getAsJsonObject();
                System.out.println("[!] " + name + " rejected/error: " + err.get("message").getAsString());
                return;
            }
            if (!"file_chunk".equals(respType)) {
                System.out.println("[!] Unexpected response: " + respJson);
                return;
            }
            receiveNativeFileChunk(session, respJson);

        } else {
            // Java protocol: need hash upfront, explicit FILE_ACCEPT/DENY
            Messages.FileRequest req = new Messages.FileRequest();
            req.name = fileName;

            var cached = fileListCache.load(session.getRemoteIdentityPubBase64());
            String hash = null;
            if (cached.isPresent()) {
                hash = cached.get().files.stream()
                        .filter(f -> f.name.equals(fileName))
                        .map(f -> f.hash).findFirst().orElse(null);
            }
            if (hash == null) {
                session.sendEncrypted(Messages.serialize(new Messages.FileListRequest()));
                String listJson = session.receiveEncrypted();
                Messages.FileListResponse listResp =
                        Messages.deserialize(listJson, Messages.FileListResponse.class);
                if (listResp.files != null) {
                    fileListCache.cache(session.getRemoteIdentityPubBase64(), name, listResp.files);
                    hash = listResp.files.stream()
                            .filter(f -> f.name.equals(fileName))
                            .map(f -> f.hash).findFirst().orElse(null);
                }
            }
            if (hash == null) {
                System.out.println("[!] File '" + fileName + "' not found in " + name + "'s file list.");
                return;
            }

            req.hash = hash;
            session.sendEncrypted(Messages.serialize(req));

            String respJson = session.receiveEncrypted();
            if (Messages.typeOf(respJson) == MessageType.FILE_DENY) {
                System.out.println("[!] " + name + " rejected the file request.");
                return;
            }
            if (Messages.typeOf(respJson) != MessageType.FILE_ACCEPT) {
                System.out.println("[!] Unexpected response: " + respJson);
                return;
            }

            receiveFileData(session, hash, fileName, session.getRemoteIdentityPubBase64());
        }
    }

    private void requestFileFromThirdParty(String offlinePeerName, String fileName) throws IOException {
        var contact = trustStore.findByName(offlinePeerName);
        if (contact.isEmpty()) {
            System.out.println("[!] No trusted contact named '" + offlinePeerName + "'");
            return;
        }
        String originPub = contact.get().identity_pub;
        var cached = fileListCache.load(originPub);
        if (cached.isEmpty()) {
            System.out.println("[!] No cached file list from '" + offlinePeerName + "'");
            return;
        }

        String hash = cached.get().files.stream()
                .filter(f -> f.name.equals(fileName))
                .map(f -> f.hash).findFirst().orElse(null);
        if (hash == null) {
            System.out.println("[!] File '" + fileName + "' not in cached list from '" + offlinePeerName + "'");
            return;
        }

        for (var entry : activeSessions.entrySet()) {
            PeerSession session = entry.getValue();
            if (session.getSocket().isClosed()) continue;
            try {
                // Use the session's own protocol for querying
                List<Messages.FileEntry> remoteFiles = queryFileList(session, entry.getKey());
                if (remoteFiles == null) continue;

                final String finalHash = hash;
                boolean hasFile = remoteFiles.stream()
                        .anyMatch(f -> f.hash.equals(finalHash) && originPub.contains(f.origin != null ? f.origin : ""));
                if (!hasFile) {
                    // Looser check: just match by hash
                    hasFile = remoteFiles.stream().anyMatch(f -> f.hash.equals(finalHash));
                }
                if (hasFile) {
                    System.out.println("[*] Found file on peer '" + entry.getKey() + "', requesting...");
                    if (session.isNativeProtocol()) {
                        Messages.NativeFileRequest req = new Messages.NativeFileRequest();
                        req.filename = fileName;
                        session.sendEncrypted(Messages.serialize(req));
                        String respJson = session.receiveEncrypted();
                        if ("file_chunk".equals(PeerSession.rawType(respJson))) {
                            receiveNativeFileChunk(session, respJson);
                            return;
                        }
                    } else {
                        Messages.FileRequest req = new Messages.FileRequest();
                        req.hash = hash;
                        req.name = fileName;
                        session.sendEncrypted(Messages.serialize(req));
                        String respJson = session.receiveEncrypted();
                        if (Messages.typeOf(respJson) == MessageType.FILE_DENY) {
                            System.out.println("[!] " + entry.getKey() + " rejected the request.");
                            continue;
                        }
                        receiveFileData(session, hash, fileName, originPub);
                        return;
                    }
                }
            } catch (IOException e) {
                System.err.println("[!] Error querying " + entry.getKey() + ": " + e.getMessage());
            }
        }
        System.out.println("[!] Could not find '" + fileName + "' on any connected peer.");
    }

    /** Returns a unified file entry list from a peer using whichever protocol that session uses. */
    private List<Messages.FileEntry> queryFileList(PeerSession session, String peerName) throws IOException {
        if (session.isNativeProtocol()) {
            session.sendEncrypted(Messages.serialize(new Messages.NativeFileListRequest()));
            String listJson = session.receiveEncrypted();
            if (!"file_list_response".equals(PeerSession.rawType(listJson))) return null;
            Messages.NativeFileListResponse resp =
                    Messages.deserialize(listJson, Messages.NativeFileListResponse.class);
            if (resp.files == null) return List.of();
            List<Messages.FileEntry> entries = new ArrayList<>();
            for (Messages.NativeFileRecord r : resp.files) {
                entries.add(new Messages.FileEntry(r.filename, r.size, r.sha256,
                        r.owner_pub != null ? r.owner_pub : ""));
            }
            fileListCache.cache(session.getRemoteIdentityPubBase64(), peerName, entries);
            return entries;
        } else {
            session.sendEncrypted(Messages.serialize(new Messages.FileListRequest()));
            String listJson = session.receiveEncrypted();
            Messages.FileListResponse resp =
                    Messages.deserialize(listJson, Messages.FileListResponse.class);
            if (resp.files == null) return List.of();
            fileListCache.cache(session.getRemoteIdentityPubBase64(), peerName, resp.files);
            return resp.files;
        }
    }

    // ── File receive helpers ─────────────────────────────────────────────────

    /** Handles a native file_chunk message (already received, passed as JSON string). */
    private void receiveNativeFileChunk(PeerSession session, String chunkJson) throws IOException {
        Messages.NativeFileChunk chunk = Messages.deserialize(chunkJson, Messages.NativeFileChunk.class);
        byte[] fileBytes = HEX.parseHex(chunk.data);

        String expectedHash = chunk.record != null ? chunk.record.sha256 : null;
        String actualHash = FileHash.hashBytes(fileBytes);

        if (expectedHash != null && !actualHash.equals(expectedHash)) {
            System.out.println("[!] FILE TAMPERED! Expected hash " + truncHash(expectedHash) +
                    " but got " + truncHash(actualHash));
            System.out.println("[!] File discarded.");
            return;
        }
        System.out.println("[+] Hash verified: " + truncHash(actualHash));

        Path saved = fileManager.saveFile(chunk.filename, fileBytes);
        String originPub = (chunk.record != null && chunk.record.owner_pub != null)
                ? java.util.Base64.getEncoder().encodeToString(HEX.parseHex(chunk.record.owner_pub))
                : session.getRemoteIdentityPubBase64();
        fileManager.addReceivedFile(chunk.filename, fileBytes.length, actualHash, originPub);
        System.out.println("[+] Saved to " + saved);

        try {
            encryptedStore.storeFile(chunk.filename, actualHash, originPub, fileBytes);
        } catch (GeneralSecurityException e) {
            System.err.println("[!] Failed to store encrypted copy: " + e.getMessage());
        }
    }

    /** Handles Java-protocol chunked transfer (FILE_TRANSFER chunks + FILE_COMPLETE). */
    private void receiveFileData(PeerSession session, String expectedHash, String fileName, String origin) throws IOException {
        System.out.println("[*] Receiving '" + fileName + "'...");
        Map<Integer, byte[]> chunks = new TreeMap<>();
        int totalChunks = -1;

        while (true) {
            String dataJson = session.receiveEncrypted();
            MessageType type = Messages.typeOf(dataJson);
            if (type == MessageType.ERROR) {
                Messages.Error err = Messages.deserialize(dataJson, Messages.Error.class);
                System.out.println("[!] Transfer error: " + err.message);
                return;
            }
            if (type == MessageType.FILE_COMPLETE) {
                break;
            }
            Messages.FileTransfer data = Messages.deserialize(dataJson, Messages.FileTransfer.class);
            totalChunks = data.total_chunks;
            chunks.put(data.chunk_index, java.util.Base64.getDecoder().decode(data.data));
        }

        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < totalChunks; i++) {
            byte[] chunk = chunks.get(i);
            if (chunk == null) {
                System.out.println("[!] Missing chunk " + i + ", transfer incomplete.");
                return;
            }
            bos.write(chunk);
        }
        byte[] fileBytes = bos.toByteArray();

        String actualHash = FileHash.hashBytes(fileBytes);
        if (!actualHash.equals(expectedHash)) {
            System.out.println("[!] FILE TAMPERED! Expected hash " + truncHash(expectedHash) +
                    " but got " + truncHash(actualHash));
            System.out.println("[!] File discarded.");
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

    // ── File send (push) ─────────────────────────────────────────────────────

    private void sendFile(String name, String filePath) throws IOException {
        PeerSession session = getSession(name);
        Path path = Path.of(filePath);
        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            path = fileManager.getSharedDir().resolve(filePath);
        }
        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            System.out.println("[!] File not found: " + filePath);
            return;
        }
        String hash = FileHash.hashFile(path);
        long size = Files.size(path);

        if (session.isNativeProtocol()) {
            // Native protocol: FILE_OFFER with embedded record, then wait for file_offer_response
            Messages.NativeFileRecord record = new Messages.NativeFileRecord();
            record.filename  = path.getFileName().toString();
            record.sha256    = hash;
            record.size      = (int) size;
            record.owner     = peerName;
            record.owner_pub = HEX.formatHex(identity.getPublicKeyBytes());
            record.signature = "";

            Messages.NativeFileOffer offer = new Messages.NativeFileOffer();
            offer.filename = record.filename;
            offer.record   = record;
            session.sendEncrypted(Messages.serialize(offer));

            String respJson = session.receiveEncrypted();
            String respType = PeerSession.rawType(respJson);
            if ("file_offer_response".equals(respType)) {
                Messages.NativeFileOfferResponse resp =
                        Messages.deserialize(respJson, Messages.NativeFileOfferResponse.class);
                if (!resp.accepted) {
                    System.out.println("[!] " + name + " rejected the file.");
                    return;
                }
            } else if ("error".equals(respType)) {
                JsonObject err = JsonParser.parseString(respJson).getAsJsonObject();
                System.out.println("[!] " + name + " rejected the file: " + err.get("message").getAsString());
                return;
            } else {
                System.out.println("[!] Unexpected response to file offer: " + respJson);
                return;
            }

            sendNativeFileChunk(session, path, hash);
            System.out.println("[+] File sent successfully.");

        } else {
            // Java protocol: FILE_OFFER → FILE_OFFER_ACCEPT/DENY → FILE_TRANSFER chunks + FILE_COMPLETE
            Messages.FileOffer offer = new Messages.FileOffer();
            offer.name = path.getFileName().toString();
            offer.size = size;
            offer.hash = hash;
            session.sendEncrypted(Messages.serialize(offer));

            String respJson = session.receiveEncrypted();
            if (Messages.typeOf(respJson) == MessageType.FILE_OFFER_DENY) {
                System.out.println("[!] " + name + " rejected the file.");
                return;
            }
            if (Messages.typeOf(respJson) != MessageType.FILE_OFFER_ACCEPT) {
                System.out.println("[!] Unexpected response to file offer: " + respJson);
                return;
            }

            sendFileData(session, path, hash);
            System.out.println("[+] File sent successfully.");
        }
    }

    /** Send a file as a single native file_chunk (the Go/Python convention). */
    private void sendNativeFileChunk(PeerSession session, Path path, String hash) throws IOException {
        byte[] fileBytes = Files.readAllBytes(path);

        Messages.NativeFileRecord record = new Messages.NativeFileRecord();
        record.filename  = path.getFileName().toString();
        record.sha256    = hash;
        record.size      = fileBytes.length;
        record.owner     = peerName;
        record.owner_pub = HEX.formatHex(identity.getPublicKeyBytes());
        record.signature = "";

        Messages.NativeFileChunk chunk = new Messages.NativeFileChunk();
        chunk.filename = record.filename;
        chunk.data     = HEX.formatHex(fileBytes);
        chunk.record   = record;
        chunk.done     = true;
        session.sendEncrypted(Messages.serialize(chunk));
    }

    /** Send a file as Java-protocol chunked transfer (FILE_TRANSFER + FILE_COMPLETE). */
    private void sendFileData(PeerSession session, Path path, String hash) throws IOException {
        byte[] fileBytes = Files.readAllBytes(path);
        int chunkSize = ProtocolConstants.MAX_CHUNK_BYTES;
        int totalChunks = (int) Math.ceil((double) fileBytes.length / chunkSize);
        if (totalChunks == 0) totalChunks = 1;

        for (int i = 0; i < totalChunks; i++) {
            int offset = i * chunkSize;
            int len = Math.min(chunkSize, fileBytes.length - offset);
            byte[] chunk = Arrays.copyOfRange(fileBytes, offset, offset + len);

            Messages.FileTransfer data = new Messages.FileTransfer();
            data.hash        = hash;
            data.chunk_index = i;
            data.total_chunks = totalChunks;
            data.data        = java.util.Base64.getEncoder().encodeToString(chunk);
            session.sendEncrypted(Messages.serialize(data));
        }
        session.sendEncrypted(Messages.serialize(new Messages.FileComplete(hash)));
    }

    // ── Incoming connection handler ──────────────────────────────────────────

    private void handleIncomingConnection(Socket socket) {
        try {
            PeerSession session = new PeerSession(socket, identity, trustStore, this);
            // Auto-detect whether the connecting peer speaks Java or native protocol
            session.handshakeAutoDetect(peerName);
            String remoteName = session.getRemotePeerName();
            System.out.println("\n[+] Incoming connection from '" + remoteName + "' [" +
                    (session.isNativeProtocol() ? "native" : "java") + "] — ready to receive.");
            handlePeerMessages(session, remoteName);
        } catch (IOException e) {
            System.err.println("[!] Incoming connection failed: " + e.getMessage());
        }
    }

    // ── Peer message dispatch ────────────────────────────────────────────────

    private void handlePeerMessages(PeerSession session, String peerNameRemote) {
        try {
            while (!session.getSocket().isClosed()) {
                String json = session.receiveEncrypted();
                String rawType = PeerSession.rawType(json);

                // File list request (both protocols)
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

                // File request — pull (both protocols)
                if ("FILE_REQUEST".equals(rawType) || "file_request".equals(rawType)) {
                    handleIncomingFileRequest(session, peerNameRemote, json, rawType);
                    continue;
                }

                // File offer — push (both protocols)
                if ("FILE_OFFER".equals(rawType) || "file_offer".equals(rawType)) {
                    handleIncomingFileOffer(session, peerNameRemote, json, rawType);
                    continue;
                }

                // Java-only: consent responses from the remote side to OUR file request/offer
                if ("FILE_OFFER_ACCEPT".equals(rawType) || "FILE_OFFER_DENY".equals(rawType)) {
                    // handled inline in sendFile, shouldn't arrive here
                    System.out.println("[?] Unexpected " + rawType + " from " + peerNameRemote);
                    continue;
                }

                // Key migration (both protocols)
                if ("KEY_MIGRATION".equals(rawType) || "key_migration".equals(rawType)) {
                    handleIncomingKeyMigration(session, peerNameRemote, json, rawType);
                    continue;
                }

                // Errors (both protocols)
                if ("ERROR".equals(rawType) || "error".equals(rawType)) {
                    JsonObject err = JsonParser.parseString(json).getAsJsonObject();
                    String msg = err.has("message") ? err.get("message").getAsString()
                                : (err.has("code") ? err.get("code").getAsString() : json);
                    System.out.printf("[!] Error from '%s': %s%n", peerNameRemote, msg);
                    continue;
                }

                System.out.println("[?] Unexpected message type from " + peerNameRemote + ": " + rawType);
            }
        } catch (IOException e) {
            if (!session.getSocket().isClosed()) {
                System.err.println("[!] Connection lost with '" + peerNameRemote + "': " + e.getMessage());
            }
            activeSessions.remove(peerNameRemote);
        }
    }

    private void sendNativeFileListResponse(PeerSession session) throws IOException {
        List<Messages.FileEntry> javaEntries = fileManager.getFileList();
        Messages.NativeFileListResponse resp = new Messages.NativeFileListResponse();
        resp.files = new ArrayList<>();
        for (Messages.FileEntry e : javaEntries) {
            Messages.NativeFileRecord r = new Messages.NativeFileRecord();
            r.filename  = e.name;
            r.sha256    = e.hash;
            r.size      = (int) e.size;
            r.owner     = peerName;
            r.owner_pub = HEX.formatHex(identity.getPublicKeyBytes());
            r.signature = "";
            resp.files.add(r);
        }
        session.sendEncrypted(Messages.serialize(resp));
    }

    private void handleIncomingFileRequest(PeerSession session, String peerNameRemote,
                                            String json, String rawType) throws IOException {
        String filename;
        String requestedHash = null;
        if ("file_request".equals(rawType)) {
            Messages.NativeFileRequest req = Messages.deserialize(json, Messages.NativeFileRequest.class);
            filename = req.filename;
        } else {
            Messages.FileRequest req = Messages.deserialize(json, Messages.FileRequest.class);
            filename = req.name;
            requestedHash = req.hash;
        }

        boolean accepted = consentManager.promptFileRequest(peerNameRemote, filename, requestedHash);

        if ("file_request".equals(rawType)) {
            // Native: send file_chunk on accept, error on deny
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
            // Java: send FILE_ACCEPT then chunks, or FILE_DENY
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

    private void handleIncomingFileOffer(PeerSession session, String peerNameRemote,
                                          String json, String rawType) throws IOException {
        String filename;
        long size = 0;
        String hash = null;

        if ("file_offer".equals(rawType)) {
            Messages.NativeFileOffer offer = Messages.deserialize(json, Messages.NativeFileOffer.class);
            filename = offer.filename;
            if (offer.record != null) {
                size = offer.record.size;
                hash = offer.record.sha256;
            }
        } else {
            Messages.FileOffer offer = Messages.deserialize(json, Messages.FileOffer.class);
            filename = offer.name;
            size = offer.size;
            hash = offer.hash;
        }

        boolean accepted = consentManager.promptFileOffer(peerNameRemote, filename, size, hash);

        if ("file_offer".equals(rawType)) {
            if (accepted) {
                Messages.NativeFileOfferResponse resp = new Messages.NativeFileOfferResponse();
                resp.filename = filename;
                resp.accepted = true;
                session.sendEncrypted(Messages.serialize(resp));
                // Now receive the file_chunk
                String chunkJson = session.receiveEncrypted();
                if ("file_chunk".equals(PeerSession.rawType(chunkJson))) {
                    receiveNativeFileChunk(session, chunkJson);
                }
            } else {
                Messages.NativeFileOfferResponse resp = new Messages.NativeFileOfferResponse();
                resp.filename = filename;
                resp.accepted = false;
                resp.message  = "Receiver rejected file offer";
                session.sendEncrypted(Messages.serialize(resp));
            }
        } else {
            if (accepted) {
                Messages.FileOfferAccept accept = new Messages.FileOfferAccept();
                accept.hash = hash;
                session.sendEncrypted(Messages.serialize(accept));
                receiveFileData(session, hash, filename, session.getRemoteIdentityPubBase64());
            } else {
                Messages.FileOfferDeny deny = new Messages.FileOfferDeny();
                deny.hash = hash;
                session.sendEncrypted(Messages.serialize(deny));
            }
        }
    }

    private void handleIncomingKeyMigration(PeerSession session, String peerNameRemote,
                                             String json, String rawType) {
        try {
            boolean verified;
            String newIdentityPubBase64;

            if ("key_migration".equals(rawType)) {
                // Native format: hex-encoded fields
                Messages.NativeKeyMigration migration =
                        Messages.deserialize(json, Messages.NativeKeyMigration.class);
                byte[] newPubBytes = HEX.parseHex(migration.new_pub);
                newIdentityPubBase64 = java.util.Base64.getEncoder().encodeToString(newPubBytes);
                verified = KeyMigration.verify(
                        Messages.deserialize(buildJavaStyleMigration(migration), Messages.KeyMigration.class),
                        session.getRemoteIdentityPubBase64());
            } else {
                // Java format: base64-encoded fields
                Messages.KeyMigration migration = Messages.deserialize(json, Messages.KeyMigration.class);
                verified = KeyMigration.verify(migration, session.getRemoteIdentityPubBase64());
                newIdentityPubBase64 = migration.new_identity_pub;
            }

            if (verified) {
                KeyMigration.applyMigration(trustStore, session.getRemoteIdentityPubBase64(), newIdentityPubBase64);
                System.out.println("[+] Key migration accepted for '" + peerNameRemote + "'");
            } else {
                System.out.println("[!] Key migration REJECTED for '" + peerNameRemote + "' — signature verification failed");
            }
        } catch (Exception e) {
            System.err.println("[!] Key migration error: " + e.getMessage());
        }
    }

    /** Converts native hex migration fields to Java base64 format for KeyMigration.verify(). */
    private String buildJavaStyleMigration(Messages.NativeKeyMigration m) {
        String b64New = java.util.Base64.getEncoder().encodeToString(HEX.parseHex(m.new_pub));
        String b64Old = java.util.Base64.getEncoder().encodeToString(HEX.parseHex(m.old_sig));
        String b64New2 = java.util.Base64.getEncoder().encodeToString(HEX.parseHex(m.new_sig));
        return "{\"type\":\"KEY_MIGRATION\",\"new_identity_pub\":\"" + b64New +
               "\",\"signature_old\":\"" + b64Old + "\",\"signature_new\":\"" + b64New2 + "\"}";
    }

    // ── Key migration ────────────────────────────────────────────────────────

    private void migrateKey() throws IOException {
        System.out.println("[*] Generating new identity key...");
        Identity newIdentity = Identity.generate();
        System.out.println("[+] New fingerprint: " + Identity.formatFingerprint(newIdentity.getFingerprint()));

        Messages.KeyMigration javaMsg = KeyMigration.createMigrationMessage(identity, newIdentity);

        // Build native-format migration message (hex fields) for native sessions
        Messages.NativeKeyMigration nativeMsg = new Messages.NativeKeyMigration();
        nativeMsg.new_pub = HEX.formatHex(java.util.Base64.getDecoder().decode(javaMsg.new_identity_pub));
        nativeMsg.old_sig = HEX.formatHex(java.util.Base64.getDecoder().decode(javaMsg.signature_old));
        nativeMsg.new_sig = HEX.formatHex(java.util.Base64.getDecoder().decode(javaMsg.signature_new));

        int notified = 0;
        for (var entry : activeSessions.entrySet()) {
            PeerSession session = entry.getValue();
            if (session.getSocket().isClosed()) continue;
            try {
                if (session.isNativeProtocol()) {
                    session.sendEncrypted(Messages.serialize(nativeMsg));
                } else {
                    session.sendEncrypted(Messages.serialize(javaMsg));
                }
                notified++;
                System.out.println("[+] Notified '" + entry.getKey() + "' of key migration.");
            } catch (IOException e) {
                System.err.println("[!] Failed to notify '" + entry.getKey() + "': " + e.getMessage());
            }
        }

        identity = newIdentity;
        identity.save(dataDir);
        System.out.printf("[+] Key migration complete. Notified %d peer(s).%n", notified);
        System.out.println("[*] Offline contacts will need to re-verify manually.");
    }

    // ── Misc commands ────────────────────────────────────────────────────────

    private void showStoredFiles() {
        try {
            var files = encryptedStore.listFiles();
            if (files.isEmpty()) {
                System.out.println("No files in encrypted store.");
                return;
            }
            System.out.println("Encrypted store (" + files.size() + " file(s)) — decrypting to verify passphrase...");
            int ok = 0, fail = 0;
            for (var meta : files) {
                try {
                    var data = encryptedStore.retrieveFile(meta.hash);
                    if (data.isPresent()) {
                        System.out.printf("  [OK] %-30s %d bytes  origin: %s  stored: %s%n",
                                meta.name, data.get().length,
                                meta.origin != null ? meta.origin.substring(0, Math.min(8, meta.origin.length())) + "..." : "?",
                                meta.stored_at != null ? meta.stored_at.substring(0, 10) : "?");
                        ok++;
                    } else {
                        System.out.printf("  [MISSING] %s — encrypted file not found on disk%n", meta.name);
                        fail++;
                    }
                } catch (Exception e) {
                    System.out.printf("  [FAIL] %-30s — decryption failed (wrong passphrase?)%n", meta.name);
                    fail++;
                }
            }
            if (fail == 0) {
                System.out.println("[+] Passphrase correct — all " + ok + " file(s) decrypted successfully.");
            } else {
                System.out.println("[!] " + fail + " file(s) failed to decrypt — passphrase may be wrong.");
            }
        } catch (Exception e) {
            System.err.println("[!] Could not read encrypted store: " + e.getMessage());
        }
    }

    private void showContacts() {
        var contacts = trustStore.getAllContacts();
        if (contacts.isEmpty()) {
            System.out.println("No trusted contacts.");
            return;
        }
        System.out.println("Trusted contacts:");
        for (var c : contacts) {
            System.out.printf("  %-20s fp: %s%n", c.name, c.fingerprint.substring(0, 16) + "...");
        }
    }

    private void printHelp() {
        System.out.println("Commands:");
        System.out.println("  peers                    - List discovered peers on the network");
        System.out.println("  connect <name>           - Connect and authenticate with a peer");
        System.out.println("  list <name>              - Request file list from a peer");
        System.out.println("  request <name> <file>    - Request a file from a peer");
        System.out.println("  send <name> <filepath>   - Send a local file to a peer");
        System.out.println("  migrate                  - Migrate to a new identity key");
        System.out.println("  contacts                 - Show trusted contacts");
        System.out.println("  stored                   - List encrypted store and verify passphrase");
        System.out.println("  help                     - Show this help");
        System.out.println("  exit                     - Quit");
    }

    private void cleanup() {
        try {
            for (PeerSession s : activeSessions.values()) {
                try { s.close(); } catch (IOException ignored) {}
            }
            if (mdnsService != null) mdnsService.close();
            if (tcpServer != null) tcpServer.close();
        } catch (IOException ignored) {}
    }

    private static String truncHash(String hash) {
        if (hash != null && hash.length() > 16) return hash.substring(0, 16) + "...";
        return hash;
    }
}
