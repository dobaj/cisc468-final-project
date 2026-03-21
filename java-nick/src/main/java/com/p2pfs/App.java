package com.p2pfs;

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
    // Commands go here (read by the command loop)
    private final BlockingQueue<String> commandQueue = new LinkedBlockingQueue<>();
    // When a consent/trust prompt is active, its dedicated response queue is registered here.
    // The stdin reader routes input to this queue instead of commandQueue.
    private final AtomicReference<BlockingQueue<String>> promptReceiver = new AtomicReference<>(null);
    private final Map<String, PeerSession> activeSessions = new ConcurrentHashMap<>();
    private Path dataDir;

    /**
     * Called by consent/trust prompt handlers (on background threads).
     * Registers a dedicated response queue so the stdin router bypasses the command loop.
     */
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
        // Single daemon thread reads stdin and routes lines:
        //   - if a prompt handler is waiting: send to its dedicated queue
        //   - otherwise: send to the command queue
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
            String peerName = commandQueue.take().trim();
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

            tcpServer = new TcpServer(0);
            int port = tcpServer.getPort();
            System.out.println("[+] Listening on port " + port);

            tcpServer.acceptAsync(this::handleIncomingConnection);

            mdnsService = new MdnsService();
            mdnsService.setPeerListener(new MdnsService.PeerListener() {
                @Override
                public void onPeerDiscovered(MdnsService.PeerInfo peer) {
                    System.out.printf("[*] Discovered peer: %s at %s:%d (fp: %s)%n",
                            peer.name(), peer.host(), peer.port(),
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
            System.out.printf("  %-20s %s:%d%n", p.name(), p.host(), p.port());
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
        session.handshakeAsInitiator();
        activeSessions.put(name, session);
        System.out.println("[+] Connected and authenticated with '" + name + "'");
    }

    private PeerSession getSession(String name) throws IOException {
        PeerSession session = activeSessions.get(name);
        if (session == null || session.getSocket().isClosed()) {
            activeSessions.remove(name);
            // Try to connect automatically
            connectToPeer(name);
            session = activeSessions.get(name);
        }
        if (session == null) {
            throw new IOException("No active session with '" + name + "'");
        }
        return session;
    }

    private void requestFileList(String name) throws IOException {
        PeerSession session = getSession(name);
        session.sendEncrypted(Messages.serialize(new Messages.FileListRequest()));
        String responseJson = session.receiveEncrypted();
        Messages.FileListResponse response = Messages.deserialize(responseJson, Messages.FileListResponse.class);

        System.out.println("Files available from '" + name + "':");
        if (response.files == null || response.files.isEmpty()) {
            System.out.println("  (none)");
        } else {
            for (Messages.FileEntry f : response.files) {
                System.out.printf("  %-30s %8d bytes  hash:%s%n", f.name, f.size, truncHash(f.hash));
            }
            // Cache the file list
            fileListCache.cache(session.getRemoteIdentityPubBase64(), name, response.files);
        }
    }

    private void requestFile(String name, String fileName) throws IOException {
        PeerSession session;
        try {
            session = getSession(name);
        } catch (IOException e) {
            // Peer might be offline — try to find file from a third party
            System.out.println("[*] Peer '" + name + "' is offline. Searching cached file lists...");
            requestFileFromThirdParty(name, fileName);
            return;
        }

        Messages.FileRequest req = new Messages.FileRequest();
        req.name = fileName;
        // We need the hash — look up from cached file list or ask
        var cached = fileListCache.load(session.getRemoteIdentityPubBase64());
        String hash = null;
        if (cached.isPresent()) {
            hash = cached.get().files.stream()
                    .filter(f -> f.name.equals(fileName))
                    .map(f -> f.hash).findFirst().orElse(null);
        }
        if (hash == null) {
            // Request file list first to get the hash
            session.sendEncrypted(Messages.serialize(new Messages.FileListRequest()));
            String listJson = session.receiveEncrypted();
            Messages.FileListResponse listResp = Messages.deserialize(listJson, Messages.FileListResponse.class);
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
        Messages.FileResponse resp = Messages.deserialize(respJson, Messages.FileResponse.class);
        if (!resp.accepted) {
            System.out.println("[!] " + name + " rejected the file request.");
            return;
        }

        receiveFileData(session, hash, fileName, session.getRemoteIdentityPubBase64());
    }

    private void requestFileFromThirdParty(String offlinePeerName, String fileName) throws IOException {
        // Find the offline peer's identity in trust store
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

        // Search connected peers for someone who has this file
        for (var entry : activeSessions.entrySet()) {
            PeerSession session = entry.getValue();
            if (session.getSocket().isClosed()) continue;
            try {
                session.sendEncrypted(Messages.serialize(new Messages.FileListRequest()));
                String listJson = session.receiveEncrypted();
                Messages.FileListResponse listResp = Messages.deserialize(listJson, Messages.FileListResponse.class);
                if (listResp.files == null) continue;

                boolean hasFile = listResp.files.stream()
                        .anyMatch(f -> f.hash.equals(hash) && f.origin.equals(originPub));
                if (hasFile) {
                    System.out.println("[*] Found file on peer '" + entry.getKey() + "', requesting...");
                    Messages.FileRequest req = new Messages.FileRequest();
                    req.hash = hash;
                    req.name = fileName;
                    session.sendEncrypted(Messages.serialize(req));

                    String respJson = session.receiveEncrypted();
                    Messages.FileResponse resp = Messages.deserialize(respJson, Messages.FileResponse.class);
                    if (!resp.accepted) {
                        System.out.println("[!] " + entry.getKey() + " rejected the request.");
                        continue;
                    }

                    receiveFileData(session, hash, fileName, originPub);
                    return;
                }
            } catch (IOException e) {
                System.err.println("[!] Error querying " + entry.getKey() + ": " + e.getMessage());
            }
        }
        System.out.println("[!] Could not find '" + fileName + "' on any connected peer.");
    }

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
            Messages.FileData data = Messages.deserialize(dataJson, Messages.FileData.class);
            totalChunks = data.total_chunks;
            chunks.put(data.chunk_index, Base64.getDecoder().decode(data.data));

            if (chunks.size() >= totalChunks) break;
        }

        // Reassemble
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

        // Verify hash
        String actualHash = FileHash.hashBytes(fileBytes);
        if (!actualHash.equals(expectedHash)) {
            System.out.println("[!] FILE TAMPERED! Expected hash " + truncHash(expectedHash) +
                    " but got " + truncHash(actualHash));
            System.out.println("[!] File discarded.");
            return;
        }
        System.out.println("[+] Hash verified: " + truncHash(actualHash));

        // Save to shared directory
        Path saved = fileManager.saveFile(fileName, fileBytes);
        fileManager.addReceivedFile(fileName, fileBytes.length, actualHash, origin);
        System.out.println("[+] Saved to " + saved);

        // Also store encrypted
        try {
            encryptedStore.storeFile(fileName, actualHash, origin, fileBytes);
        } catch (GeneralSecurityException e) {
            System.err.println("[!] Failed to store encrypted copy: " + e.getMessage());
        }
    }

    private void sendFile(String name, String filePath) throws IOException {
        PeerSession session = getSession(name);
        Path path = Path.of(filePath);
        // If not found as given, try relative to the shared directory
        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            path = fileManager.getSharedDir().resolve(filePath);
        }
        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            System.out.println("[!] File not found: " + filePath);
            return;
        }
        String hash = FileHash.hashFile(path);
        long size = Files.size(path);

        Messages.FileOffer offer = new Messages.FileOffer();
        offer.name = path.getFileName().toString();
        offer.size = size;
        offer.hash = hash;
        session.sendEncrypted(Messages.serialize(offer));

        String respJson = session.receiveEncrypted();
        Messages.FileOfferResponse resp = Messages.deserialize(respJson, Messages.FileOfferResponse.class);
        if (!resp.accepted) {
            System.out.println("[!] " + name + " rejected the file.");
            return;
        }

        sendFileData(session, path, hash);
        System.out.println("[+] File sent successfully.");
    }

    private void sendFileData(PeerSession session, Path path, String hash) throws IOException {
        byte[] fileBytes = Files.readAllBytes(path);
        int chunkSize = ProtocolConstants.MAX_CHUNK_BYTES;
        int totalChunks = (int) Math.ceil((double) fileBytes.length / chunkSize);
        if (totalChunks == 0) totalChunks = 1;

        for (int i = 0; i < totalChunks; i++) {
            int offset = i * chunkSize;
            int len = Math.min(chunkSize, fileBytes.length - offset);
            byte[] chunk = Arrays.copyOfRange(fileBytes, offset, offset + len);

            Messages.FileData data = new Messages.FileData();
            data.hash = hash;
            data.chunk_index = i;
            data.total_chunks = totalChunks;
            data.data = Base64.getEncoder().encodeToString(chunk);
            session.sendEncrypted(Messages.serialize(data));
        }
    }

    private void handleIncomingConnection(Socket socket) {
        try {
            PeerSession session = new PeerSession(socket, identity, trustStore, this);
            session.handshakeAsResponder();
            String remoteName = session.getRemotePeerName();
            System.out.println("\n[+] Incoming connection from '" + remoteName + "' — ready to receive.");

            // Handle messages from this peer (incoming sessions are NOT in activeSessions;
            // use 'connect <name>' to open an outgoing session for sending commands)
            handlePeerMessages(session, remoteName);
        } catch (IOException e) {
            System.err.println("[!] Incoming connection failed: " + e.getMessage());
        }
    }

    private void handlePeerMessages(PeerSession session, String peerName) {
        try {
            while (!session.getSocket().isClosed()) {
                String json = session.receiveEncrypted();
                MessageType type = Messages.typeOf(json);

                switch (type) {
                    case FILE_LIST_REQUEST -> {
                        Messages.FileListResponse resp = new Messages.FileListResponse();
                        resp.files = fileManager.getFileList();
                        session.sendEncrypted(Messages.serialize(resp));
                    }
                    case FILE_REQUEST -> {
                        Messages.FileRequest req = Messages.deserialize(json, Messages.FileRequest.class);
                        boolean accepted = consentManager.promptFileRequest(peerName, req.name, req.hash);
                        Messages.FileResponse resp = new Messages.FileResponse();
                        resp.hash = req.hash;
                        resp.accepted = accepted;
                        session.sendEncrypted(Messages.serialize(resp));

                        if (accepted) {
                            Optional<Path> file = fileManager.getFileByHash(req.hash);
                            if (file.isPresent()) {
                                sendFileData(session, file.get(), req.hash);
                            } else {
                                session.sendEncrypted(Messages.serialize(
                                        new Messages.Error("FILE_NOT_FOUND", "File not available")));
                            }
                        }
                    }
                    case FILE_OFFER -> {
                        Messages.FileOffer offer = Messages.deserialize(json, Messages.FileOffer.class);
                        boolean accepted = consentManager.promptFileOffer(peerName, offer.name, offer.size, offer.hash);
                        Messages.FileOfferResponse resp = new Messages.FileOfferResponse();
                        resp.hash = offer.hash;
                        resp.accepted = accepted;
                        session.sendEncrypted(Messages.serialize(resp));

                        if (accepted) {
                            receiveFileData(session, offer.hash, offer.name, session.getRemoteIdentityPubBase64());
                        }
                    }
                    case KEY_MIGRATION -> {
                        Messages.KeyMigration migration = Messages.deserialize(json, Messages.KeyMigration.class);
                        if (KeyMigration.verify(migration, session.getRemoteIdentityPubBase64())) {
                            KeyMigration.applyMigration(trustStore,
                                    session.getRemoteIdentityPubBase64(), migration.new_identity_pub);
                            System.out.println("[+] Key migration accepted for '" + peerName + "'");
                        } else {
                            System.out.println("[!] Key migration REJECTED for '" + peerName + "' — signature verification failed");
                        }
                    }
                    case ERROR -> {
                        Messages.Error err = Messages.deserialize(json, Messages.Error.class);
                        System.out.printf("[!] Error from '%s': [%s] %s%n", peerName, err.code, err.message);
                    }
                    default -> System.out.println("[?] Unexpected message type from " + peerName + ": " + type);
                }
            }
        } catch (IOException e) {
            if (!session.getSocket().isClosed()) {
                System.err.println("[!] Connection lost with '" + peerName + "': " + e.getMessage());
            }
            activeSessions.remove(peerName);
        }
    }

    private void migrateKey() throws IOException {
        System.out.println("[*] Generating new identity key...");
        Identity newIdentity = Identity.generate();
        System.out.println("[+] New fingerprint: " + Identity.formatFingerprint(newIdentity.getFingerprint()));

        Messages.KeyMigration migrationMsg = KeyMigration.createMigrationMessage(identity, newIdentity);

        int notified = 0;
        for (var entry : activeSessions.entrySet()) {
            PeerSession session = entry.getValue();
            if (session.getSocket().isClosed()) continue;
            try {
                session.sendEncrypted(Messages.serialize(migrationMsg));
                notified++;
                System.out.println("[+] Notified '" + entry.getKey() + "' of key migration.");
            } catch (IOException e) {
                System.err.println("[!] Failed to notify '" + entry.getKey() + "': " + e.getMessage());
            }
        }

        // Replace identity
        identity = newIdentity;
        identity.save(dataDir);
        System.out.printf("[+] Key migration complete. Notified %d peer(s).%n", notified);
        System.out.println("[*] Offline contacts will need to re-verify manually.");
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
