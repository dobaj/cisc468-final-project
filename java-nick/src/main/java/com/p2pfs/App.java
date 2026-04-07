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
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
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
    private MessageHandler handler;
    private String peerName;

    private final BlockingQueue<String> commandQueue = new LinkedBlockingQueue<>();
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
                if (pr != null) pr.offer(line);
                else            commandQueue.offer(line);
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
            if (passphrase.isEmpty()) { System.err.println("[!] Passphrase cannot be empty."); return; }

            dataDir      = Path.of("data", peerName);
            Files.createDirectories(dataDir);

            identity      = Identity.loadOrGenerate(dataDir);
            System.out.println("[+] Identity fingerprint: " + Identity.formatFingerprint(identity.getFingerprint()));

            trustStore    = new TrustStore(dataDir.resolve("truststore.json"));
            fileManager   = new FileManager(dataDir.resolve("shared"), identity.getPublicKeyBase64());
            fileListCache = new FileListCache(dataDir.resolve("cache"));
            encryptedStore= new EncryptedFileStore(dataDir.resolve("store"), passphrase);
            consentManager= new ConsentManager(this);

            try { tcpServer = new TcpServer(ProtocolConstants.DEFAULT_PORT); }
            catch (java.net.BindException e) { tcpServer = new TcpServer(0); }
            System.out.println("[+] Listening on port " + tcpServer.getPort());

            handler = new MessageHandler(identity, peerName, fileManager, fileListCache,
                    consentManager, encryptedStore, activeSessions, trustStore);

            tcpServer.acceptAsync(this::handleIncomingConnection);

            mdnsService = new MdnsService();
            mdnsService.setPeerListener(new MdnsService.PeerListener() {
                @Override public void onPeerDiscovered(MdnsService.PeerInfo peer) {
                    System.out.printf("[*] Discovered peer: %s at %s:%d [%s]%n",
                            peer.name(), peer.host(), peer.port(),
                            peer.isJavaPeer() ? "java" : "native");
                }
                @Override public void onPeerRemoved(String name) {
                    System.out.println("[*] Peer departed: " + name);
                    activeSessions.remove(name);
                }
            });
            mdnsService.start(peerName, tcpServer.getPort(), identity.getFingerprint());
            System.out.println("[+] mDNS registered as '" + peerName + "'");

            commandLoop();
        } catch (Exception e) {
            System.err.println("[!] Fatal error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            cleanup();
        }
    }

    // --- Command loop ---

    private void commandLoop() {
        System.out.println("\nCommands: peers, connect <name>, list <name>, request <name> <file>,");
        System.out.println("          send <name> <file>, migrate, contacts, help, exit\n");

        while (true) {
            System.out.print("> ");
            System.out.flush();
            String line;
            try { line = commandQueue.take().trim(); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
            if (line.isEmpty()) continue;

            String[] parts = line.split("\\s+", 2);
            String cmd  = parts[0].toLowerCase();
            String rest = parts.length > 1 ? parts[1].trim() : "";

            try {
                switch (cmd) {
                    case "peers"   -> listPeers();
                    case "connect" -> { if (rest.isEmpty()) { System.out.println("Usage: connect <name>"); break; }
                                       connectToPeer(rest); }
                    case "connect_ip" -> {
                        String[] p = rest.split("\\s+", 3);
                        if (p.length < 3) { System.out.println("Usage: connect_ip <ip> <port> <name>"); break; }
                        mdnsService.injectPeer(new MdnsService.PeerInfo(p[2], p[0], Integer.parseInt(p[1]), "", "native"));
                        connectToPeer(p[2]);
                    }
                    case "list"    -> { if (rest.isEmpty()) { System.out.println("Usage: list <name>"); break; }
                                       requestFileList(rest); }
                    case "request" -> { int sp = rest.lastIndexOf(' ');
                                       if (sp < 0) { System.out.println("Usage: request <name> <file>"); break; }
                                       requestFile(rest.substring(0, sp).trim(), rest.substring(sp + 1).trim()); }
                    case "send"    -> { int sp = rest.lastIndexOf(' ');
                                       if (sp < 0) { System.out.println("Usage: send <name> <file>"); break; }
                                       sendFile(rest.substring(0, sp).trim(), rest.substring(sp + 1).trim()); }
                    case "migrate" -> migrateKey();
                    case "contacts"-> showContacts();
                    case "stored"  -> showStoredFiles();
                    case "help"    -> printHelp();
                    case "exit", "quit" -> { System.out.println("Goodbye."); return; }
                    default -> System.out.println("Unknown command. Type 'help' for usage.");
                }
            } catch (Exception e) {
                System.err.println("[!] Error: " + e.getMessage());
            }
        }
    }

    // --- Peer management ---

    private void listPeers() {
        var peers = mdnsService.getDiscoveredPeers();
        if (peers.isEmpty()) { System.out.println("No peers discovered."); return; }
        System.out.println("Discovered peers:");
        peers.values().forEach(p -> System.out.printf("  %-20s %s:%d [%s]%n",
                p.name(), p.host(), p.port(), p.isJavaPeer() ? "java" : "native"));
    }

    private void connectToPeer(String name) throws IOException {
        var peerInfo = mdnsService.getDiscoveredPeers().get(name);
        if (peerInfo == null) {
            System.out.println("[!] Peer '" + name + "' not found. Run 'peers' to see available peers.");
            return;
        }
        Socket sock = TcpClient.connect(peerInfo.host(), peerInfo.port());
        PeerSession session = new PeerSession(sock, identity, trustStore, this);

        if (peerInfo.isJavaPeer()) session.handshakeAsInitiator();
        else                       session.handshakeNativeAsInitiator(peerName);

        activeSessions.put(name, session);
        System.out.println("[+] Connected and authenticated with '" + name + "' [" +
                (session.isNativeProtocol() ? "native" : "java") + "]");

        LinkedBlockingQueue<String> rq = new LinkedBlockingQueue<>();
        session.setReceiveQueue(rq);
        Thread t = new Thread(() -> handler.dispatch(session, name), "peer-" + name);
        t.setDaemon(true);
        t.start();
    }

    private PeerSession getSession(String name) throws IOException {
        PeerSession s = activeSessions.get(name);
        if (s == null || s.getSocket().isClosed()) {
            activeSessions.remove(name);
            connectToPeer(name);
            s = activeSessions.get(name);
        }
        if (s == null) throw new IOException("No active session with '" + name + "'");
        return s;
    }

    // --- File list ---

    private void requestFileList(String name) throws IOException {
        PeerSession session = getSession(name);
        if (session.isNativeProtocol()) {
            session.sendEncrypted(Messages.serialize(new Messages.NativeFileListRequest()));
            String resp = session.receiveEncrypted();
            if (!"file_list_response".equals(PeerSession.rawType(resp))) {
                System.out.println("[!] Unexpected response: " + resp); return;
            }
            Messages.NativeFileListResponse r = Messages.deserialize(resp, Messages.NativeFileListResponse.class);
            System.out.println("Files available from '" + name + "':");
            if (r.files == null || r.files.isEmpty()) { System.out.println("  (none)"); return; }
            List<Messages.FileEntry> entries = new ArrayList<>();
            for (Messages.NativeFileRecord f : r.files) {
                System.out.printf("  %-30s %8d bytes  hash:%s%n", f.filename, f.size, MessageHandler.truncHash(f.sha256));
                entries.add(new Messages.FileEntry(f.filename, f.size, f.sha256,
                        f.owner_pub != null ? HEX.formatHex(HEX.parseHex(f.owner_pub)) : ""));
            }
            fileListCache.cache(session.getRemoteIdentityPubBase64(), name, entries);
        } else {
            session.sendEncrypted(Messages.serialize(new Messages.FileListRequest()));
            Messages.FileListResponse r = Messages.deserialize(
                    session.receiveEncrypted(), Messages.FileListResponse.class);
            System.out.println("Files available from '" + name + "':");
            if (r.files == null || r.files.isEmpty()) { System.out.println("  (none)"); return; }
            r.files.forEach(f -> System.out.printf("  %-30s %8d bytes  hash:%s%n",
                    f.name, f.size, MessageHandler.truncHash(f.hash)));
            fileListCache.cache(session.getRemoteIdentityPubBase64(), name, r.files);
        }
    }

    // --- File request (pull) ---

    private void requestFile(String name, String fileName) throws IOException {
        PeerSession session;
        try { session = getSession(name); }
        catch (IOException e) {
            System.out.println("[*] Peer '" + name + "' is offline. Searching cached file lists...");
            requestFileFromThirdParty(name, fileName);
            return;
        }

        if (session.isNativeProtocol()) {
            Messages.NativeFileRequest req = new Messages.NativeFileRequest();
            req.filename = fileName;
            session.sendEncrypted(Messages.serialize(req));
            String resp = session.receiveEncrypted();
            String type = PeerSession.rawType(resp);
            if ("error".equals(type)) {
                System.out.println("[!] " + name + ": " +
                        JsonParser.parseString(resp).getAsJsonObject().get("message").getAsString());
                return;
            }
            if (!"file_chunk".equals(type)) { System.out.println("[!] Unexpected: " + resp); return; }
            handler.receiveNativeFileChunk(session, resp);
        } else {
            Messages.FileRequest req = new Messages.FileRequest();
            req.name = fileName;
            String hash = resolveHash(session, name, fileName);
            if (hash == null) { System.out.println("[!] File '" + fileName + "' not found in " + name + "'s list."); return; }
            req.hash = hash;
            session.sendEncrypted(Messages.serialize(req));
            String resp = session.receiveEncrypted();
            if (Messages.typeOf(resp) == MessageType.FILE_DENY) {
                System.out.println("[!] " + name + " rejected the request."); return;
            }
            if (Messages.typeOf(resp) != MessageType.FILE_ACCEPT) {
                System.out.println("[!] Unexpected: " + resp); return;
            }
            handler.receiveFileData(session, hash, fileName, session.getRemoteIdentityPubBase64());
        }
    }

    private String resolveHash(PeerSession session, String peerName, String fileName) throws IOException {
        var cached = fileListCache.load(session.getRemoteIdentityPubBase64());
        if (cached.isPresent()) {
            String h = cached.get().files.stream()
                    .filter(f -> f.name.equals(fileName)).map(f -> f.hash).findFirst().orElse(null);
            if (h != null) return h;
        }
        session.sendEncrypted(Messages.serialize(new Messages.FileListRequest()));
        Messages.FileListResponse list = Messages.deserialize(
                session.receiveEncrypted(), Messages.FileListResponse.class);
        if (list.files != null) {
            fileListCache.cache(session.getRemoteIdentityPubBase64(), peerName, list.files);
            return list.files.stream()
                    .filter(f -> f.name.equals(fileName)).map(f -> f.hash).findFirst().orElse(null);
        }
        return null;
    }

    private void requestFileFromThirdParty(String offlinePeerName, String fileName) throws IOException {
        var contact = trustStore.findByName(offlinePeerName);
        if (contact.isEmpty()) { System.out.println("[!] No trusted contact named '" + offlinePeerName + "'"); return; }
        var cached = fileListCache.load(contact.get().identity_pub);
        if (cached.isEmpty()) { System.out.println("[!] No cached file list from '" + offlinePeerName + "'"); return; }

        String hash = cached.get().files.stream()
                .filter(f -> f.name.equals(fileName)).map(f -> f.hash).findFirst().orElse(null);
        if (hash == null) { System.out.println("[!] File '" + fileName + "' not in cached list."); return; }

        String originPub = contact.get().identity_pub;
        for (var entry : activeSessions.entrySet()) {
            PeerSession session = entry.getValue();
            if (session.getSocket().isClosed()) continue;
            try {
                List<Messages.FileEntry> files = queryFileList(session, entry.getKey());
                if (files == null) continue;
                final String fHash = hash;
                boolean has = files.stream().anyMatch(f -> f.hash.equals(fHash));
                if (!has) continue;
                System.out.println("[*] Found '" + fileName + "' on '" + entry.getKey() + "', requesting...");
                if (session.isNativeProtocol()) {
                    Messages.NativeFileRequest req = new Messages.NativeFileRequest();
                    req.filename = fileName;
                    session.sendEncrypted(Messages.serialize(req));
                    String resp = session.receiveEncrypted();
                    if ("file_chunk".equals(PeerSession.rawType(resp))) {
                        handler.receiveNativeFileChunk(session, resp); return;
                    }
                } else {
                    Messages.FileRequest req = new Messages.FileRequest();
                    req.hash = hash; req.name = fileName;
                    session.sendEncrypted(Messages.serialize(req));
                    String resp = session.receiveEncrypted();
                    if (Messages.typeOf(resp) == MessageType.FILE_DENY) continue;
                    handler.receiveFileData(session, hash, fileName, originPub); return;
                }
            } catch (IOException e) {
                System.err.println("[!] Error querying " + entry.getKey() + ": " + e.getMessage());
            }
        }
        System.out.println("[!] Could not find '" + fileName + "' on any connected peer.");
    }

    private List<Messages.FileEntry> queryFileList(PeerSession session, String peerName) throws IOException {
        if (session.isNativeProtocol()) {
            session.sendEncrypted(Messages.serialize(new Messages.NativeFileListRequest()));
            String json = session.receiveEncrypted();
            if (!"file_list_response".equals(PeerSession.rawType(json))) return null;
            Messages.NativeFileListResponse resp = Messages.deserialize(json, Messages.NativeFileListResponse.class);
            if (resp.files == null) return List.of();
            List<Messages.FileEntry> entries = new ArrayList<>();
            for (Messages.NativeFileRecord r : resp.files)
                entries.add(new Messages.FileEntry(r.filename, r.size, r.sha256, r.owner_pub != null ? r.owner_pub : ""));
            fileListCache.cache(session.getRemoteIdentityPubBase64(), peerName, entries);
            return entries;
        } else {
            session.sendEncrypted(Messages.serialize(new Messages.FileListRequest()));
            Messages.FileListResponse resp = Messages.deserialize(
                    session.receiveEncrypted(), Messages.FileListResponse.class);
            if (resp.files == null) return List.of();
            fileListCache.cache(session.getRemoteIdentityPubBase64(), peerName, resp.files);
            return resp.files;
        }
    }

    // --- File send (push) ---

    private void sendFile(String name, String filePath) throws IOException {
        PeerSession session = getSession(name);
        Path path = Path.of(filePath);
        if (!Files.isRegularFile(path)) path = fileManager.getSharedDir().resolve(filePath);
        if (!Files.isRegularFile(path)) { System.out.println("[!] File not found: " + filePath); return; }

        String hash = FileHash.hashFile(path);
        long size   = Files.size(path);

        if (session.isNativeProtocol()) {
            Messages.NativeFileRecord rec = new Messages.NativeFileRecord();
            rec.filename  = path.getFileName().toString();
            rec.sha256    = hash; rec.size = (int) size;
            rec.owner     = peerName;
            rec.owner_pub = HEX.formatHex(identity.getPublicKeyBytes());
            rec.signature = HEX.formatHex(identity.sign(MessageHandler.nativeFileRecordPayload(rec)));

            Messages.NativeFileOffer offer = new Messages.NativeFileOffer();
            offer.filename = rec.filename; offer.record = rec;
            session.sendEncrypted(Messages.serialize(offer));

            String resp = session.receiveEncrypted();
            String type = PeerSession.rawType(resp);
            if ("file_offer_response".equals(type)) {
                if (!Messages.deserialize(resp, Messages.NativeFileOfferResponse.class).accepted) {
                    System.out.println("[!] " + name + " rejected the file."); return;
                }
            } else if ("error".equals(type)) {
                System.out.println("[!] " + name + ": " +
                        JsonParser.parseString(resp).getAsJsonObject().get("message").getAsString());
                return;
            } else { System.out.println("[!] Unexpected: " + resp); return; }

            handler.sendNativeFileChunk(session, path, hash);
        } else {
            Messages.FileOffer offer = new Messages.FileOffer();
            offer.name = path.getFileName().toString(); offer.size = size; offer.hash = hash;
            session.sendEncrypted(Messages.serialize(offer));

            String resp = session.receiveEncrypted();
            if (Messages.typeOf(resp) == MessageType.FILE_OFFER_DENY) {
                System.out.println("[!] " + name + " rejected the file."); return;
            }
            if (Messages.typeOf(resp) != MessageType.FILE_OFFER_ACCEPT) {
                System.out.println("[!] Unexpected: " + resp); return;
            }
            handler.sendFileData(session, path, hash);
        }
        System.out.println("[+] File sent successfully.");
    }

    // --- Incoming connection ---

    private void handleIncomingConnection(Socket socket) {
        try {
            PeerSession session = new PeerSession(socket, identity, trustStore, this);
            session.handshakeAutoDetect(peerName);
            String remoteName = session.getRemotePeerName();
            System.out.println("\n[+] Incoming connection from '" + remoteName + "' [" +
                    (session.isNativeProtocol() ? "native" : "java") + "], ready to receive.");
            handler.dispatch(session, remoteName);
        } catch (IOException e) {
            System.err.println("[!] Incoming connection failed: " + e.getMessage());
        }
    }

    // --- Key migration ---

    private void migrateKey() throws IOException {
        System.out.println("[*] Generating new identity key...");
        Identity newIdentity = Identity.generate();
        System.out.println("[+] New fingerprint: " + Identity.formatFingerprint(newIdentity.getFingerprint()));

        Messages.KeyMigration javaMsg = KeyMigration.createMigrationMessage(identity, newIdentity);
        Messages.NativeKeyMigration nativeMsg = new Messages.NativeKeyMigration();
        nativeMsg.new_pub = HEX.formatHex(Base64.getDecoder().decode(javaMsg.new_identity_pub));
        nativeMsg.old_sig = HEX.formatHex(Base64.getDecoder().decode(javaMsg.signature_old));
        nativeMsg.new_sig = HEX.formatHex(Base64.getDecoder().decode(javaMsg.signature_new));

        int notified = 0;
        for (var entry : activeSessions.entrySet()) {
            PeerSession s = entry.getValue();
            if (s.getSocket().isClosed()) continue;
            try {
                s.sendEncrypted(Messages.serialize(s.isNativeProtocol() ? nativeMsg : javaMsg));
                notified++;
                System.out.println("[+] Notified '" + entry.getKey() + "' of key migration.");
            } catch (IOException e) {
                System.err.println("[!] Failed to notify '" + entry.getKey() + "': " + e.getMessage());
            }
        }

        identity = newIdentity;
        identity.save(dataDir);
        handler.setIdentity(newIdentity);
        System.out.printf("[+] Key migration complete. Notified %d peer(s).%n", notified);
        System.out.println("[*] Offline contacts will need to re-verify manually.");
    }

    // --- Misc ---

    private void showContacts() {
        var contacts = trustStore.getAllContacts();
        if (contacts.isEmpty()) { System.out.println("No trusted contacts."); return; }
        System.out.println("Trusted contacts:");
        contacts.forEach(c -> System.out.printf("  %-20s fp: %s%n",
                c.name, c.fingerprint.substring(0, 16) + "..."));
    }

    private void showStoredFiles() {
        try {
            var files = encryptedStore.listFiles();
            if (files.isEmpty()) { System.out.println("No files in encrypted store."); return; }
            System.out.println("Encrypted store (" + files.size() + " file(s)):");
            int ok = 0, fail = 0;
            for (var meta : files) {
                try {
                    var data = encryptedStore.retrieveFile(meta.hash);
                    if (data.isPresent()) {
                        System.out.printf("  [OK] %-30s %d bytes  stored: %s%n",
                                meta.name, data.get().length,
                                meta.stored_at != null ? meta.stored_at.substring(0, 10) : "?");
                        ok++;
                    } else { System.out.printf("  [MISSING] %s%n", meta.name); fail++; }
                } catch (Exception e) { System.out.printf("  [FAIL] %s%n", meta.name); fail++; }
            }
            System.out.println(fail == 0 ? "[+] All " + ok + " file(s) OK." : "[!] " + fail + " file(s) failed.");
        } catch (Exception e) { System.err.println("[!] Could not read store: " + e.getMessage()); }
    }

    private void printHelp() {
        System.out.println("Commands:");
        System.out.println("  peers                  - List discovered peers");
        System.out.println("  connect <name>         - Connect to a peer");
        System.out.println("  list <name>            - Get file list from a peer");
        System.out.println("  request <name> <file>  - Pull a file from a peer");
        System.out.println("  send <name> <file>     - Push a file to a peer");
        System.out.println("  migrate                - Rotate identity key");
        System.out.println("  contacts               - Show trusted contacts");
        System.out.println("  stored                 - List encrypted store");
        System.out.println("  exit                   - Quit");
    }

    private void cleanup() {
        activeSessions.values().forEach(s -> { try { s.close(); } catch (IOException ignored) {} });
        try { if (mdnsService != null) mdnsService.close(); } catch (IOException ignored) {}
        try { if (tcpServer   != null) tcpServer.close();   } catch (IOException ignored) {}
    }
}
