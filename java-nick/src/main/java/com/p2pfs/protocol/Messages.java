package com.p2pfs.protocol;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.List;

public final class Messages {

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    private Messages() {}

    public static String serialize(Object msg) {
        return GSON.toJson(msg);
    }

    public static MessageType typeOf(String json) {
        JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
        String typeName = obj.get("type").getAsString();
        try {
            return MessageType.valueOf(typeName);
        } catch (IllegalArgumentException e) {
            return MessageType.ERROR;
        }
    }

    public static <T> T deserialize(String json, Class<T> clazz) {
        return GSON.fromJson(json, clazz);
    }

    // --- Handshake ---

    // initiator sends identity pub, ephemeral key, nonce
    public static class AuthRequest {
        public final String type = MessageType.AUTH_REQUEST.name();
        public int version = ProtocolConstants.VERSION;
        public String identity_pub;
        public String ephemeral_pub;
        public String nonce;
    }

    // responder echoes back its keys and signs the exchange
    public static class AuthResponse {
        public final String type = MessageType.AUTH_RESPONSE.name();
        public int version = ProtocolConstants.VERSION;
        public String identity_pub;
        public String ephemeral_pub;
        public String nonce;
        public String signature;
    }

    // initiator confirms by signing the responder's nonce
    public static class AuthSuccess {
        public final String type = MessageType.AUTH_SUCCESS.name();
        public String signature;
    }

    // sent when handshake can't continue (untrusted key, bad sig, etc.)
    public static class AuthFail {
        public final String type = MessageType.AUTH_FAIL.name();
        public String reason;

        public AuthFail() {}
        public AuthFail(String reason) { this.reason = reason; }
    }

    // --- Session envelope ---

    // AES-256-GCM wrapper for all post-handshake messages (Java protocol)
    public static class Encrypted {
        public final String type = MessageType.ENCRYPTED.name();
        public String iv;
        public String ciphertext;
    }

    // --- File listing ---

    public static class FileListRequest {
        public final String type = MessageType.FILE_LIST_REQUEST.name();
    }

    public static class FileEntry {
        public String name;
        public long size;
        public String hash;
        public String origin;

        public FileEntry() {}

        public FileEntry(String name, long size, String hash, String origin) {
            this.name = name;
            this.size = size;
            this.hash = hash;
            this.origin = origin;
        }
    }

    public static class FileListResponse {
        public final String type = MessageType.FILE_LIST_RESPONSE.name();
        public List<FileEntry> files;
    }

    // --- File pull (requester -> owner) ---

    public static class FileRequest {
        public final String type = MessageType.FILE_REQUEST.name();
        public String hash;
        public String name;
    }

    public static class FileAccept {
        public final String type = MessageType.FILE_ACCEPT.name();
        public String hash;
    }

    public static class FileDeny {
        public final String type = MessageType.FILE_DENY.name();
        public String hash;
        public String reason;

        public FileDeny() {}
        public FileDeny(String hash, String reason) { this.hash = hash; this.reason = reason; }
    }

    // --- File push (sender -> receiver) ---

    public static class FileOffer {
        public final String type = MessageType.FILE_OFFER.name();
        public String name;
        public long size;
        public String hash;
    }

    public static class FileOfferAccept {
        public final String type = MessageType.FILE_OFFER_ACCEPT.name();
        public String hash;
    }

    public static class FileOfferDeny {
        public final String type = MessageType.FILE_OFFER_DENY.name();
        public String hash;
    }

    // --- File data transfer ---

    // chunk_index is 0-based; total_chunks is the full count
    public static class FileTransfer {
        public final String type = MessageType.FILE_TRANSFER.name();
        public String hash;
        public int chunk_index;
        public int total_chunks;
        public String data;
    }

    // signals end-of-file after all chunks
    public static class FileComplete {
        public final String type = MessageType.FILE_COMPLETE.name();
        public String hash;

        public FileComplete() {}
        public FileComplete(String hash) { this.hash = hash; }
    }

    // --- Key migration ---

    public static class KeyMigration {
        public final String type = MessageType.KEY_MIGRATION.name();
        public String new_identity_pub;
        public String signature_old;
        public String signature_new;
    }

    // --- Native protocol (Go / Python), lowercase types, hex-encoded binary ---

    // both sides send this; initiator goes first
    public static class NativeKeyExchange {
        public final String type = "key_exchange";
        public String pub; // hex-encoded X25519 public key
    }

    // identity announcement after DH
    public static class NativeHello {
        public final String type = "hello";
        public String name;
        public String identity_pub; // hex-encoded Ed25519 public key
        public String fingerprint;  // hex-encoded SHA-256 of identity_pub
    }

    // native encryption envelope (replaces ENCRYPTED for Go/Python sessions)
    public static class NativeData {
        public final String type = "data";
        public String nonce;   // hex, 12 bytes
        public String payload; // hex, AES-256-GCM ciphertext+tag
    }

    // file metadata embedded in list responses and chunks; mirrors Go's FileRecord / Python's record dict
    public static class NativeFileRecord {
        public String owner;     // peer name
        public String owner_pub; // hex Ed25519 public key of original sharer
        public String filename;
        public String sha256;    // hex SHA-256 of file contents
        public int    size;
        public String signature; // hex Ed25519 signature (may be empty from Java)
    }

    public static class NativeFileListRequest {
        public final String type = "file_list_request";
    }

    public static class NativeFileListResponse {
        public final String type = "file_list_response";
        public List<NativeFileRecord> files;
    }

    // pull by filename (no hash needed upfront in native protocol)
    public static class NativeFileRequest {
        public final String type = "file_request";
        public String filename;
    }

    // complete file in one shot; done=true always (Go/Python convention)
    public static class NativeFileChunk {
        public final String type = "file_chunk";
        public String filename;
        public String data;            // hex-encoded file bytes
        public NativeFileRecord record;
        public boolean done = true;
    }

    // push offer; Python supports this, Go does not
    public static class NativeFileOffer {
        public final String type = "file_offer";
        public String filename;
        public NativeFileRecord record;
    }

    public static class NativeFileOfferResponse {
        public final String type = "file_offer_response";
        public String filename;
        public boolean accepted;
        public String message = "";
    }

    // all fields hex-encoded
    public static class NativeKeyMigration {
        public final String type = "key_migration";
        public String new_pub; // hex
        public String old_sig; // hex
        public String new_sig; // hex
    }

    public static class NativeError {
        public final String type = "error";
        public String message;

        public NativeError() {}
        public NativeError(String message) { this.message = message; }
    }

    // --- Error ---

    public static class Error {
        public final String type = MessageType.ERROR.name();
        public String code;
        public String message;

        public Error() {}

        public Error(String code, String message) {
            this.code = code;
            this.message = message;
        }
    }
}
