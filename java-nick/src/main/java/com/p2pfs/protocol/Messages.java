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

    // ── Handshake ──────────────────────────────────────────────────────────────

    /** Initiator opens authentication: sends identity pub key, ephemeral key, nonce. */
    public static class AuthRequest {
        public final String type = MessageType.AUTH_REQUEST.name();
        public int version = ProtocolConstants.VERSION;
        public String identity_pub;
        public String ephemeral_pub;
        public String nonce;
    }

    /** Responder replies with its own keys + its signature over the exchange. */
    public static class AuthResponse {
        public final String type = MessageType.AUTH_RESPONSE.name();
        public int version = ProtocolConstants.VERSION;
        public String identity_pub;
        public String ephemeral_pub;
        public String nonce;
        public String signature;
    }

    /** Initiator confirms authentication by sending its own signature. */
    public static class AuthSuccess {
        public final String type = MessageType.AUTH_SUCCESS.name();
        public String signature;
    }

    /** Sent when authentication cannot proceed (untrusted key, bad signature, etc.). */
    public static class AuthFail {
        public final String type = MessageType.AUTH_FAIL.name();
        public String reason;

        public AuthFail() {}
        public AuthFail(String reason) { this.reason = reason; }
    }

    // ── Session envelope ───────────────────────────────────────────────────────

    /** AES-256-GCM encrypted wrapper for all post-handshake messages. */
    public static class Encrypted {
        public final String type = MessageType.ENCRYPTED.name();
        public String iv;
        public String ciphertext;
    }

    // ── File listing ───────────────────────────────────────────────────────────

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

    // ── File pull (requester → owner) ──────────────────────────────────────────

    /** Requester asks for a specific file by hash + name. */
    public static class FileRequest {
        public final String type = MessageType.FILE_REQUEST.name();
        public String hash;
        public String name;
    }

    /** Owner accepts the file request; data transfer will follow. */
    public static class FileAccept {
        public final String type = MessageType.FILE_ACCEPT.name();
        public String hash;
    }

    /** Owner denies the file request. */
    public static class FileDeny {
        public final String type = MessageType.FILE_DENY.name();
        public String hash;
        public String reason;

        public FileDeny() {}
        public FileDeny(String hash, String reason) { this.hash = hash; this.reason = reason; }
    }

    // ── File push (sender → receiver) ─────────────────────────────────────────

    /** Sender offers a file; receiver must consent before transfer begins. */
    public static class FileOffer {
        public final String type = MessageType.FILE_OFFER.name();
        public String name;
        public long size;
        public String hash;
    }

    /** Receiver accepts the file offer. */
    public static class FileOfferAccept {
        public final String type = MessageType.FILE_OFFER_ACCEPT.name();
        public String hash;
    }

    /** Receiver denies the file offer. */
    public static class FileOfferDeny {
        public final String type = MessageType.FILE_OFFER_DENY.name();
        public String hash;
    }

    // ── File data transfer ─────────────────────────────────────────────────────

    /** One chunk of file data. chunk_index is 0-based; total_chunks is the full count. */
    public static class FileTransfer {
        public final String type = MessageType.FILE_TRANSFER.name();
        public String hash;
        public int chunk_index;
        public int total_chunks;
        public String data;
    }

    /** Sent by the sender after all FILE_TRANSFER chunks to signal end-of-file. */
    public static class FileComplete {
        public final String type = MessageType.FILE_COMPLETE.name();
        public String hash;

        public FileComplete() {}
        public FileComplete(String hash) { this.hash = hash; }
    }

    // ── Key migration ──────────────────────────────────────────────────────────

    public static class KeyMigration {
        public final String type = MessageType.KEY_MIGRATION.name();
        public String new_identity_pub;
        public String signature_old;
        public String signature_new;
    }

    // ── Native protocol (Go / Python) ─────────────────────────────────────────
    // All type strings are lowercase; binary values are hex-encoded (not Base64).

    /** Step 1 of native handshake — sent by both sides (initiator first). */
    public static class NativeKeyExchange {
        public final String type = "key_exchange";
        public String pub; // hex-encoded X25519 public key
    }

    /** Step 2 of native handshake — identity announcement after DH. */
    public static class NativeHello {
        public final String type = "hello";
        public String name;
        public String identity_pub; // hex-encoded Ed25519 public key
        public String fingerprint;  // hex-encoded SHA-256 of identity_pub
    }

    /** Native session encryption envelope (replaces ENCRYPTED for native sessions). */
    public static class NativeData {
        public final String type = "data";
        public String nonce;   // hex, 12 bytes
        public String payload; // hex, AES-256-GCM ciphertext+tag
    }

    /**
     * File metadata record embedded in native file list and file chunk messages.
     * All fields use hex encoding; this matches Go's FileRecord struct and Python's record dict.
     */
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

    /** Native file pull request — uses filename only, no hash required upfront. */
    public static class NativeFileRequest {
        public final String type = "file_request";
        public String filename;
    }

    /** Native file chunk — complete file in one message (Go/Python always set done=true). */
    public static class NativeFileChunk {
        public final String type = "file_chunk";
        public String filename;
        public String data;            // hex-encoded file bytes
        public NativeFileRecord record;
        public boolean done = true;
    }

    /** Native file push offer (Python supports this; Go does not). */
    public static class NativeFileOffer {
        public final String type = "file_offer";
        public String filename;
        public NativeFileRecord record;
    }

    /** Response to a native file offer. */
    public static class NativeFileOfferResponse {
        public final String type = "file_offer_response";
        public String filename;
        public boolean accepted;
        public String message = "";
    }

    /** Native key migration — all fields hex-encoded. */
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

    // ── Error ──────────────────────────────────────────────────────────────────

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
