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
