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
        return MessageType.valueOf(obj.get("type").getAsString());
    }

    public static <T> T deserialize(String json, Class<T> clazz) {
        return GSON.fromJson(json, clazz);
    }

    public static class Hello {
        public final String type = MessageType.HELLO.name();
        public int version = ProtocolConstants.VERSION;
        public String identity_pub;
        public String ephemeral_pub;
        public String nonce;
    }

    public static class HelloReply {
        public final String type = MessageType.HELLO_REPLY.name();
        public int version = ProtocolConstants.VERSION;
        public String identity_pub;
        public String ephemeral_pub;
        public String nonce;
        public String signature;
    }

    public static class Auth {
        public final String type = MessageType.AUTH.name();
        public String signature;
    }

    public static class Encrypted {
        public final String type = MessageType.ENCRYPTED.name();
        public String iv;
        public String ciphertext;
    }

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

    public static class FileRequest {
        public final String type = MessageType.FILE_REQUEST.name();
        public String hash;
        public String name;
    }

    public static class FileResponse {
        public final String type = MessageType.FILE_RESPONSE.name();
        public String hash;
        public boolean accepted;
    }

    public static class FileOffer {
        public final String type = MessageType.FILE_OFFER.name();
        public String name;
        public long size;
        public String hash;
    }

    public static class FileOfferResponse {
        public final String type = MessageType.FILE_OFFER_RESPONSE.name();
        public String hash;
        public boolean accepted;
    }

    public static class FileData {
        public final String type = MessageType.FILE_DATA.name();
        public String hash;
        public int chunk_index;
        public int total_chunks;
        public String data;
    }

    public static class KeyMigration {
        public final String type = MessageType.KEY_MIGRATION.name();
        public String new_identity_pub;
        public String signature_old;
        public String signature_new;
    }

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
