package com.p2pfs.protocol;

public final class ProtocolConstants {
    public static final int VERSION = 1;
    /** Group-agreed TCP port. mDNS advertises the actual port, so peers discover each other even when this falls back. */
    public static final int DEFAULT_PORT = 6767;
    /** HKDF info string used by Go and Python native protocol (differs from Java's "p2p-session"). */
    public static final String NATIVE_HKDF_INFO = "session key";
    public static final int LENGTH_PREFIX_BYTES = 4;
    public static final int MAX_PAYLOAD_BYTES = 10 * 1024 * 1024; // 10 MiB
    public static final int MAX_CHUNK_BYTES = 1024 * 1024; // 1 MiB
    public static final int NONCE_BYTES = 32;
    public static final int AES_KEY_BYTES = 32;
    public static final int GCM_IV_BYTES = 12;
    public static final String HKDF_INFO = "p2p-session";
    public static final String MDNS_SERVICE_TYPE = "_p2pfs._tcp.local.";

    private ProtocolConstants() {}
}
