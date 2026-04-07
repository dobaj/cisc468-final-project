package com.p2pfs.net;

import com.p2pfs.protocol.ProtocolConstants;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Reads and writes length-prefixed UTF-8 JSON messages over a TCP socket.
 * Wire format: [4-byte big-endian uint32 payload length][UTF-8 JSON payload]
 */
public class MessageFramer implements Closeable {

    private final DataInputStream in;
    private final DataOutputStream out;
    private final Object writeLock = new Object();

    public MessageFramer(Socket socket) throws IOException {
        this.in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        this.out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
    }

    public MessageFramer(InputStream inputStream, OutputStream outputStream) {
        this.in = new DataInputStream(new BufferedInputStream(inputStream));
        this.out = new DataOutputStream(new BufferedOutputStream(outputStream));
    }

    public void send(String json) throws IOException {
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);
        if (payload.length > ProtocolConstants.MAX_PAYLOAD_BYTES) {
            throw new IOException("Payload exceeds maximum size: " + payload.length + " bytes");
        }
        synchronized (writeLock) {
            out.writeInt(payload.length);
            out.write(payload);
            out.flush();
        }
    }

    public String receive() throws IOException {
        int length = in.readInt();
        if (length < 0 || length > ProtocolConstants.MAX_PAYLOAD_BYTES) {
            throw new IOException("Invalid payload length: " + length);
        }
        byte[] payload = new byte[length];
        in.readFully(payload);
        return new String(payload, StandardCharsets.UTF_8);
    }

    @Override
    public void close() throws IOException {
        in.close();
        out.close();
    }
}
