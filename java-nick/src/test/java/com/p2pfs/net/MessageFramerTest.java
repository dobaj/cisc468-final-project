package com.p2pfs.net;

import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.*;

class MessageFramerTest {

    @Test
    void sendAndReceiveMessage() throws IOException {
        PipedOutputStream pipeOut = new PipedOutputStream();
        PipedInputStream pipeIn = new PipedInputStream(pipeOut, 65536);

        MessageFramer sender = new MessageFramer(new ByteArrayInputStream(new byte[0]), pipeOut);
        MessageFramer receiver = new MessageFramer(pipeIn, new ByteArrayOutputStream());

        String json = "{\"type\":\"HELLO\",\"version\":1}";
        sender.send(json);
        String received = receiver.receive();
        assertEquals(json, received);
    }

    @Test
    void handlesLargePayload() throws IOException {
        PipedOutputStream pipeOut = new PipedOutputStream();
        PipedInputStream pipeIn = new PipedInputStream(pipeOut, 1024 * 1024);

        MessageFramer sender = new MessageFramer(new ByteArrayInputStream(new byte[0]), pipeOut);
        MessageFramer receiver = new MessageFramer(pipeIn, new ByteArrayOutputStream());

        StringBuilder sb = new StringBuilder("{\"data\":\"");
        for (int i = 0; i < 50000; i++) sb.append('A');
        sb.append("\"}");
        String bigJson = sb.toString();

        sender.send(bigJson);
        String received = receiver.receive();
        assertEquals(bigJson, received);
    }

    @Test
    void multipleMessages() throws IOException {
        PipedOutputStream pipeOut = new PipedOutputStream();
        PipedInputStream pipeIn = new PipedInputStream(pipeOut, 65536);

        MessageFramer sender = new MessageFramer(new ByteArrayInputStream(new byte[0]), pipeOut);
        MessageFramer receiver = new MessageFramer(pipeIn, new ByteArrayOutputStream());

        sender.send("{\"type\":\"A\"}");
        sender.send("{\"type\":\"B\"}");
        sender.send("{\"type\":\"C\"}");

        assertEquals("{\"type\":\"A\"}", receiver.receive());
        assertEquals("{\"type\":\"B\"}", receiver.receive());
        assertEquals("{\"type\":\"C\"}", receiver.receive());
    }

    @Test
    void rejectsInvalidLength() {
        byte[] invalidFrame = ByteBuffer.allocate(4).putInt(-1).array();
        InputStream in = new ByteArrayInputStream(invalidFrame);
        MessageFramer framer = new MessageFramer(in, new ByteArrayOutputStream());

        assertThrows(IOException.class, framer::receive);
    }

    @Test
    void handlesUtf8() throws IOException {
        PipedOutputStream pipeOut = new PipedOutputStream();
        PipedInputStream pipeIn = new PipedInputStream(pipeOut, 65536);

        MessageFramer sender = new MessageFramer(new ByteArrayInputStream(new byte[0]), pipeOut);
        MessageFramer receiver = new MessageFramer(pipeIn, new ByteArrayOutputStream());

        String json = "{\"name\":\"日本語テスト\"}";
        sender.send(json);
        assertEquals(json, receiver.receive());
    }
}
