package com.p2pfs.net;

import java.io.IOException;
import java.net.Socket;

/**
 * TCP client that connects to a remote peer.
 */
public class TcpClient {

    public static Socket connect(String host, int port) throws IOException {
        return new Socket(host, port);
    }
}
