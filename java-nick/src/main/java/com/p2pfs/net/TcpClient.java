package com.p2pfs.net;

import java.io.IOException;
import java.net.Socket;

// thin wrapper, opens a TCP connection to a remote peer
public class TcpClient {

    public static Socket connect(String host, int port) throws IOException {
        return new Socket(host, port);
    }
}
