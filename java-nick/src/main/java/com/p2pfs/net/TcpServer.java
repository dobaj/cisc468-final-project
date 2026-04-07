package com.p2pfs.net;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

// accepts connections and dispatches each socket to a handler thread
public class TcpServer implements AutoCloseable {

    private final ServerSocket serverSocket;
    private final ExecutorService executor;
    private volatile boolean running;

    public TcpServer(int port) throws IOException {
        this.serverSocket = new ServerSocket(port);
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
    }

    public int getPort() {
        return serverSocket.getLocalPort();
    }

    // blocks until closed; each incoming socket is handed off to handler
    public void accept(Consumer<Socket> handler) {
        running = true;
        while (running) {
            try {
                Socket client = serverSocket.accept();
                executor.submit(() -> handler.accept(client));
            } catch (IOException e) {
                if (running) {
                    System.err.println("[TcpServer] Accept error: " + e.getMessage());
                }
            }
        }
    }

    public void acceptAsync(Consumer<Socket> handler) {
        Thread acceptThread = new Thread(() -> accept(handler));
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    @Override
    public void close() throws IOException {
        running = false;
        serverSocket.close();
        executor.shutdownNow();
    }
}
