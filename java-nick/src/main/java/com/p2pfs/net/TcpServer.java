package com.p2pfs.net;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * TCP server that listens for incoming peer connections.
 * Each accepted connection is handed off to a consumer on a separate thread.
 */
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

    /**
     * Starts accepting connections. Each accepted socket is passed to the handler.
     * This method blocks until the server is closed.
     */
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

    /**
     * Starts accepting in a background thread.
     */
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
