package com.p2pfs.discovery;

import com.p2pfs.protocol.ProtocolConstants;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * mDNS-based peer discovery using JmDNS.
 * Registers the local peer and discovers remote peers on the LAN.
 */
public class MdnsService implements Closeable {

    /**
     * @param clientType "java" for Java peers, "native" for Go/Python peers.
     *                   Java peers are detected by the "client=java" TXT record.
     */
    public record PeerInfo(String name, String host, int port, String fingerprint, String clientType) {
        public boolean isJavaPeer() { return "java".equals(clientType); }
    }

    private JmDNS jmdns;
    private final Map<String, PeerInfo> discoveredPeers = new ConcurrentHashMap<>();
    private PeerListener listener;

    public interface PeerListener {
        void onPeerDiscovered(PeerInfo peer);
        void onPeerRemoved(String name);
    }

    public void setPeerListener(PeerListener listener) {
        this.listener = listener;
    }

    /**
     * Starts mDNS, registers this peer, and begins browsing for others.
     */
    public void start(String peerName, int port, String fingerprint) throws IOException {
        jmdns = JmDNS.create(InetAddress.getLocalHost());

        ServiceInfo serviceInfo = ServiceInfo.create(
                ProtocolConstants.MDNS_SERVICE_TYPE,
                peerName,
                port,
                "fingerprint=" + fingerprint + "&version=" + ProtocolConstants.VERSION + "&client=java"
        );
        jmdns.registerService(serviceInfo);

        jmdns.addServiceListener(ProtocolConstants.MDNS_SERVICE_TYPE, new ServiceListener() {
            @Override
            public void serviceAdded(ServiceEvent event) {
                jmdns.requestServiceInfo(event.getType(), event.getName());
            }

            @Override
            public void serviceRemoved(ServiceEvent event) {
                String name = event.getName();
                discoveredPeers.remove(name);
                if (listener != null) {
                    listener.onPeerRemoved(name);
                }
            }

            @Override
            public void serviceResolved(ServiceEvent event) {
                ServiceInfo info = event.getInfo();
                String[] addrs = info.getHostAddresses();
                if (addrs.length == 0) return;

                String fp = info.getPropertyString("fingerprint");
                String client = info.getPropertyString("client");
                String clientType = "java".equals(client) ? "java" : "native";
                PeerInfo peer = new PeerInfo(
                        event.getName(),
                        addrs[0],
                        info.getPort(),
                        fp != null ? fp : "",
                        clientType
                );
                discoveredPeers.put(event.getName(), peer);
                if (listener != null) {
                    listener.onPeerDiscovered(peer);
                }
            }
        });
    }

    public Map<String, PeerInfo> getDiscoveredPeers() {
        return Map.copyOf(discoveredPeers);
    }

    @Override
    public void close() throws IOException {
        if (jmdns != null) {
            jmdns.unregisterAllServices();
            jmdns.close();
        }
    }
}
