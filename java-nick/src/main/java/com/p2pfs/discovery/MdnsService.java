package com.p2pfs.discovery;

import com.p2pfs.protocol.ProtocolConstants;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;
import java.io.Closeable;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// mDNS peer discovery; registers locally and browses for others on the LAN
public class MdnsService implements Closeable {

    // clientType is "java" or "native", detected via the TXT record "client=java"
    public record PeerInfo(String name, String host, int port, String fingerprint, String clientType) {
        public boolean isJavaPeer() { return "java".equals(clientType); }
    }

    private JmDNS jmdns;
    private final Map<String, PeerInfo> discoveredPeers = new ConcurrentHashMap<>();
    private PeerListener listener;
    private String localName;
    private String localFingerprint;

    public interface PeerListener {
        void onPeerDiscovered(PeerInfo peer);
        void onPeerRemoved(String name);
    }

    public void setPeerListener(PeerListener listener) {
        this.listener = listener;
    }

    public void start(String peerName, int port, String fingerprint) throws IOException {
        this.localName = peerName;
        this.localFingerprint = fingerprint;
        // UDP connect to 8.8.8.8 tricks the OS into revealing the outbound interface without sending packets
        InetAddress localAddr;
        try (DatagramSocket probe = new DatagramSocket()) {
            probe.connect(InetAddress.getByName("8.8.8.8"), 80);
            localAddr = probe.getLocalAddress();
        } catch (Exception e) {
            localAddr = InetAddress.getLocalHost();
        }
        jmdns = JmDNS.create(localAddr);

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

                // skip our own reflected advertisement (by name, or fingerprint if TXT has resolved)
                if (localName.equals(event.getName())) return;

                String fp = info.getPropertyString("fingerprint");
                if (localFingerprint != null && localFingerprint.equals(fp)) return;
                String client = info.getPropertyString("client");
                String clientType = "java".equals(client) ? "java" : "native";
                PeerInfo peer = new PeerInfo(
                        event.getName(),
                        addrs[0],
                        info.getPort(),
                        fp != null ? fp : "",
                        clientType
                );

                PeerInfo existing = discoveredPeers.put(event.getName(), peer);
                if (listener != null && !peer.equals(existing)) {
                    listener.onPeerDiscovered(peer);
                }
            }
        });
    }

    public Map<String, PeerInfo> getDiscoveredPeers() {
        return Map.copyOf(discoveredPeers);
    }

    // bypass mDNS, inject a peer directly (used in tests for cross-client connections)
    public void injectPeer(PeerInfo peer) {
        discoveredPeers.put(peer.name(), peer);
    }

    @Override
    public void close() throws IOException {
        if (jmdns != null) {
            jmdns.unregisterAllServices();
            jmdns.close();
        }
    }
}
