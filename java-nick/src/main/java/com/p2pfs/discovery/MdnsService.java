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

    public record PeerInfo(String name, String host, int port, String fingerprint) {}

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

    /**
     * Starts mDNS, registers this peer, and begins browsing for others.
     */
    public void start(String peerName, int port, String fingerprint) throws IOException {
        this.localName = peerName;
        this.localFingerprint = fingerprint;
        jmdns = JmDNS.create(InetAddress.getLocalHost());

        ServiceInfo serviceInfo = ServiceInfo.create(
                ProtocolConstants.MDNS_SERVICE_TYPE,
                peerName,
                port,
                "fingerprint=" + fingerprint + "&version=" + ProtocolConstants.VERSION
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

                // Skip our own advertisement — mDNS reflects it back to us.
                // Filter by name (always available) and also by fingerprint (available
                // once TXT records resolve) to catch both resolution events.
                if (localName.equals(event.getName())) return;

                String fp = info.getPropertyString("fingerprint");
                if (localFingerprint != null && localFingerprint.equals(fp)) return;

                PeerInfo peer = new PeerInfo(
                        event.getName(),
                        addrs[0],
                        info.getPort(),
                        fp != null ? fp : ""
                );

                // Only notify when a peer is genuinely new or its info has changed
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

    @Override
    public void close() throws IOException {
        if (jmdns != null) {
            jmdns.unregisterAllServices();
            jmdns.close();
        }
    }
}
