import socket
import threading

from net.peer_registry import active_peers
from net.peer_session import handle_peer


def connect_to_peer(peer_name: str, identity, mdns, trust_store, file_cache):
    if peer_name in active_peers:
        print("Already connected")
        return

    host, port = mdns.resolve_peer(peer_name)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"Connected to {peer_name}")

    threading.Thread(
        target=handle_peer,
        args=(sock, identity, trust_store, file_cache, False, active_peers),
        daemon=True,
    ).start()
