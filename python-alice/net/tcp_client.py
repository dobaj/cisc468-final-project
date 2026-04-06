import socket
import threading
import time

from net.peer_registry import active_peers
from net.peer_session import handle_peer


def connect_to_peer(peer_name: str, identity, mdns, trust_store, file_cache):
    if peer_name in active_peers:
        print("Already connected")
        return

    peer_info = (
        mdns.resolve_peer_info(peer_name)
        if hasattr(mdns, "resolve_peer_info")
        else {
            "host": mdns.resolve_peer(peer_name)[0],
            "port": mdns.resolve_peer(peer_name)[1],
            "protocol_hint": "python",
        }
    )
    host, port = peer_info["host"], peer_info["port"]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"Connected to {peer_name}")

    threading.Thread(
        target=handle_peer,
        args=(
            sock,
            identity,
            trust_store,
            file_cache,
            False,
            active_peers,
            peer_info.get("protocol_hint", "python"),
            peer_name,
        ),
        daemon=True,
    ).start()

    announced_wait = False
    deadline = time.time() + 30.0
    while time.time() < deadline:
        connection = active_peers.get(peer_name)
        if connection is not None:
            return
        if not announced_wait and time.time() + 1.0 < deadline:
            print(f"Waiting for authentication with {peer_name}...")
            announced_wait = True
        time.sleep(0.05)

    print(f"Authentication with {peer_name} is still pending")
