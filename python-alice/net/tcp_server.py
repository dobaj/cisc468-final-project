import socket
import threading
from net.peer_session import handle_peer
from net.peer_registry import active_peers


def start_server(identity, port, trust_store, file_cache):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # allow quick restart
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind(("0.0.0.0", port))
    server.listen()

    print(f"Listening on port {port}...")

    while True:
        conn, addr = server.accept()

        threading.Thread(
            target=handle_peer,
            args=(conn, identity, trust_store, file_cache, True, active_peers),
            daemon=True
        ).start()
