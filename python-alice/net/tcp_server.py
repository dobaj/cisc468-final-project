import socket
import threading
from net.peer_session import handle_peer
from net.peer_registry import active_peers


def start_server(
    identity,
    port,
    trust_store,
    file_cache,
    stop_event=None,
    ready_event=None,
    startup_state=None,
    allow_fallback=False,
):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # allow quick restart
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(0.5)

        selected_port = port
        try:
            server.bind(("0.0.0.0", selected_port))
        except OSError:
            if not allow_fallback:
                raise
            server.bind(("0.0.0.0", 0))
            selected_port = server.getsockname()[1]

        server.listen()

        print(f"Listening on port {selected_port}...")
        if startup_state is not None:
            startup_state["started"] = True
            startup_state["port"] = selected_port
        if ready_event is not None:
            ready_event.set()

        while stop_event is None or not stop_event.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue

            threading.Thread(
                target=handle_peer,
                args=(conn, identity, trust_store, file_cache, True, active_peers),
                daemon=True
            ).start()
    except Exception as exc:
        if startup_state is not None:
            startup_state["error"] = exc
        if ready_event is not None:
            ready_event.set()
        if startup_state is None:
            raise
    finally:
        server.close()
