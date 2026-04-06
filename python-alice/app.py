import argparse
import threading

from cli.console import init_console, shutdown_console
from cli.commands import command_loop
from crypto.identity import Identity
from discovery.mdns_service import init_mdns
from net.tcp_server import start_server
from sharing.file_cache import FileListCache
from trust.trust_store import TrustStore
from utils.text import clean_text


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--name")
    parser.add_argument("--password")
    parser.add_argument("--port", type=int)
    args, _ = parser.parse_known_args()

    name = clean_text(args.name) if args.name else clean_text(input("Enter name: "))
    password = clean_text(args.password) if args.password else clean_text(input("Enter passphrase: "))
    preferred_port = args.port if args.port is not None else 0

    identity = Identity(name, password).load_or_create()
    trust_store = TrustStore(f"data/{name}/truststore.json")
    file_cache = FileListCache()
    init_console()

    stop_event = threading.Event()
    server_ready = threading.Event()
    startup_state = {}
    server_thread = threading.Thread(
        target=start_server,
        args=(
            identity,
            preferred_port,
            trust_store,
            file_cache,
            stop_event,
            server_ready,
            startup_state,
            True,
        ),
    )
    server_thread.start()
    server_ready.wait()
    if "error" in startup_state:
        raise startup_state["error"]
    port = startup_state["port"]

    mdns = init_mdns(name, port)

    try:
        command_loop(identity, mdns, trust_store, file_cache)
    finally:
        stop_event.set()
        shutdown_console()
        mdns.close()
        server_thread.join(timeout=1.0)


if __name__ == "__main__":
    main()
