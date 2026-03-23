import argparse
import threading

from cli.commands import command_loop
from crypto.identity import Identity
from discovery.mdns_service import init_mdns
from net.tcp_server import start_server
from protocol.constants import DEFAULT_PORT, DEFAULT_PORTS_BY_NAME
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
    default_port = DEFAULT_PORTS_BY_NAME.get(name, DEFAULT_PORT)
    if args.port is not None:
        port = args.port
    else:
        port_text = clean_text(input(f"Enter port [{default_port}]: "))
        port = int(port_text) if port_text else default_port

    identity = Identity(name, password).load_or_create()
    trust_store = TrustStore(f"data/{name}/truststore.json")
    file_cache = FileListCache()

    mdns = init_mdns(name, port)

    threading.Thread(
        target=start_server,
        args=(identity, port, trust_store, file_cache),
        daemon=True,
    ).start()

    command_loop(identity, mdns, trust_store, file_cache)


if __name__ == "__main__":
    main()
