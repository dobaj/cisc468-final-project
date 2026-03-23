from net.peer_registry import active_peers
from net.tcp_client import connect_to_peer
from protocol.messages import (
    file_list_request,
    file_offer,
    file_request,
    key_migration,
)
from sharing.file_manager import FileManager
from trust.key_migration import create_migration_message
from utils.text import clean_text


def command_loop(identity, mdns, trust_store, file_cache):
    file_manager = FileManager(f"data/{identity.name}/shared")

    while True:
        cmd = clean_text(input("> "))

        if cmd == "peers":
            if not mdns.peers:
                print("No peers discovered")
            for name, (host, port) in mdns.peers.items():
                print(f"{name} -> {host}:{port}")
            continue

        if cmd.startswith("connect "):
            peer = clean_text(cmd.split(maxsplit=1)[1])
            try:
                connect_to_peer(peer, identity, mdns, trust_store, file_cache)
            except Exception as exc:
                print(f"Failed to connect: {exc}")
            continue

        if cmd.startswith("list "):
            peer = clean_text(cmd.split(maxsplit=1)[1])
            connection = active_peers.get(peer)
            if not connection:
                print("Not connected to that peer")
                continue
            connection.send_secure(file_list_request())
            continue

        if cmd.startswith("request "):
            parts = cmd.split(maxsplit=2)
            if len(parts) < 3:
                print("Usage: request <peer> <filename>")
                continue
            _, peer, filename = parts
            peer = clean_text(peer)
            filename = clean_text(filename)
            connection = active_peers.get(peer)
            if not connection:
                print("Not connected to that peer")
                continue
            connection.send_secure(file_request(filename))
            continue

        if cmd.startswith("send "):
            parts = cmd.split(maxsplit=2)
            if len(parts) < 3:
                print("Usage: send <peer> <filepath>")
                continue
            _, peer, filepath = parts
            peer = clean_text(peer)
            filepath = clean_text(filepath)
            connection = active_peers.get(peer)
            if not connection:
                print("Not connected to that peer")
                continue
            try:
                _, record = file_manager.build_record_for_path(filepath, identity)
            except FileNotFoundError:
                print("File not found")
                continue
            connection.pending_offers[record["filename"]] = filepath
            connection.send_secure(file_offer(record["filename"], record))
            continue

        if cmd == "contacts":
            contacts = trust_store.list_contacts()
            if not contacts:
                print("No trusted contacts")
            for peer_name, fingerprint in contacts.items():
                print(f"{peer_name}: {fingerprint}")
            continue

        if cmd == "migrate":
            old_private_key, new_private_key = identity.rotate_key()
            migration_message = create_migration_message(
                old_private_key,
                new_private_key,
                identity.public_key_hex(),
            )
            for connection in list(active_peers.values()):
                connection.send_secure(
                    key_migration(
                        migration_message["new_pub"],
                        migration_message["old_sig"],
                        migration_message["new_sig"],
                    )
                )
            print("Rotated identity key and notified connected peers")
            continue

        if cmd == "cache":
            if not file_cache.cache:
                print("No cached file lists")
            for peer_name, records in file_cache.cache.items():
                print(f"{peer_name}:")
                for record in records:
                    print(f"  {record['filename']} ({record['sha256'][:12]}...)")
            continue

        if cmd == "exit":
            print("Exiting...")
            break

        print("Unknown command")
