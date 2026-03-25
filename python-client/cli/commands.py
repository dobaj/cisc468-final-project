import base64

from cli.console import get_console
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
    console = get_console()
    file_manager = FileManager(f"data/{identity.name}/shared")

    while True:
        if console is not None:
            cmd = clean_text(console.read_command())
        else:
            cmd = clean_text(input("> "))
        if not cmd:
            continue

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
            if connection.protocol == "java":
                connection.send_secure({"type": "FILE_LIST_REQUEST"})
            else:
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
            if connection.protocol == "java":
                _, record = file_cache.find_record(filename)
                if record is None or record.get("owner") != peer:
                    records = file_cache.get(peer)
                    record = next(
                        (item for item in records if item.get("filename") == filename),
                        None,
                    )
                if record is None:
                    print("Run 'list <peer>' first so Python knows the Java file hash")
                    continue
                connection.pending_downloads[record["sha256"]] = {
                    "filename": filename,
                    "expected_hash": record["sha256"],
                    "origin_pub": record.get("owner_pub"),
                    "chunks": {},
                    "total_chunks": None,
                }
                connection.send_secure(
                    {
                        "type": "FILE_REQUEST",
                        "name": filename,
                        "hash": record["sha256"],
                    }
                )
            else:
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
            if connection.protocol == "java":
                connection.pending_offers_by_hash[record["sha256"]] = filepath
                connection.send_secure(
                    {
                        "type": "FILE_OFFER",
                        "name": record["filename"],
                        "size": record["size"],
                        "hash": record["sha256"],
                    }
                )
            else:
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
                if connection.protocol == "java":
                    connection.send_secure(
                        {
                            "type": "KEY_MIGRATION",
                            "new_identity_pub": base64.b64encode(
                                bytes.fromhex(migration_message["new_pub"])
                            ).decode("ascii"),
                            "signature_old": base64.b64encode(
                                bytes.fromhex(migration_message["old_sig"])
                            ).decode("ascii"),
                            "signature_new": base64.b64encode(
                                bytes.fromhex(migration_message["new_sig"])
                            ).decode("ascii"),
                        }
                    )
                else:
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
