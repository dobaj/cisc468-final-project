from crypto.hkdf import derive_key
from crypto.identity import Identity
from crypto.key_exchange import KeyExchange
from crypto.session_cipher import SessionCipher
from net.message_framer import receive_message, send_message
from net.peer_registry import PeerConnection
from protocol.message_types import (
    DATA,
    ERROR,
    FILE_CHUNK,
    FILE_LIST_REQUEST,
    FILE_LIST_RESPONSE,
    FILE_OFFER,
    FILE_OFFER_RESPONSE,
    FILE_REQUEST,
    HELLO,
    KEY_EXCHANGE,
    KEY_MIGRATION,
)
from protocol.messages import (
    decode_payload,
    error_message,
    file_chunk,
    file_list_response,
    file_offer_response,
    hello,
    key_exchange,
)
from sharing.consent_manager import ConsentManager
from sharing.file_manager import FileManager
from storage.encrypted_store import EncryptedStore
from trust.key_migration import verify_migration


def handle_peer(
    sock,
    identity,
    trust_store,
    file_cache,
    is_incoming=False,
    peer_registry=None,
):
    peer_name = None
    connection = None

    try:
        ke = KeyExchange()
        # both peers send first, then derive the same session key from x25519 output.
        send_message(sock, key_exchange(ke.get_public_bytes().hex()))

        msg = receive_message(sock)
        if msg["type"] != KEY_EXCHANGE:
            raise ValueError("Expected key_exchange")

        shared_secret = ke.compute_shared_secret(bytes.fromhex(msg["pub"]))
        cipher = SessionCipher(derive_key(shared_secret))

        send_message(
            sock,
            hello(identity.name, identity.public_key_hex(), identity.fingerprint()),
        )

        msg = receive_message(sock)
        if msg["type"] != HELLO:
            raise ValueError("Expected hello")

        peer_name = msg["name"]
        peer_fingerprint = msg["fingerprint"]
        peer_identity_pub = msg["identity_pub"]
        # trust-on-first-use is only allowed when the user explicitly accepts the fingerprint.
        _authenticate_peer(peer_name, peer_fingerprint, peer_identity_pub, trust_store)

        if peer_registry is None:
            peer_registry = {}

        existing = peer_registry.get(peer_name)
        if existing is not None:
            existing.close()

        connection = PeerConnection(
            peer_name=peer_name,
            sock=sock,
            cipher=cipher,
            fingerprint=peer_fingerprint,
            identity_pub=peer_identity_pub,
        )
        peer_registry[peer_name] = connection

        if is_incoming:
            print(f"Incoming connection from '{peer_name}'")
        print(f"Authenticated with '{peer_name}' ({peer_fingerprint[:16]}...)")

        file_manager = FileManager(f"data/{identity.name}/shared")
        encrypted_store = EncryptedStore(f"data/{identity.name}/store", identity.password)
        consent = ConsentManager()

        while True:
            outer = receive_message(sock)
            if outer["type"] != DATA:
                raise ValueError("Expected encrypted data message")

            inner = _decrypt_inner_message(cipher, outer)
            _handle_inner_message(
                connection,
                inner,
                identity,
                trust_store,
                file_cache,
                file_manager,
                encrypted_store,
                consent,
            )

    except Exception as exc:
        message = str(exc)
        if "10054" not in message and "10053" not in message:
            print(f"Connection error: {exc}")

    finally:
        try:
            sock.close()
        except OSError:
            pass
        if peer_registry is not None and peer_name:
            if peer_registry.get(peer_name) is connection:
                peer_registry.pop(peer_name, None)


def _authenticate_peer(peer_name, fingerprint, identity_pub, trust_store):
    key_bytes = bytes.fromhex(identity_pub)
    derived_fingerprint = _fingerprint(key_bytes)
    if derived_fingerprint != fingerprint:
        raise ValueError("Peer fingerprint does not match provided identity key")

    expected = trust_store.get_fingerprint(peer_name)
    if expected is None:
        consent = ConsentManager()
        if not consent.request_consent(peer_name, "trust", fingerprint):
            raise ValueError("Untrusted peer rejected by user")
        trust_store.add_contact(peer_name, fingerprint)
        print(f"Trusted new contact '{peer_name}'")
        return

    if expected != fingerprint:
        raise ValueError(
            f"Fingerprint mismatch for {peer_name}. Expected {expected}, got {fingerprint}"
        )

    Identity.public_key_from_bytes(key_bytes)


def _decrypt_inner_message(cipher, outer):
    nonce = bytes.fromhex(outer["nonce"])
    ciphertext = bytes.fromhex(outer["payload"])
    plaintext = cipher.decrypt(nonce, ciphertext)
    return decode_payload(plaintext)


def _handle_inner_message(
    connection,
    message,
    identity,
    trust_store,
    file_cache,
    file_manager,
    encrypted_store,
    consent,
):
    msg_type = message["type"]

    if msg_type == FILE_LIST_REQUEST:
        # file list responses carry signed metadata so cached copies can be verified later.
        records = [file_manager.build_file_record(name, identity) for name in file_manager.list_files()]
        connection.send_secure(file_list_response(records))
        return

    if msg_type == FILE_LIST_RESPONSE:
        file_cache.update(connection.peer_name, message["files"])
        if not message["files"]:
            print("No files available")
            return
        print(f"Files from {connection.peer_name}:")
        for record in message["files"]:
            print(f"- {record['filename']} ({record['sha256'][:12]}...)")
        return

    if msg_type == FILE_REQUEST:
        filename = message["filename"]
        if not consent.request_consent(connection.peer_name, "request", filename):
            connection.send_secure(error_message(f"File request rejected for {filename}"))
            return
        try:
            data, record = file_manager.get_shared_file(filename, identity)
        except FileNotFoundError:
            connection.send_secure(error_message(f"File not found: {filename}"))
            return
        connection.send_secure(file_chunk(filename, data.hex(), record))
        print(f"Sent '{filename}' to {connection.peer_name}")
        return

    if msg_type == FILE_OFFER:
        filename = message["filename"]
        if not consent.request_consent(connection.peer_name, "send", filename):
            connection.send_secure(
                file_offer_response(filename, False, "Receiver rejected file offer")
            )
            return
        connection.send_secure(file_offer_response(filename, True))
        print(f"Accepted file offer for '{filename}' from {connection.peer_name}")
        return

    if msg_type == FILE_OFFER_RESPONSE:
        filename = message["filename"]
        if not message["accepted"]:
            print(f"{connection.peer_name} rejected '{filename}': {message['message']}")
            connection.pending_offers.pop(filename, None)
            return

        filepath = connection.pending_offers.pop(filename, None)
        if filepath is None:
            connection.send_secure(error_message(f"No pending file offer for {filename}"))
            return

        # the sender transmits bytes only after the receiver has consented to the offer.
        data, record = file_manager.build_record_for_path(filepath, identity)
        connection.send_secure(file_chunk(filename, data.hex(), record))
        print(f"Sent offered file '{filename}' to {connection.peer_name}")
        return

    if msg_type == FILE_CHUNK:
        filename = message["filename"]
        data = bytes.fromhex(message["data"])
        record = message["record"]
        # storing both plaintext and encrypted copies lets the user share files while still
        # preserving an at-rest protected copy for received data.
        file_manager.save_verified_file(filename, data, record)
        encrypted_store.save_bytes(filename, data)
        print(f"Received and verified '{filename}' from {connection.peer_name}")
        return

    if msg_type == KEY_MIGRATION:
        # migration only succeeds if the old and new identity keys cross-sign each other.
        old_public = Identity.public_key_from_bytes(bytes.fromhex(connection.identity_pub))
        new_public = Identity.public_key_from_bytes(bytes.fromhex(message["new_pub"]))
        verified = verify_migration(
            old_public,
            new_public,
            bytes.fromhex(message["old_sig"]),
            bytes.fromhex(message["new_sig"]),
        )
        if not verified:
            print(f"Rejected key migration from {connection.peer_name}")
            return

        trust_store.rotate_contact_key(connection.peer_name, _fingerprint(bytes.fromhex(message["new_pub"])))
        connection.identity_pub = message["new_pub"]
        connection.fingerprint = _fingerprint(bytes.fromhex(message["new_pub"]))
        print(f"Updated trusted key for {connection.peer_name}")
        return

    if msg_type == ERROR:
        print(f"Operation failed: {message['message']}")
        return

    print(f"Unknown secure message from {connection.peer_name}: {message}")


def _fingerprint(public_key_bytes: bytes) -> str:
    import hashlib

    return hashlib.sha256(public_key_bytes).hexdigest()
