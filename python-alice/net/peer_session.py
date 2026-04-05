import base64
import hashlib
import math
import os
import socket

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

JAVA_AUTH_FAIL = "AUTH_FAIL"
JAVA_AUTH_REQUEST = "AUTH_REQUEST"
JAVA_AUTH_RESPONSE = "AUTH_RESPONSE"
JAVA_AUTH_SUCCESS = "AUTH_SUCCESS"
JAVA_ENCRYPTED = "ENCRYPTED"
JAVA_ERROR = "ERROR"
JAVA_FILE_ACCEPT = "FILE_ACCEPT"
JAVA_FILE_COMPLETE = "FILE_COMPLETE"
JAVA_FILE_DENY = "FILE_DENY"
JAVA_FILE_LIST_REQUEST = "FILE_LIST_REQUEST"
JAVA_FILE_LIST_RESPONSE = "FILE_LIST_RESPONSE"
JAVA_FILE_OFFER = "FILE_OFFER"
JAVA_FILE_OFFER_ACCEPT = "FILE_OFFER_ACCEPT"
JAVA_FILE_OFFER_DENY = "FILE_OFFER_DENY"
JAVA_FILE_REQUEST = "FILE_REQUEST"
JAVA_FILE_TRANSFER = "FILE_TRANSFER"
JAVA_HKDF_INFO = b"p2p-session"
JAVA_KEY_MIGRATION = "KEY_MIGRATION"
JAVA_MAX_CHUNK_BYTES = 1024 * 1024


def handle_peer(
    sock,
    identity,
    trust_store,
    file_cache,
    is_incoming=False,
    peer_registry=None,
    protocol_hint="python",
    expected_peer_name=None,
):
    peer_name = None
    connection = None

    try:
        protocol, peer_name, peer_fingerprint, peer_identity_pub, cipher = _establish_session(
            sock,
            identity,
            trust_store,
            is_incoming,
            protocol_hint,
            expected_peer_name,
        )

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
            protocol=protocol,
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


def _establish_session(
    sock,
    identity,
    trust_store,
    is_incoming,
    protocol_hint,
    expected_peer_name,
):
    if is_incoming:
        return _handshake_incoming(sock, identity, trust_store)
    if protocol_hint == "java":
        return _handshake_java_initiator(
            sock, identity, trust_store, expected_peer_name
        )
    return _handshake_python(sock, identity, trust_store)


def _handshake_incoming(sock, identity, trust_store):
    original_timeout = sock.gettimeout()
    first_message = None
    try:
        sock.settimeout(1.0)
        first_message = receive_message(sock)
    except socket.timeout:
        first_message = None
    finally:
        sock.settimeout(original_timeout)

    if first_message is None:
        return _handshake_python(sock, identity, trust_store)

    msg_type = first_message.get("type")
    if msg_type == KEY_EXCHANGE:
        return _handshake_python(sock, identity, trust_store, first_message=first_message)
    if msg_type == JAVA_AUTH_REQUEST:
        return _handshake_java_responder(
            sock, identity, trust_store, first_message=first_message
        )
    raise ValueError(f"Unsupported handshake start: {msg_type}")


def _handshake_python(sock, identity, trust_store, first_message=None):
    ke = KeyExchange()

    if first_message is None:
        send_message(sock, key_exchange(ke.get_public_bytes().hex()))
        msg = receive_message(sock)
    else:
        msg = first_message
        send_message(sock, key_exchange(ke.get_public_bytes().hex()))

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
    _authenticate_peer(
        peer_name,
        peer_fingerprint,
        peer_identity_pub,
        trust_store,
        wire_identity_pub=peer_identity_pub,
    )

    return "python", peer_name, peer_fingerprint, peer_identity_pub, cipher


def _handshake_java_initiator(sock, identity, trust_store, expected_peer_name):
    nonce_a = os.urandom(32)
    ke = KeyExchange()
    local_public_bytes = identity.get_public_bytes()
    local_ephemeral = ke.get_public_bytes()

    send_message(
        sock,
        {
            "type": JAVA_AUTH_REQUEST,
            "version": 1,
            "identity_pub": _b64(local_public_bytes),
            "ephemeral_pub": _b64(local_ephemeral),
            "nonce": _b64(nonce_a),
        },
    )

    reply = receive_message(sock)
    reply_type = reply.get("type")
    if reply_type == JAVA_AUTH_FAIL:
        raise ValueError(reply.get("reason", "Java peer rejected authentication"))
    if reply_type != JAVA_AUTH_RESPONSE:
        raise ValueError(f"Expected AUTH_RESPONSE, got {reply_type}")

    remote_public_bytes = _unb64(reply["identity_pub"])
    remote_ephemeral = _unb64(reply["ephemeral_pub"])
    nonce_b = _unb64(reply["nonce"])
    signature_b = _unb64(reply["signature"])

    _verify_signature(
        remote_public_bytes,
        nonce_a + local_ephemeral + remote_ephemeral,
        signature_b,
        "Responder signature verification failed",
    )

    peer_identity_pub = remote_public_bytes.hex()
    peer_fingerprint = _fingerprint(remote_public_bytes)
    peer_name = (
        expected_peer_name
        or trust_store.find_name_by_fingerprint(peer_fingerprint)
        or f"peer-{peer_fingerprint[:8]}"
    )
    _authenticate_peer(
        peer_name,
        peer_fingerprint,
        peer_identity_pub,
        trust_store,
        wire_identity_pub=reply["identity_pub"],
    )

    signature_a = identity.sign(nonce_b + remote_ephemeral + local_ephemeral)
    send_message(
        sock,
        {
            "type": JAVA_AUTH_SUCCESS,
            "signature": _b64(signature_a),
        },
    )

    shared_secret = ke.compute_shared_secret(remote_ephemeral)
    cipher = SessionCipher(
        derive_key(shared_secret, salt=nonce_a + nonce_b, info=JAVA_HKDF_INFO)
    )
    return "java", peer_name, peer_fingerprint, peer_identity_pub, cipher


def _handshake_java_responder(sock, identity, trust_store, first_message):
    remote_public_bytes = _unb64(first_message["identity_pub"])
    remote_ephemeral = _unb64(first_message["ephemeral_pub"])
    nonce_a = _unb64(first_message["nonce"])

    peer_identity_pub = remote_public_bytes.hex()
    peer_fingerprint = _fingerprint(remote_public_bytes)
    peer_name = (
        trust_store.find_name_by_fingerprint(peer_fingerprint)
        or f"peer-{peer_fingerprint[:8]}"
    )
    _authenticate_peer(
        peer_name,
        peer_fingerprint,
        peer_identity_pub,
        trust_store,
        wire_identity_pub=first_message["identity_pub"],
    )

    nonce_b = os.urandom(32)
    ke = KeyExchange()
    local_ephemeral = ke.get_public_bytes()
    signature_b = identity.sign(nonce_a + remote_ephemeral + local_ephemeral)

    send_message(
        sock,
        {
            "type": JAVA_AUTH_RESPONSE,
            "version": 1,
            "identity_pub": _b64(identity.get_public_bytes()),
            "ephemeral_pub": _b64(local_ephemeral),
            "nonce": _b64(nonce_b),
            "signature": _b64(signature_b),
        },
    )

    auth = receive_message(sock)
    auth_type = auth.get("type")
    if auth_type == JAVA_AUTH_FAIL:
        raise ValueError(auth.get("reason", "Java peer rejected authentication"))
    if auth_type != JAVA_AUTH_SUCCESS:
        raise ValueError(f"Expected AUTH_SUCCESS, got {auth_type}")

    signature_a = _unb64(auth["signature"])
    _verify_signature(
        remote_public_bytes,
        nonce_b + local_ephemeral + remote_ephemeral,
        signature_a,
        "Initiator signature verification failed",
    )

    shared_secret = ke.compute_shared_secret(remote_ephemeral)
    cipher = SessionCipher(
        derive_key(shared_secret, salt=nonce_a + nonce_b, info=JAVA_HKDF_INFO)
    )
    return "java", peer_name, peer_fingerprint, peer_identity_pub, cipher


def _authenticate_peer(
    peer_name,
    fingerprint,
    identity_pub,
    trust_store,
    wire_identity_pub=None,
):
    key_bytes = bytes.fromhex(identity_pub)
    derived_fingerprint = _fingerprint(key_bytes)
    if derived_fingerprint != fingerprint:
        raise ValueError("Peer fingerprint does not match provided identity key")

    expected = trust_store.get_fingerprint(peer_name)
    if expected is None:
        consent = ConsentManager()
        if not consent.request_consent(peer_name, "trust", fingerprint):
            raise ValueError("Untrusted peer rejected by user")
        trust_store.add_contact(
            peer_name,
            fingerprint,
            identity_pub=wire_identity_pub or identity_pub,
        )
        print(f"Trusted new contact '{peer_name}'")
        return

    if expected != fingerprint:
        raise ValueError(
            f"Fingerprint mismatch for {peer_name}. Expected {expected}, got {fingerprint}"
        )

    Identity.public_key_from_bytes(key_bytes)


def _decrypt_inner_message(cipher, outer):
    if outer["type"] == DATA:
        nonce = bytes.fromhex(outer["nonce"])
        ciphertext = bytes.fromhex(outer["payload"])
    elif outer["type"] == JAVA_ENCRYPTED:
        nonce = _unb64(outer["iv"])
        ciphertext = _unb64(outer["ciphertext"])
    else:
        raise ValueError(f"Expected encrypted message, got {outer['type']}")

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

    if msg_type in (FILE_LIST_REQUEST, JAVA_FILE_LIST_REQUEST):
        records = file_manager.list_file_records(identity)
        if msg_type == JAVA_FILE_LIST_REQUEST:
            connection.send_secure(
                {
                    "type": JAVA_FILE_LIST_RESPONSE,
                    "files": [
                        {
                            "name": record["filename"],
                            "size": record["size"],
                            "hash": record["sha256"],
                            "origin": _b64(bytes.fromhex(record["owner_pub"])),
                        }
                        for record in records
                    ],
                }
            )
        else:
            connection.send_secure(file_list_response(records))
        return

    if msg_type in (FILE_LIST_RESPONSE, JAVA_FILE_LIST_RESPONSE):
        records = (
            message["files"]
            if msg_type == FILE_LIST_RESPONSE
            else _normalize_java_file_list(message["files"], connection)
        )
        file_cache.update(connection.peer_name, records)
        if not records:
            print("No files available")
            return
        print(f"Files from {connection.peer_name}:")
        for record in records:
            print(f"- {record['filename']} ({record['sha256'][:12]}...)")
        return

    if msg_type in (FILE_REQUEST, JAVA_FILE_REQUEST):
        filename = message.get("filename") or message.get("name")
        if not consent.request_consent(connection.peer_name, "request", filename):
            if msg_type == JAVA_FILE_REQUEST:
                connection.send_secure(
                    {
                        "type": JAVA_FILE_DENY,
                        "hash": message.get("hash", ""),
                        "reason": f"File request rejected for {filename}",
                    }
                )
            else:
                connection.send_secure(error_message(f"File request rejected for {filename}"))
            return

        try:
            data, record = file_manager.get_shared_file(filename, identity)
        except FileNotFoundError:
            if msg_type == JAVA_FILE_REQUEST:
                connection.send_secure(
                    {
                        "type": JAVA_ERROR,
                        "code": "FILE_NOT_FOUND",
                        "message": f"File not found: {filename}",
                    }
                )
            else:
                connection.send_secure(error_message(f"File not found: {filename}"))
            return

        if msg_type == JAVA_FILE_REQUEST:
            requested_hash = message.get("hash")
            if requested_hash and requested_hash != record["sha256"]:
                connection.send_secure(
                    {
                        "type": JAVA_ERROR,
                        "code": "HASH_MISMATCH",
                        "message": f"Requested hash does not match {filename}",
                    }
                )
                return
            connection.send_secure(
                {
                    "type": JAVA_FILE_ACCEPT,
                    "hash": record["sha256"],
                }
            )
            _send_java_file(connection, record["sha256"], data)
        else:
            connection.send_secure(file_chunk(filename, data.hex(), record))

        print(f"Sent '{filename}' to {connection.peer_name}")
        return

    if msg_type in (FILE_OFFER, JAVA_FILE_OFFER):
        filename = message.get("filename") or message.get("name")
        if not consent.request_consent(connection.peer_name, "send", filename):
            if msg_type == JAVA_FILE_OFFER:
                connection.send_secure(
                    {
                        "type": JAVA_FILE_OFFER_DENY,
                        "hash": message["hash"],
                    }
                )
            else:
                connection.send_secure(
                    file_offer_response(
                        filename, False, "Receiver rejected file offer"
                    )
                )
            return

        if msg_type == JAVA_FILE_OFFER:
            connection.pending_downloads[message["hash"]] = {
                "filename": filename,
                "expected_hash": message["hash"],
                "origin_pub": connection.identity_pub,
                "chunks": {},
                "total_chunks": None,
            }
            connection.send_secure(
                {
                    "type": JAVA_FILE_OFFER_ACCEPT,
                    "hash": message["hash"],
                }
            )
        else:
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

        data, record = file_manager.build_record_for_path(filepath, identity)
        connection.send_secure(file_chunk(filename, data.hex(), record))
        print(f"Sent offered file '{filename}' to {connection.peer_name}")
        return

    if msg_type == JAVA_FILE_OFFER_ACCEPT:
        hash_value = message["hash"]
        filepath = connection.pending_offers_by_hash.pop(hash_value, None)
        if filepath is None:
            connection.send_secure(
                {
                    "type": JAVA_ERROR,
                    "code": "NO_PENDING_FILE",
                    "message": f"No pending file offer for hash {hash_value}",
                }
            )
            return

        filename = os.path.basename(filepath)
        connection.pending_offers.pop(filename, None)
        data, record = file_manager.build_record_for_path(filepath, identity)
        _send_java_file(connection, record["sha256"], data)
        print(f"Sent offered file '{filename}' to {connection.peer_name}")
        return

    if msg_type == JAVA_FILE_OFFER_DENY:
        hash_value = message["hash"]
        filepath = connection.pending_offers_by_hash.pop(hash_value, None)
        if filepath is not None:
            connection.pending_offers.pop(os.path.basename(filepath), None)
        print(f"{connection.peer_name} rejected the offered file")
        return

    if msg_type == FILE_CHUNK:
        filename = message["filename"]
        data = bytes.fromhex(message["data"])
        record = message["record"]
        file_manager.save_verified_file(filename, data, record)
        encrypted_store.save_bytes(filename, data)
        print(f"Received and verified '{filename}' from {connection.peer_name}")
        return

    if msg_type == JAVA_FILE_ACCEPT:
        return

    if msg_type == JAVA_FILE_DENY:
        print(f"Operation failed: {message.get('reason', 'File request rejected')}")
        return

    if msg_type == JAVA_FILE_TRANSFER:
        transfer = connection.pending_downloads.setdefault(
            message["hash"],
            {
                "filename": message["hash"],
                "expected_hash": message["hash"],
                "origin_pub": connection.identity_pub,
                "chunks": {},
                "total_chunks": None,
            },
        )
        transfer["chunks"][message["chunk_index"]] = _unb64(message["data"])
        transfer["total_chunks"] = message["total_chunks"]
        return

    if msg_type == JAVA_FILE_COMPLETE:
        transfer = connection.pending_downloads.pop(message["hash"], None)
        if transfer is None:
            print(f"Operation failed: Missing transfer state for {message['hash']}")
            return
        _finalize_java_download(
            connection, transfer, file_manager, encrypted_store
        )
        return

    if msg_type in (KEY_MIGRATION, JAVA_KEY_MIGRATION):
        if msg_type == KEY_MIGRATION:
            old_public = Identity.public_key_from_bytes(
                bytes.fromhex(connection.identity_pub)
            )
            new_public_bytes = bytes.fromhex(message["new_pub"])
            new_public = Identity.public_key_from_bytes(new_public_bytes)
            verified = verify_migration(
                old_public,
                new_public,
                bytes.fromhex(message["old_sig"]),
                bytes.fromhex(message["new_sig"]),
            )
            new_wire_identity = message["new_pub"]
        else:
            old_public = Identity.public_key_from_bytes(
                bytes.fromhex(connection.identity_pub)
            )
            new_public_bytes = _unb64(message["new_identity_pub"])
            new_public = Identity.public_key_from_bytes(new_public_bytes)
            verified = verify_migration(
                old_public,
                new_public,
                _unb64(message["signature_old"]),
                _unb64(message["signature_new"]),
            )
            new_wire_identity = message["new_identity_pub"]

        if not verified:
            print(f"Rejected key migration from {connection.peer_name}")
            return

        trust_store.rotate_contact_key(
            connection.peer_name,
            _fingerprint(new_public_bytes),
            identity_pub=new_wire_identity,
        )
        connection.identity_pub = new_public_bytes.hex()
        connection.fingerprint = _fingerprint(new_public_bytes)
        print(f"Updated trusted key for {connection.peer_name}")
        return

    if msg_type in (ERROR, JAVA_ERROR):
        print(f"Operation failed: {message['message']}")
        return

    print(f"Unknown secure message from {connection.peer_name}: {message}")


def _normalize_java_file_list(files, connection):
    records = []
    for entry in files:
        owner_pub_bytes = _unb64(entry["origin"])
        records.append(
            {
                "owner": connection.peer_name,
                "owner_pub": owner_pub_bytes.hex(),
                "filename": entry["name"],
                "sha256": entry["hash"],
                "size": entry["size"],
                "signature": "",
            }
        )
    return records


def _send_java_file(connection, hash_value, data):
    total_chunks = max(1, math.ceil(len(data) / JAVA_MAX_CHUNK_BYTES))
    for index in range(total_chunks):
        start = index * JAVA_MAX_CHUNK_BYTES
        chunk = data[start : start + JAVA_MAX_CHUNK_BYTES]
        connection.send_secure(
            {
                "type": JAVA_FILE_TRANSFER,
                "hash": hash_value,
                "chunk_index": index,
                "total_chunks": total_chunks,
                "data": _b64(chunk),
            }
        )
    connection.send_secure(
        {
            "type": JAVA_FILE_COMPLETE,
            "hash": hash_value,
        }
    )


def _finalize_java_download(connection, transfer, file_manager, encrypted_store):
    total_chunks = transfer.get("total_chunks")
    chunks = transfer.get("chunks", {})
    if total_chunks is None:
        print("Operation failed: Transfer did not include a chunk count")
        return

    data = b"".join(chunks[index] for index in range(total_chunks) if index in chunks)
    if len(chunks) != total_chunks:
        print("Operation failed: Missing file chunks during Java transfer")
        return

    expected_hash = transfer.get("expected_hash")
    actual_hash = hashlib.sha256(data).hexdigest()
    if expected_hash and actual_hash != expected_hash:
        print(
            f"Operation failed: File hash mismatch for {transfer['filename']}"
        )
        return

    file_manager.save_file(transfer["filename"], data)
    encrypted_store.save_bytes(transfer["filename"], data)
    print(f"Received and verified '{transfer['filename']}' from {connection.peer_name}")


def _verify_signature(public_key_bytes, payload, signature, message):
    try:
        Identity.public_key_from_bytes(public_key_bytes).verify(signature, payload)
    except Exception as exc:  # cryptography raises multiple verify exception types
        raise ValueError(message) from exc


def _fingerprint(public_key_bytes: bytes) -> str:
    return hashlib.sha256(public_key_bytes).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))
