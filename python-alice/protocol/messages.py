import json

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
    KEY_CONFIRM,
    KEY_EXCHANGE,
    KEY_MIGRATION,
)


def key_exchange(pub_hex: str):
    return {
        "type": KEY_EXCHANGE,
        "pub": pub_hex,
    }


def hello(
    name: str,
    identity_pub_hex: str,
    fingerprint: str,
    signature_hex: str = "",
):
    message = {
        "type": HELLO,
        "name": name,
        "identity_pub": identity_pub_hex,
        "fingerprint": fingerprint,
    }
    if signature_hex:
        message["signature"] = signature_hex
    return message


def data_message(nonce_hex: str, payload_hex: str):
    return {
        "type": DATA,
        "nonce": nonce_hex,
        "payload": payload_hex,
    }


def key_confirm(echoed_identity_pub_hex: str, signer_identity_pub_hex: str, signature_hex: str):
    return {
        "type": KEY_CONFIRM,
        "echoed_identity_pub": echoed_identity_pub_hex,
        "signer_identity_pub": signer_identity_pub_hex,
        "signature": signature_hex,
    }


def file_list_request():
    return {"type": FILE_LIST_REQUEST}


def file_list_response(files: list):
    return {
        "type": FILE_LIST_RESPONSE,
        "files": files,
    }


def file_request(filename: str):
    return {
        "type": FILE_REQUEST,
        "filename": filename,
    }


def file_offer(filename: str, record: dict):
    return {
        "type": FILE_OFFER,
        "filename": filename,
        "record": record,
    }


def file_offer_response(filename: str, accepted: bool, message: str = ""):
    return {
        "type": FILE_OFFER_RESPONSE,
        "filename": filename,
        "accepted": accepted,
        "message": message,
    }


def file_chunk(filename: str, data_hex: str, record: dict, done: bool = True):
    return {
        "type": FILE_CHUNK,
        "filename": filename,
        "data": data_hex,
        "record": record,
        "done": done,
    }


def key_migration(new_pub: str, old_sig: str, new_sig: str):
    return {
        "type": KEY_MIGRATION,
        "new_pub": new_pub,
        "old_sig": old_sig,
        "new_sig": new_sig,
    }


def error_message(message: str):
    return {
        "type": ERROR,
        "message": message,
    }


def encode_payload(message: dict) -> bytes:
    return json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")


def decode_payload(payload: bytes) -> dict:
    return json.loads(payload.decode("utf-8"))
