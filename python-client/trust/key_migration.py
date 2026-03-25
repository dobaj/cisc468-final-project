from cryptography.hazmat.primitives import serialization


def _public_bytes(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def create_migration_message(old_private_key, new_private_key, new_public_hex: str):
    new_pub_bytes = bytes.fromhex(new_public_hex)
    old_pub_bytes = _public_bytes(old_private_key.public_key())

    old_signature = old_private_key.sign(new_pub_bytes)
    new_signature = new_private_key.sign(old_pub_bytes)

    return {
        "type": "key_migration",
        "new_pub": new_public_hex,
        "old_sig": old_signature.hex(),
        "new_sig": new_signature.hex(),
    }


def verify_migration(old_public_key, new_public_key, old_sig: bytes, new_sig: bytes) -> bool:
    try:
        old_public_key.verify(old_sig, _public_bytes(new_public_key))
        new_public_key.verify(new_sig, _public_bytes(old_public_key))
        return True
    except Exception:
        return False

