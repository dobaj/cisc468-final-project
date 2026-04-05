from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import serialization

class KeyExchange:
    def __init__(self):
        self.private = X25519PrivateKey.generate()
        self.public = self.private.public_key()

    def get_public_bytes(self):
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def compute_shared_secret(self, peer_bytes: bytes):
        peer_public = X25519PublicKey.from_public_bytes(peer_bytes)
        return self.private.exchange(peer_public)