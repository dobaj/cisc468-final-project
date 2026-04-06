import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class Identity:
    def __init__(self, name, password, base_dir="data"):
        self.name = name
        self.password = password
        self.base_dir = Path(base_dir)
        self.private_key = None
        self.public_key = None
        self.identity_dir = self.base_dir / self.name
        self.private_key_path = self.identity_dir / "identity.pem"

    def load_or_create(self):
        self.identity_dir.mkdir(parents=True, exist_ok=True)

        if self.private_key_path.exists():
            pem_bytes = self.private_key_path.read_bytes()
            self.private_key = serialization.load_pem_private_key(
                pem_bytes,
                password=self.password.encode("utf-8"),
            )
        else:
            self.private_key = Ed25519PrivateKey.generate()
            pem_bytes = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    self.password.encode("utf-8")
                ),
            )
            self.private_key_path.write_bytes(pem_bytes)

        self.public_key = self.private_key.public_key()
        return self

    def sign(self, data: bytes):
        return self.private_key.sign(data)

    def verify(self, signature: bytes, data: bytes):
        self.public_key.verify(signature, data)

    def get_public_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_hex(self):
        return self.get_public_bytes().hex()

    def fingerprint(self):
        return hashlib.sha256(self.get_public_bytes()).hexdigest()

    def rotate_key(self):
        old_private_key = self.private_key
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        pem_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                self.password.encode("utf-8")
            ),
        )
        self.private_key_path.write_bytes(pem_bytes)
        return old_private_key, self.private_key

    @staticmethod
    def public_key_from_bytes(public_key_bytes: bytes):
        return Ed25519PublicKey.from_public_bytes(public_key_bytes)
