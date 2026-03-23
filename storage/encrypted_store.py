import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode("utf-8"))


def generate_salt() -> bytes:
    return os.urandom(16)


class EncryptedStore:
    NONCE_SIZE = 12

    def __init__(self, root: str, password: str):
        self.root = Path(root)
        self.password = password
        self.root.mkdir(parents=True, exist_ok=True)

    def save_bytes(self, relative_path: str, data: bytes):
        path = self._resolve(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        salt = generate_salt()
        key = derive_key(self.password, salt)
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = AESGCM(key).encrypt(nonce, data, None)
        path.write_bytes(salt + nonce + ciphertext)

    def load_bytes(self, relative_path: str) -> bytes:
        path = self._resolve(relative_path)
        raw = path.read_bytes()
        salt = raw[:16]
        nonce = raw[16:16 + self.NONCE_SIZE]
        ciphertext = raw[16 + self.NONCE_SIZE:]
        key = derive_key(self.password, salt)
        return AESGCM(key).decrypt(nonce, ciphertext, None)

    def exists(self, relative_path: str) -> bool:
        return self._resolve(relative_path).exists()

    def _resolve(self, relative_path: str) -> Path:
        path = (self.root / relative_path).resolve()
        root = self.root.resolve()
        if root not in path.parents and path != root:
            raise ValueError("Invalid encrypted store path")
        return path

