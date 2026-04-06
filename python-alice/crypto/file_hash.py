import hashlib


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(filepath: str) -> str:
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()