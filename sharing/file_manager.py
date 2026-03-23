import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from crypto.identity import Identity


class FileManager:
    def __init__(self, directory: str):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def list_files(self):
        return sorted(
            f.name for f in self.dir.iterdir()
            if f.is_file() and not f.name.endswith(".meta.json")
        )

    def get_file_path(self, filename: str) -> str:
        return str(self._path(filename))

    def read_file(self, filename: str) -> bytes:
        return self._path(filename).read_bytes()

    def save_file(self, filename: str, data: bytes):
        self._path(filename).write_bytes(data)

    def hash_file(self, filename: str) -> str:
        return self._hash_bytes(self.read_file(filename))

    def build_file_record(self, filename: str, identity) -> dict:
        return self.build_record_for_bytes(filename, self.read_file(filename), identity)

    def build_record_for_path(self, filepath: str, identity) -> tuple[bytes, dict]:
        path = Path(filepath)
        data = path.read_bytes()
        return data, self.build_record_for_bytes(path.name, data, identity)

    def build_record_for_bytes(self, filename: str, data: bytes, identity) -> dict:
        sha256 = self._hash_bytes(data)
        payload = self._record_payload(identity.name, filename, sha256, len(data))
        signature = identity.sign(payload).hex()
        return {
            "owner": identity.name,
            "owner_pub": identity.public_key_hex(),
            "filename": filename,
            "sha256": sha256,
            "size": len(data),
            "signature": signature,
        }

    def get_shared_file(self, filename: str, identity) -> tuple[bytes, dict]:
        data = self.read_file(filename)
        metadata = self.load_metadata(filename)
        if metadata is None:
            metadata = self.build_file_record(filename, identity)
        return data, metadata

    def load_metadata(self, filename: str):
        metadata_path = self._metadata_path(filename)
        if not metadata_path.exists():
            return None
        return json.loads(metadata_path.read_text(encoding="utf-8"))

    def save_verified_file(self, filename: str, data: bytes, record: dict):
        # never persist a relayed or received file until the owner metadata verifies.
        self.verify_file_record(record, data)
        self.save_file(filename, data)
        self._metadata_path(filename).write_text(
            json.dumps(record, indent=2),
            encoding="utf-8",
        )

    @staticmethod
    def verify_file_record(record: dict, data: bytes) -> bool:
        expected_hash = FileManager._hash_bytes(data)
        if record["sha256"] != expected_hash:
            raise ValueError("File hash mismatch")

        payload = FileManager._record_payload(
            record["owner"],
            record["filename"],
            record["sha256"],
            record["size"],
        )
        public_key = Identity.public_key_from_bytes(bytes.fromhex(record["owner_pub"]))

        try:
            public_key.verify(bytes.fromhex(record["signature"]), payload)
        except InvalidSignature as exc:
            raise ValueError("File signature verification failed") from exc

        if record["size"] != len(data):
            raise ValueError("File size mismatch")

        return True

    @staticmethod
    def _record_payload(owner: str, filename: str, sha256: str, size: int) -> bytes:
        payload = {
            "filename": filename,
            "owner": owner,
            "sha256": sha256,
            "size": size,
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @staticmethod
    def _hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _metadata_path(self, filename: str) -> Path:
        return self._path(f"{filename}.meta.json")

    def _path(self, filename: str) -> Path:
        name = os.path.basename(filename)
        path = self.dir / name
        return path
