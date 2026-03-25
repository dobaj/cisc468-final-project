import json
import os
from typing import Optional


class TrustStore:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.trusted = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.filepath):
            self.trusted = {}
            return

        with open(self.filepath, "r", encoding="utf-8-sig") as handle:
            raw = json.load(handle)

        self.trusted = {}
        if isinstance(raw, list):
            for entry in raw:
                self.trusted[entry["name"]] = {
                    "fingerprint": entry["fingerprint"],
                    "previous_fingerprints": [],
                    "identity_pub": entry.get("identity_pub"),
                }
            return

        for peer_name, entry in raw.items():
            if isinstance(entry, str):
                self.trusted[peer_name] = {
                    "fingerprint": entry,
                    "previous_fingerprints": [],
                    "identity_pub": None,
                }
            else:
                self.trusted[peer_name] = {
                    "fingerprint": entry["fingerprint"],
                    "previous_fingerprints": entry.get("previous_fingerprints", []),
                    "identity_pub": entry.get("identity_pub"),
                }

    def _save(self):
        directory = os.path.dirname(self.filepath)
        if directory:
            os.makedirs(directory, exist_ok=True)

        with open(self.filepath, "w", encoding="utf-8") as handle:
            json.dump(self.trusted, handle, indent=2, sort_keys=True)

    def add_contact(
        self,
        peer_name: str,
        fingerprint: str,
        identity_pub: Optional[str] = None,
    ):
        self.trusted[peer_name] = {
            "fingerprint": fingerprint,
            "previous_fingerprints": [],
            "identity_pub": identity_pub,
        }
        self._save()

    def remove_contact(self, peer_name: str):
        if peer_name in self.trusted:
            del self.trusted[peer_name]
            self._save()

    def is_trusted(self, peer_name: str, fingerprint: str) -> bool:
        return self.get_fingerprint(peer_name) == fingerprint

    def get_fingerprint(self, peer_name: str):
        entry = self.trusted.get(peer_name)
        if not entry:
            return None
        return entry["fingerprint"]

    def get_identity_pub(self, peer_name: str):
        entry = self.trusted.get(peer_name)
        if not entry:
            return None
        return entry.get("identity_pub")

    def find_name_by_fingerprint(self, fingerprint: str):
        for peer_name, entry in self.trusted.items():
            if entry["fingerprint"] == fingerprint:
                return peer_name
            if fingerprint in entry.get("previous_fingerprints", []):
                return peer_name
        return None

    def rotate_contact_key(
        self,
        peer_name: str,
        new_fingerprint: str,
        identity_pub: Optional[str] = None,
    ):
        current = self.trusted.get(peer_name)
        if current is None:
            self.add_contact(peer_name, new_fingerprint, identity_pub=identity_pub)
            return

        old_fingerprint = current["fingerprint"]
        previous = current.get("previous_fingerprints", [])
        if old_fingerprint and old_fingerprint not in previous:
            previous.append(old_fingerprint)

        self.trusted[peer_name] = {
            "fingerprint": new_fingerprint,
            "previous_fingerprints": previous,
            "identity_pub": identity_pub if identity_pub is not None else current.get("identity_pub"),
        }
        self._save()

    def list_contacts(self):
        return {
            peer_name: entry["fingerprint"]
            for peer_name, entry in self.trusted.items()
        }
