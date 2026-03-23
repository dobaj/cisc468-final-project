import json
import os


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
        for peer_name, entry in raw.items():
            if isinstance(entry, str):
                self.trusted[peer_name] = {
                    "fingerprint": entry,
                    "previous_fingerprints": [],
                }
            else:
                self.trusted[peer_name] = {
                    "fingerprint": entry["fingerprint"],
                    "previous_fingerprints": entry.get("previous_fingerprints", []),
                }

    def _save(self):
        directory = os.path.dirname(self.filepath)
        if directory:
            os.makedirs(directory, exist_ok=True)

        with open(self.filepath, "w", encoding="utf-8") as handle:
            json.dump(self.trusted, handle, indent=2, sort_keys=True)

    def add_contact(self, peer_name: str, fingerprint: str):
        self.trusted[peer_name] = {
            "fingerprint": fingerprint,
            "previous_fingerprints": [],
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

    def rotate_contact_key(self, peer_name: str, new_fingerprint: str):
        current = self.trusted.get(peer_name)
        if current is None:
            self.add_contact(peer_name, new_fingerprint)
            return

        old_fingerprint = current["fingerprint"]
        previous = current.get("previous_fingerprints", [])
        if old_fingerprint and old_fingerprint not in previous:
            previous.append(old_fingerprint)

        self.trusted[peer_name] = {
            "fingerprint": new_fingerprint,
            "previous_fingerprints": previous,
        }
        self._save()

    def list_contacts(self):
        return {
            peer_name: entry["fingerprint"]
            for peer_name, entry in self.trusted.items()
        }
