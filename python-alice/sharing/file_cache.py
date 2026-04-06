class FileListCache:
    def __init__(self):
        self.cache = {}

    def update(self, peer_name: str, records: list):
        self.cache[peer_name] = records

    def get(self, peer_name: str):
        return self.cache.get(peer_name, [])

    def find_record(self, filename: str):
        for peer_name, records in self.cache.items():
            for record in records:
                if record.get("filename") == filename:
                    return peer_name, record
        return None, None

    def has(self, peer_name: str) -> bool:
        return peer_name in self.cache

    def clear(self, peer_name: str):
        if peer_name in self.cache:
            del self.cache[peer_name]
