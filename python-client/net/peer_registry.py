import threading

from net.message_framer import send_message
from protocol.messages import data_message, encode_payload


class PeerConnection:
    def __init__(self, peer_name, sock, cipher, fingerprint, identity_pub):
        self.peer_name = peer_name
        self.sock = sock
        self.cipher = cipher
        self.fingerprint = fingerprint
        self.identity_pub = identity_pub
        self.pending_offers = {}
        self.lock = threading.Lock()

    def send_secure(self, inner_message: dict):
        # all post-handshake traffic is wrapped in aes-gcm before it hits the wire.
        payload = encode_payload(inner_message)
        nonce, ciphertext = self.cipher.encrypt(payload)
        with self.lock:
            send_message(self.sock, data_message(nonce.hex(), ciphertext.hex()))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


active_peers = {}
