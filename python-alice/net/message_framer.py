import struct
import json


def send_message(sock, msg):
    data = json.dumps(msg).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def receive_message(sock):
    # read length (4 bytes)
    raw_len = _recv_exact(sock, 4)
    length = struct.unpack(">I", raw_len)[0]

    # read full message
    data = _recv_exact(sock, length)
    return json.loads(data.decode())


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed early")
        data += chunk
    return data
