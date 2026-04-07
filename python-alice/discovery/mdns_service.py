import socket
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
from protocol.constants import SERVICE_TYPE
from utils.text import clean_text


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def _decode_mdns_value(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


class MdnsService:
    def __init__(self, name: str, port: int):
        self.zeroconf = Zeroconf()
        self.name = name
        self.port = port

        self.type = SERVICE_TYPE
        self.service_name = f"{name}.{self.type}"

        self.peers = {}
        self.peer_details = {}

    def register(self):
        local_ip = get_local_ip()

        info = ServiceInfo(
            self.type,
            self.service_name,
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
        )

        self.zeroconf.register_service(info)
        print(f"mDNS registered ({local_ip}:{self.port})")

    def discover(self):
        ServiceBrowser(self.zeroconf, self.type, handlers=[self.on_service_state_change])

    def on_service_state_change(self, zeroconf, service_type, name, state_change):
        if not name.endswith(self.type):
            return

        peer_name = clean_text(name.replace("." + self.type, ""))

        # ignore self
        if peer_name == self.name:
            return

        info = zeroconf.get_service_info(service_type, name)
        if info and info.addresses:
            ip = socket.inet_ntoa(info.addresses[0])
            port = info.port
            props = {
                _decode_mdns_value(key): _decode_mdns_value(value)
                for key, value in info.properties.items()
            }
            protocol_hint = (
                "java" if props.get("fingerprint") or props.get("version") else "python"
            )

            # Only print if new peer
            if peer_name not in self.peers:
                print(f"Discovered {peer_name} ({ip}:{port})")

            self.peers[peer_name] = (ip, port)
            self.peer_details[peer_name] = {
                "host": ip,
                "port": port,
                "properties": props,
                "protocol_hint": protocol_hint,
            }

    def resolve_peer(self, peer_name: str):
        if peer_name not in self.peers:
            raise Exception(f"Peer '{peer_name}' not found")
        return self.peers[peer_name]

    def resolve_peer_info(self, peer_name: str):
        if peer_name not in self.peer_details:
            raise Exception(f"Peer '{peer_name}' not found")
        return self.peer_details[peer_name]

    def close(self):
        self.zeroconf.close()


mdns_service_instance = None


def init_mdns(name: str, port: int):
    global mdns_service_instance
    mdns_service_instance = MdnsService(name, port)
    mdns_service_instance.register()
    mdns_service_instance.discover()
    return mdns_service_instance
