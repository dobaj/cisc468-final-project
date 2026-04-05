import os

from cli.console import get_console


class ConsentManager:
    def request_consent(self, peer_name: str, action: str, filename: str = "") -> bool:
        # automated tests can preload yes/no answers here to avoid stdin races.
        queued = self._consume_queued_response()
        if queued is not None:
            return queued

        if action == "send":
            prompt = f"{peer_name} wants to send you '{filename}'. Allow? (y/n): "
        elif action == "request":
            prompt = f"{peer_name} is requesting file '{filename}'. Allow? (y/n): "
        elif action == "trust":
            prompt = f"Trust peer '{peer_name}' with fingerprint {filename}? (y/n): "
        else:
            prompt = f"{peer_name} wants to {action}. Allow? (y/n): "

        console = get_console()
        while True:
            if console is not None:
                response = console.request_confirmation(prompt).strip().lower()
            else:
                response = input(prompt).strip().lower()
            if response in ("y", "yes"):
                return True
            if response in ("n", "no"):
                return False
            print("Please enter 'y' or 'n'.")

    def _consume_queued_response(self):
        queue_path = os.environ.get("P2P_CONSENT_QUEUE")
        if not queue_path or not os.path.exists(queue_path):
            return None

        with open(queue_path, "r", encoding="utf-8-sig") as handle:
            responses = [line.strip().lower() for line in handle.readlines() if line.strip()]

        if not responses:
            return None

        first = responses[0]
        with open(queue_path, "w", encoding="utf-8") as handle:
            remaining = responses[1:]
            if remaining:
                handle.write("\n".join(remaining) + "\n")

        if first in ("y", "yes"):
            return True
        if first in ("n", "no"):
            return False
        return None
