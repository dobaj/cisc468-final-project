import queue
import threading


class ConsoleManager:
    def __init__(self):
        self._lines = queue.Queue()
        self._prompts = queue.Queue()
        self._input_started = False
        self._print_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._input_thread = None

    def start(self):
        if self._input_started:
            return
        self._input_started = True
        self._input_thread = threading.Thread(target=self._input_loop, daemon=True)
        self._input_thread.start()

    def read_command(self) -> str:
        self._show_prompt("> ")
        while not self._stop_event.is_set():
            prompt_request = self._next_prompt_request()
            if prompt_request is not None:
                prompt, response_queue = prompt_request
                with self._print_lock:
                    print("", flush=True)
                response_queue.put(self._blocking_read_line(prompt))
                self._show_prompt("> ")
                continue

            line = self._try_read_line()
            if line is not None:
                return line

        return "exit"

    def request_confirmation(self, prompt: str) -> str:
        response_queue = queue.Queue(maxsize=1)
        self._prompts.put((prompt, response_queue))
        return response_queue.get()

    def print_message(self, message: str):
        with self._print_lock:
            print(message, flush=True)

    def _next_prompt_request(self):
        try:
            return self._prompts.get_nowait()
        except queue.Empty:
            return None

    def _show_prompt(self, prompt: str):
        with self._print_lock:
            print(prompt, end="", flush=True)

    def _blocking_read_line(self, prompt: str) -> str:
        self._show_prompt(prompt)
        return self._lines.get()

    def _try_read_line(self):
        try:
            return self._lines.get(timeout=0.1)
        except queue.Empty:
            return None

    def _input_loop(self):
        while not self._stop_event.is_set():
            try:
                line = input()
            except EOFError:
                line = "exit"
            self._lines.put(line)
            if line == "exit":
                self._stop_event.set()
                break

    def shutdown(self):
        self._stop_event.set()


console_manager = None


def init_console():
    global console_manager
    if console_manager is None:
        console_manager = ConsoleManager()
        console_manager.start()
    return console_manager


def get_console():
    return console_manager


def shutdown_console():
    if console_manager is not None:
        console_manager.shutdown()
