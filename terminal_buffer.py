"""Bounded human-only byte stream, independent of model-visible job output."""
import threading


class TerminalBuffer:
    def __init__(self, limit=1048576):
        self.lock = threading.Lock()
        self.limit = limit
        self.data = b''
        self.end = 0

    def append(self, data):
        with self.lock:
            self.end += len(data)
            self.data = (self.data + data)[-self.limit:]

    def since(self, cursor):
        with self.lock:
            start = self.end - len(self.data)
            reset = cursor < start or cursor > self.end
            cursor = start if reset else cursor
            return self.end, self.data[cursor - start:], reset
