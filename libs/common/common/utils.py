from threading import Lock


class ThreadSafeCounter:
    def __init__(self):
        self._value = 0
        self._lock = Lock()

    def increment(self):
        with self._lock:
            self._value += 1
            return self._value

    @property
    def value(self):
        with self._lock:
            return self._value
