"""Serialize compound state/index updates in the threaded reference engine."""
from functools import wraps


def locked(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return call
