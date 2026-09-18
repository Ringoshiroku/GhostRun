import hashlib
import os
import threading
from collections import defaultdict


def hash_file(path, size_cap_bytes=100_000_000):
    try:
        if os.path.getsize(path) > size_cap_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError, FileNotFoundError):
        return None


class DebouncedHasher:
    """
    groups repeated create/modify events for the same path into one
    hash check, fired debounce_seconds after the last touch.
    """

    def __init__(self, on_settled, debounce_seconds=1.5, size_cap_bytes=100_000_000):
        self.on_settled = on_settled
        self.debounce_seconds = debounce_seconds
        self.size_cap_bytes = size_cap_bytes
        self._timers = {}
        self._lock = threading.Lock()

    def touch(self, path):
        with self._lock:
            existing = self._timers.get(path)
            if existing is not None:
                existing.cancel()
            timer = threading.Timer(self.debounce_seconds, self._settle, args=(path,))
            timer.daemon = True
            self._timers[path] = timer
            timer.start()

    def cancel(self, path):
        with self._lock:
            existing = self._timers.pop(path, None)
            if existing is not None:
                existing.cancel()

    def _settle(self, path):
        with self._lock:
            self._timers.pop(path, None)
        digest = hash_file(path, self.size_cap_bytes)
        self.on_settled(path, digest)


_MASS_CHANGE_THRESHOLD = 3


class RenameExtensionTracker:
    def __init__(self, on_ransomware_pattern):
        self.on_ransomware_pattern = on_ransomware_pattern
        self._counts = defaultdict(int)
        self._fired = set()

    def record_rename(self, old_path, new_path):
        old_ext = os.path.splitext(old_path)[1].lower()
        new_ext = os.path.splitext(new_path)[1].lower()
        if new_ext == old_ext or new_ext == "":
            return

        key = (old_ext, new_ext)
        self._counts[key] += 1
        if self._counts[key] >= _MASS_CHANGE_THRESHOLD and key not in self._fired:
            self._fired.add(key)
            self.on_ransomware_pattern(old_ext, new_ext, self._counts[key])
