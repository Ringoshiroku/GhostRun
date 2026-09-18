import hashlib
import os
import threading
from collections import defaultdict

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


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


class _Handler(FileSystemEventHandler):
    def __init__(self, root_name, emit, hasher, rename_tracker, root_pid):
        self.root_name = root_name
        self.emit = emit
        self.hasher = hasher
        self.rename_tracker = rename_tracker
        self.root_pid = root_pid

    def on_created(self, event):
        if event.is_directory:
            return
        self.emit("filesystem_behavior", "file_created", {
            "root": self.root_name, "path": event.src_path, "pid": self.root_pid,
        })
        self.hasher.touch(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self.hasher.touch(event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self.hasher.cancel(event.src_path)
        self.emit("filesystem_behavior", "file_deleted", {
            "root": self.root_name, "path": event.src_path, "pid": self.root_pid,
        })

    def on_moved(self, event):
        if event.is_directory:
            return
        self.emit("filesystem_behavior", "file_renamed", {
            "root": self.root_name, "old_path": event.src_path, "new_path": event.dest_path,
            "pid": self.root_pid,
        })
        self.rename_tracker.record_rename(event.src_path, event.dest_path)


class FilesystemWatcher:
    def __init__(self, targets, emit_func, debounce_seconds=1.5, size_cap_bytes=100_000_000, root_pid=None):
        self.targets = targets
        self.emit = emit_func
        self.root_pid = root_pid
        self._observer = Observer()

        self.hasher = DebouncedHasher(
            on_settled=self._on_hash_settled,
            debounce_seconds=debounce_seconds,
            size_cap_bytes=size_cap_bytes,
        )
        self.rename_tracker = RenameExtensionTracker(on_ransomware_pattern=self._on_ransomware_pattern)

        for root_name, root_path in targets.items():
            if not root_path or not os.path.isdir(root_path):
                continue
            handler = _Handler(root_name, self.emit, self.hasher, self.rename_tracker, self.root_pid)
            self._observer.schedule(handler, root_path, recursive=True)

    def _on_hash_settled(self, path, digest):
        if digest is not None:
            self.emit("filesystem_behavior", "file_content_hashed", {
                "path": path, "sha256": digest, "pid": self.root_pid,
            })

    def _on_ransomware_pattern(self, old_ext, new_ext, count):
        self.emit("filesystem_behavior", "mass_extension_change", {
            "from_ext": old_ext, "to_ext": new_ext, "affected_files": count,
            "note": "Pattern consistent with ransomware-style file encryption behavior.",
            "pid": self.root_pid,
        })

    def start(self):
        self._observer.start()

    def stop(self):
        self._observer.stop()
        self._observer.join(timeout=5)
