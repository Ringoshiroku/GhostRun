import hashlib
import os
import threading
from collections import defaultdict

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from yara_scan import YaraScanError, resolve_yara_rules_dir, scan_file


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

    def cancel_all(self):
        with self._lock:
            for timer in self._timers.values():
                timer.cancel()
            self._timers.clear()

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
    def __init__(self, watcher, emit, hasher, rename_tracker, root_pid):
        self.watcher = watcher
        self.emit = emit
        self.hasher = hasher
        self.rename_tracker = rename_tracker
        self.root_pid = root_pid

    def on_created(self, event):
        if event.is_directory:
            return
        self.emit("filesystem_behavior", "file_created", {
            "root": self.watcher._root_for_path(event.src_path), "path": event.src_path, "pid": self.root_pid,
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
            "root": self.watcher._root_for_path(event.src_path), "path": event.src_path, "pid": self.root_pid,
        })

    def on_moved(self, event):
        if event.is_directory:
            return
        self.emit("filesystem_behavior", "file_renamed", {
            "root": self.watcher._root_for_path(event.src_path), "old_path": event.src_path, "new_path": event.dest_path,
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

        # lazy, cached rules-dir resolution: resolved on the first scan
        # attempt, not here, so an interactive fetch prompt, if any,
        # only ever appears once per run, not once per dropped file.
        # locked because watchdog's debounce timers settle on separate
        # threads, so several dropped files can hit the first scan
        # attempt at the same time.
        self._yara_rules_dir = None
        self._yara_rules_resolved = False
        self._yara_lock = threading.Lock()

        handler = _Handler(self, self.emit, self.hasher, self.rename_tracker, self.root_pid)

        # watchdog's recursive=True already covers everything under a
        # scheduled target. a target nested inside another configured
        # target (e.g. STARTUP inside APPDATA) would otherwise get its
        # events delivered twice, once per matching schedule. so only
        # schedule the outermost targets. self.targets still keeps every
        # entry, nested ones included, so _root_for_path can attribute
        # events to the most specific root.
        valid = {
            root_name: os.path.normpath(root_path)
            for root_name, root_path in targets.items()
            if root_path and os.path.isdir(root_path)
        }
        for root_name, norm_path in valid.items():
            nested = any(
                other_name != root_name and self._is_nested_under(norm_path, other_norm)
                for other_name, other_norm in valid.items()
            )
            if nested:
                continue
            self._observer.schedule(handler, targets[root_name], recursive=True)

    @staticmethod
    def _is_nested_under(inner_path, outer_path):
        """true if inner_path is a proper subdirectory of outer_path
        (case-insensitive match, same rule _root_for_path uses).
        equal paths do not count as nested.
        """
        if os.path.normcase(inner_path) == os.path.normcase(outer_path):
            return False
        try:
            common = os.path.commonpath([inner_path, outer_path])
        except ValueError:
            return False
        return os.path.normcase(common) == os.path.normcase(outer_path)

    def _root_for_path(self, path):
        """
        best-effort match of a bare path back to whichever configured
        target root it falls under. targets can nest or overlap (e.g.
        STARTUP inside APPDATA), so the most specific, longest matching
        root path wins. returns None when no configured root contains
        the path.
        """
        if not path:
            return None
        norm_path = os.path.normpath(path)
        best_root = None
        best_len = -1
        for root_name, root_path in self.targets.items():
            if not root_path:
                continue
            norm_root = os.path.normpath(root_path)
            try:
                common = os.path.commonpath([norm_path, norm_root])
            except ValueError:
                # e.g. paths on different drives on windows.
                continue
            if os.path.normcase(common) == os.path.normcase(norm_root) and len(norm_root) > best_len:
                best_len = len(norm_root)
                best_root = root_name
        return best_root

    def _on_hash_settled(self, path, digest):
        if digest is not None:
            self.emit("filesystem_behavior", "file_content_hashed", {
                "path": path, "sha256": digest, "pid": self.root_pid,
                "root": self._root_for_path(path),
            })
            self._scan_and_emit_yara_matches(path)
            return

        # hash_file returns None both for a missing/unreadable file and
        # for a file over size_cap_bytes, but the two mean different
        # things. a missing file already has its own file_deleted event,
        # so staying silent there is fine. an over-cap file otherwise
        # leaves no evidence that hashing was even attempted, so check
        # the file's current size to tell the cases apart, and emit an
        # explicit, hash-less record for the over-cap case.
        try:
            over_cap = os.path.getsize(path) > self.hasher.size_cap_bytes
        except OSError:
            over_cap = False

        if over_cap:
            self.emit("filesystem_behavior", "file_content_hashed", {
                "path": path, "sha256": None, "reason": "size_cap_exceeded",
                "pid": self.root_pid, "root": self._root_for_path(path),
            })

    def _resolve_yara_rules_dir_once(self):
        with self._yara_lock:
            if not self._yara_rules_resolved:
                self._yara_rules_dir = resolve_yara_rules_dir()
                self._yara_rules_resolved = True
            return self._yara_rules_dir

    def _scan_and_emit_yara_matches(self, path):
        rules_dir = self._resolve_yara_rules_dir_once()
        if rules_dir is None:
            return
        try:
            matches = scan_file(path, rules_dir)
        except (YaraScanError, OSError, ImportError):
            # ImportError means yara-python isn't installed. scan_file's
            # `import yara` is deferred inside the function so this module
            # stays importable without it, so that failure shows up here,
            # not at import time. must degrade like every other
            # optional-tool-missing case, not crash monitoring.
            return
        for match in matches:
            self.emit("filesystem_behavior", "yara_match", {
                "path": path, "rule": match["rule"], "tags": match["tags"],
                "matches": match["matches"], "pid": self.root_pid,
            })

    def _on_ransomware_pattern(self, old_ext, new_ext, count):
        self.emit("filesystem_behavior", "mass_extension_change", {
            "from_ext": old_ext, "to_ext": new_ext, "affected_files": count,
            "note": "Pattern consistent with ransomware-style file encryption behavior.",
            "pid": self.root_pid,
            # RenameExtensionTracker aggregates renames across all targets, and
            # its on_ransomware_pattern callback carries no path, so no single
            # root can be named here. use explicit None, not a missing key, so
            # later code can tell "ambiguous/aggregate" from "forgotten".
            "root": None,
        })

    def start(self):
        self._observer.start()

    def stop(self):
        self._observer.stop()
        if self._observer.is_alive():
            self._observer.join(timeout=5)
        self.hasher.cancel_all()
