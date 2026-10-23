import hashlib
import os
import threading
from collections import defaultdict

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from yara_scan import YaraScanError, match_rules

# the filesystem-watch API (watchdog/ReadDirectoryChangesW) never exposes
# which process actually wrote a file, unlike network capture's
# connection-table correlation (see network_watch.py's
# _PID_ATTRIBUTION_NOTE/_RESOLVED_PID_NOTE). root_pid below is always a
# capture-wide guess, never a resolved fact, for every monitored root.
# that's an acceptable, unhedged simplifying assumption for a root scoped
# to the one analysis user's own profile (TEMP, APPDATA, etc.), where the
# sample is normally the dominant writer during a short monitoring window.
# it broke live for WINDOWS_TEMP: a real run captured an OS-created-then-
# deleted OProcSessId.dat (hash of an empty file) and a diagnostic .log,
# neither written by the sample, reported as a confident Dropped File IOC
# just because they landed under a root the sample's PID happened to be
# watching. these roots are written to by system/service-level processes
# regardless of which user is logged in, so file events there carry an
# explicit attribution_confidence hedge instead.
_SHARED_SYSTEM_ROOTS = {"WINDOWS_TEMP", "PROGRAMDATA"}


def _attribution_fields(root):
    if root in _SHARED_SYSTEM_ROOTS:
        return {"attribution_confidence": "unknown"}
    return {}


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
        root = self.watcher._root_for_path(event.src_path)
        self.emit("filesystem_behavior", "file_created", {
            "root": root, "path": event.src_path, "pid": self.root_pid,
            **_attribution_fields(root),
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
    def __init__(self, targets, emit_func, debounce_seconds=1.5, size_cap_bytes=100_000_000, root_pid=None,
                 yara_rules=None):
        self.targets = targets
        self.emit = emit_func
        self.root_pid = root_pid
        # an already-compiled yara.Rules object (yara_scan.load_yara_rules),
        # resolved and compiled by the caller before the sample launches.
        # never done here: resolving can prompt and git clone, and
        # compiling a large ruleset takes seconds, neither of which
        # belongs mid-detonation or per dropped file. None means no YARA
        # scanning this run. shared read-only across the debounce timer
        # threads, which yara.Rules.match() supports.
        self.yara_rules = yara_rules
        self._observer = Observer()

        self.hasher = DebouncedHasher(
            on_settled=self._on_hash_settled,
            debounce_seconds=debounce_seconds,
            size_cap_bytes=size_cap_bytes,
        )
        self.rename_tracker = RenameExtensionTracker(on_ransomware_pattern=self._on_ransomware_pattern)

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
        root = self._root_for_path(path)
        if digest is not None:
            self.emit("filesystem_behavior", "file_content_hashed", {
                "path": path, "sha256": digest, "pid": self.root_pid,
                "root": root,
                **_attribution_fields(root),
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
                "pid": self.root_pid, "root": root,
                **_attribution_fields(root),
            })

    def _scan_and_emit_yara_matches(self, path):
        if self.yara_rules is None:
            return
        try:
            matches = match_rules(self.yara_rules, path)
        except (YaraScanError, OSError):
            # e.g. a self-deleting dropper removed the file between
            # settling and this scan. must not crash monitoring.
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
