import sys
import types
import hashlib

try:
    import wmi
except ImportError:
    # wmi needs pywin32 and only runs on windows
    # not installed here on this dev/test machine
    # so build a fake wmi module with just what we need (x_wmi_timed_out, WMI)
    # register it in sys.modules so every import of wmi anywhere in the process
    # resolves to this same fake instead of retrying a real import that would fail
    # actually connecting still fails loudly, just later, when WMI() is called
    # instead of at import time
    wmi = types.ModuleType("wmi")

    class x_wmi_timed_out(Exception):
        pass

    def _WMI():
        raise RuntimeError(
            "the 'wmi' package (Windows-only, requires pywin32) is not "
            "available on this platform; process monitoring via WMI events "
            "requires Windows"
        )

    wmi.x_wmi_timed_out = x_wmi_timed_out
    wmi.WMI = _WMI
    sys.modules.setdefault("wmi", wmi)

_HASH_CACHE = {}


def _hash_image(path):
    if not path:
        return None

    if path in _HASH_CACHE:
        return _HASH_CACHE[path]

    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
    except OSError:
        return None

    _HASH_CACHE[path] = digest
    return digest


def _creation_event_to_evidence(wmi_event):
    image_path = getattr(wmi_event, "ExecutablePath", None)
    return {
        "pid": wmi_event.ProcessId,
        "ppid": wmi_event.ParentProcessId,
        "name": wmi_event.Name,
        "cmdline": wmi_event.CommandLine,
        "image_path": image_path,
        "image_sha256": _hash_image(image_path) if image_path else None,
    }


def _deletion_event_to_evidence(wmi_event):
    return {"pid": wmi_event.ProcessId, "name": wmi_event.Name}


def _connect_wmi():
    return wmi.WMI()


class ProcessMonitor:
    def __init__(self, root_pid, emit_func):
        self.root_pid = root_pid
        self.emit = emit_func
        self.running = True

        self.parent_map = {}

    def is_descendant(self, pid, root_pid):
        """
        Check if pid is descendant of root_pid
        """
        current = pid
        while current:
            if current == root_pid:
                return True
            current = self.parent_map.get(current)
        return False

    def _poll_creation(self, watcher):
        try:
            event = watcher(timeout_ms=500)
        except wmi.x_wmi_timed_out:
            return
        self.parent_map[event.ProcessId] = event.ParentProcessId
        if self.is_descendant(event.ProcessId, self.root_pid):
            self.emit("process", "process_create", _creation_event_to_evidence(event))

    def _poll_deletion(self, watcher):
        try:
            event = watcher(timeout_ms=500)
        except wmi.x_wmi_timed_out:
            return
        if self.is_descendant(event.ProcessId, self.root_pid):
            self.emit("process", "process_terminate", _deletion_event_to_evidence(event))

    def run(self):
        self.emit("process", "monitor_start", {
            "root_pid": self.root_pid
        })

        conn = _connect_wmi()
        creation_watcher = conn.Win32_Process.watch_for("creation")
        deletion_watcher = conn.Win32_Process.watch_for("deletion")

        while self.running:
            self._poll_creation(creation_watcher)
            self._poll_deletion(deletion_watcher)

        self.emit("process", "monitor_stop", {})

    def stop(self):
        self.running = False
