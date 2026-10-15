import sys
import types
import hashlib
import shlex

try:
    import wmi
except ImportError:
    # wmi needs pywin32 and only runs on windows
    # not installed here on this dev/test machine
    # so build a fake wmi module with just what we need (x_wmi, x_wmi_timed_out, WMI)
    # register it in sys.modules so every import of wmi anywhere in the process
    # resolves to this same fake instead of retrying a real import that would fail
    # actually connecting still fails loudly, just later, when WMI() is called
    # instead of at import time
    wmi = types.ModuleType("wmi")

    class x_wmi(Exception):
        pass

    class x_wmi_timed_out(x_wmi):
        pass

    def _WMI(**kwargs):
        # accepts **kwargs (unused) so this stub matches persistence_watch.py's stub
        # both modules register their stub via sys.modules.setdefault("wmi", ...)
        # whichever one imports first (process_mon.py, per ghostrun.py's import order)
        # installs the stub the other module's call sites actually use
        # if the signatures ever differed, wmi.WMI(namespace=...) from
        # persistence_watch.py would raise a plain TypeError instead of this
        # intended RuntimeError
        raise RuntimeError(
            "the 'wmi' package (Windows-only, requires pywin32) is not "
            "available on this platform; process monitoring via WMI events "
            "requires Windows"
        )

    wmi.x_wmi = x_wmi
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


def _normalize_cmdline(cmdline_raw):
    """
    always return a list of strings, no matter the source.
    wmi's CommandLine is a single string (or none), psutil's cmdline is already a list.
    downstream code (persistence_detector, timeline_builder, report_builder) does
    " ".join(cmdline) and must never see none or a bare string, joining a string
    joins its characters, not its words.
    """
    if not cmdline_raw:
        return []
    if isinstance(cmdline_raw, list):
        return [str(part) for part in cmdline_raw]
    try:
        return shlex.split(cmdline_raw)
    except ValueError:
        # if the quoting is malformed, shlex raises
        # fall back to a plain split instead of losing the command line
        return cmdline_raw.split()


def _build_process_create_evidence(pid, ppid, name, cmdline_raw, image_path, create_time):
    return {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "cmdline": _normalize_cmdline(cmdline_raw),
        "image_path": image_path,
        "image_sha256": _hash_image(image_path) if image_path else None,
        "create_time": create_time,
    }


def _creation_event_to_evidence(wmi_event):
    image_path = getattr(wmi_event, "ExecutablePath", None)
    return _build_process_create_evidence(
        pid=wmi_event.ProcessId,
        ppid=wmi_event.ParentProcessId,
        name=wmi_event.Name,
        cmdline_raw=getattr(wmi_event, "CommandLine", None),
        image_path=image_path,
        create_time=getattr(wmi_event, "CreationDate", None),
    )


def _deletion_event_to_evidence(wmi_event):
    return {"pid": wmi_event.ProcessId, "name": wmi_event.Name}


def _connect_wmi():
    return wmi.WMI()


class ProcessMonitor:
    def __init__(self, root_pid, emit_func, malware_pids=None):
        self.root_pid = root_pid
        self.emit = emit_func
        self.running = True

        self.parent_map = {}
        self.image_paths = {}  # pid to image path, updated live as descendants appear and exit
        # shared mutable set, same object as ghostrun.py's MALWARE_PIDS global
        # passed by reference, not copied
        # grows as this monitor discovers real descendants
        # that's what lets emit()'s noise filter correctly accept network evidence
        # for a child process instead of dropping it
        self.malware_pids = malware_pids if malware_pids is not None else set()

    def is_descendant(self, pid, root_pid):
        """
        check if pid is a descendant of root_pid.
        guards against a cycle in parent_map (e.g. pid reuse making
        parent_map[a]=b and parent_map[b]=a), which would otherwise loop forever.
        needed because this now gets called with arbitrary system-wide pids from
        the network-attribution path, not just ones already known safe.
        """
        current = pid
        visited = set()
        while current:
            if current == root_pid:
                return True
            if current in visited:
                return False
            visited.add(current)
            current = self.parent_map.get(current)
        return False

    def resolve_path_to_pid(self, path):
        """
        return the one tracked descendant pid whose image path matches `path`.
        returns none if zero or more than one match.
        two live descendants with the same executable path are treated as
        no match on purpose, picking a specific wrong process would be worse.
        """
        matches = [pid for pid, image_path in self.image_paths.items() if image_path == path]
        return matches[0] if len(matches) == 1 else None

    def _poll_creation(self, watcher):
        try:
            event = watcher(timeout_ms=500)
        except wmi.x_wmi_timed_out:
            return
        self.parent_map[event.ProcessId] = event.ParentProcessId
        if self.is_descendant(event.ProcessId, self.root_pid):
            self.malware_pids.add(event.ProcessId)
            self.image_paths[event.ProcessId] = getattr(event, "ExecutablePath", None)
            self.emit("process", "process_create", _creation_event_to_evidence(event))

    def _poll_deletion(self, watcher):
        try:
            event = watcher(timeout_ms=500)
        except wmi.x_wmi_timed_out:
            return
        self.image_paths.pop(event.ProcessId, None)
        if self.is_descendant(event.ProcessId, self.root_pid):
            self.emit("process", "process_terminate", _deletion_event_to_evidence(event))

    def _seed_existing_processes(self):
        """
        backfill lineage for every process already running when we attach the watcher.
        also emit process_create for the root sample and any descendants already running.
        the wmi creation watcher only sees processes created after watch_for("creation")
        is called, so without this, the root sample's own creation, and anything that
        needs to see a process_create first, would never show up.
        """
        import psutil

        for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "exe"]):
            try:
                info = proc.info
                pid = info["pid"]
                ppid = info["ppid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            self.parent_map[pid] = ppid
            if self.is_descendant(pid, self.root_pid):
                self.malware_pids.add(pid)
                image_path = info.get("exe")
                self.image_paths[pid] = image_path
                self.emit("process", "process_create", _build_process_create_evidence(
                    pid=pid,
                    ppid=ppid,
                    name=info.get("name"),
                    cmdline_raw=info.get("cmdline"),
                    image_path=image_path,
                    create_time=None,
                ))

    def run(self):
        self.emit("process", "monitor_start", {
            "root_pid": self.root_pid
        })

        # pywin32/wmi needs com initialized on the current thread before its first
        # com call (wmi.WMI() does this internally)
        # pywin32 only auto-initializes com for the main thread at import time, not
        # for threads created later, and this runs on a worker thread started by
        # ghostrun.py
        # without this, wmi.WMI() raises a com_error and the thread dies immediately
        pythoncom = None
        try:
            import pythoncom
            pythoncom.CoInitialize()
        except ImportError:
            # pythoncom (part of pywin32) isn't installed on this platform
            # (e.g. this non-windows dev/test host), so there's nothing to initialize
            pythoncom = None

        try:
            try:
                conn = _connect_wmi()
                creation_watcher = conn.Win32_Process.watch_for("creation")
                deletion_watcher = conn.Win32_Process.watch_for("deletion")

                self._seed_existing_processes()

                while self.running:
                    self._poll_creation(creation_watcher)
                    self._poll_deletion(deletion_watcher)
            except wmi.x_wmi as exc:
                # covers com errors, rpc failures, or wmi provider restarts, not just a timeout
                # (timeouts are already handled in _poll_creation/_poll_deletion)
                # record this via ghostrun_status (exempt from emit()'s pid filter, so it
                # actually gets recorded) instead of letting the thread die silently with
                # no evidence trail
                self.emit("ghostrun_status", "process_monitor_degraded", {
                    "error": str(exc),
                })
        finally:
            if pythoncom is not None:
                pythoncom.CoUninitialize()
            self.emit("process", "monitor_stop", {})

    def stop(self):
        self.running = False
