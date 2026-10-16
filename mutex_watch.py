import ctypes
import os
import threading
from ctypes import wintypes

from rules_loader import load_rule_file


def diff_mutexes(before, after):
    return sorted(
        name for name, obj_type in after.items()
        if obj_type == "Mutant" and before.get(name) != "Mutant"
    )


class _UNICODE_STRING(ctypes.Structure):
    # Buffer is ctypes.c_void_p on purpose, not wintypes.LPWSTR
    # LPWSTR auto-converts to a python str by scanning for a NUL terminator
    # that happens before our own bounded ctypes.wstring_at read ever runs
    # NT UNICODE_STRING isn't guaranteed NUL-terminated, that's why it has a Length field
    # these names are attacker-influenced, so an unbounded auto-read is unsafe
    # c_void_p keeps Buffer a raw address ctypes won't touch
    # so wstring_at's explicit length bound is the only read that happens
    _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT),
                ("Buffer", ctypes.c_void_p)]


class _OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
                ("ObjectName", ctypes.POINTER(_UNICODE_STRING)), ("Attributes", wintypes.ULONG),
                ("SecurityDescriptor", ctypes.c_void_p), ("SecurityQualityOfService", ctypes.c_void_p)]


class _OBJECT_DIRECTORY_INFORMATION(ctypes.Structure):
    # not in an official microsoft header, just documented by convention
    # see sysinternals WinObj and process hacker / system informer's ntdll headers
    # NtQueryDirectoryObject fills the buffer with a run of these entries
    # ends at an entry whose Name.Length is 0
    _fields_ = [("Name", _UNICODE_STRING), ("TypeName", _UNICODE_STRING)]


# STATUS_MORE_ENTRIES: buffer filled, more entries remain
# call again with the same context to continue
# it's a success-severity status (positive), so signed/unsigned compare the same
_STATUS_MORE_ENTRIES = 0x00000105


def list_named_objects(directory_path=r"\BaseNamedObjects"):
    """
    enumerates an nt kernel object directory (default \\BaseNamedObjects,
    where named mutexes/events/semaphores live) via NtQueryDirectoryObject.
    returns {} on any failure, including on a non-windows host (where
    ctypes.WinDLL doesn't even exist), instead of raising, since this
    touches undocumented low-level windows internals.
    """
    try:
        ntdll = ctypes.WinDLL("ntdll")
        # without an explicit restype, ctypes defaults the return value to signed c_int
        # that's not always enough to sign-extend a true 32-bit NTSTATUS correctly
        # pin it to c_long so negative/error statuses compare correctly below
        ntdll.NtQueryDirectoryObject.restype = ctypes.c_long

        name_buf = ctypes.create_unicode_buffer(directory_path)
        name = _UNICODE_STRING(
            len(directory_path) * 2, len(directory_path) * 2 + 2,
            ctypes.addressof(name_buf),
        )
        attrs = _OBJECT_ATTRIBUTES()
        attrs.Length = ctypes.sizeof(_OBJECT_ATTRIBUTES)
        attrs.ObjectName = ctypes.pointer(name)

        handle = wintypes.HANDLE()
        status = ntdll.NtOpenDirectoryObject(ctypes.byref(handle), 0x0001, ctypes.byref(attrs))
        if status != 0:
            return {}

        results = {}
        try:
            context = wintypes.ULONG(0)
            buf_size = 65536
            buf = ctypes.create_string_buffer(buf_size)
            restart_scan = True
            entry_size = ctypes.sizeof(_OBJECT_DIRECTORY_INFORMATION)

            while True:
                returned = wintypes.ULONG(0)
                status = ntdll.NtQueryDirectoryObject(
                    handle, buf, buf_size, False, restart_scan,
                    ctypes.byref(context), ctypes.byref(returned),
                )
                restart_scan = False

                if status == 0 or status == _STATUS_MORE_ENTRIES:
                    # parse whatever batch is already in the buffer before deciding to stop
                    # bounded by how many whole entries the returned byte count can hold
                    # this is defense in depth alongside the empty-name terminator check below
                    # in case a batch exactly fills the buffer with no terminating entry
                    entries = ctypes.cast(buf, ctypes.POINTER(_OBJECT_DIRECTORY_INFORMATION))
                    max_entries = returned.value // entry_size
                    i = 0
                    while i < max_entries:
                        entry = entries[i]
                        if entry.Name.Length == 0:
                            break  # empty entry marks the end of this batch
                        obj_name = ctypes.wstring_at(entry.Name.Buffer, entry.Name.Length // 2)
                        obj_type = ctypes.wstring_at(entry.TypeName.Buffer, entry.TypeName.Length // 2)
                        results[obj_name] = obj_type
                        i += 1

                if status == _STATUS_MORE_ENTRIES:
                    continue  # more data than fit in this buffer, call again
                break  # success with no more data, or a negative/error status
                       # includes STATUS_NO_MORE_ENTRIES (0x8000001A), negative when read as signed
                       # stop either way, nothing left to parse
        finally:
            ntdll.NtClose(handle)

        return results
    except Exception:
        return {}


def _get_current_session_id():
    """
    returns the current process's terminal services session id via
    ProcessIdToSessionId, or None on any failure (non-windows host,
    missing kernel32, or the call itself failing). matches this
    codebase's degrade-gracefully convention for windows-only calls.
    """
    try:
        session_id = wintypes.DWORD()
        if not ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session_id)):
            return None
        return session_id.value
    except Exception:
        return None


def _merge_named_object_dicts(dicts_with_sources):
    """
    pure merge logic. combines multiple (source_directory, {name: type})
    enumerations into one name->type dict (the shape diff_mutexes expects)
    plus a parallel name->source_directory dict, so a caller can tell
    which directory each object came from. on a name collision, the
    later entry in iteration order wins.
    """
    merged = {}
    sources = {}
    for source_directory, objects in dicts_with_sources:
        for name, obj_type in objects.items():
            merged[name] = obj_type
            sources[name] = source_directory
    return merged, sources


def list_all_named_objects():
    """
    enumerates \\BaseNamedObjects (the global/session-0 object directory)
    and, when the current process's session id is known, this process's
    own \\Sessions\\<id>\\BaseNamedObjects directory too, merging both
    into one name->type dict.

    this matters because GhostRun launches samples in an interactive
    session. a mutex created via CreateMutexW(NULL, ..., "SomeName")
    with no "Global\\" prefix lands in the session-specific directory,
    not the global one. per-session namespace redirection applies to
    the Win32 name, not to an NT path passed straight to
    NtOpenDirectoryObject. most single-instance malware mutexes have no
    "Global\\" prefix, so checking only \\BaseNamedObjects would miss
    the common real-world case.

    returns (merged, sources): merged is the diff_mutexes-compatible
    name->type dict, sources is a parallel name->source_directory dict.
    """
    directories = [r"\BaseNamedObjects"]
    session_id = _get_current_session_id()
    if session_id is not None:
        directories.append(f"\\Sessions\\{session_id}\\BaseNamedObjects")

    dicts_with_sources = [(path, list_named_objects(path)) for path in directories]
    return _merge_named_object_dicts(dicts_with_sources)


# same disclaimer wording persistence_detector.py uses for its
# capture-derived, pid-stamped-but-not-per-process findings
# \BaseNamedObjects/session directories are system-wide namespaces
# any process's mutex created during the window gets stamped with
# root_pid here, not just the sample's
_ATTRIBUTION_NOTE = (
    "pid is capture-derived, stamped with the analysis root PID, "
    "not per-process attributed."
)


# known malware mutex-name classification

# curated, extensible list, same shape as registry_snapshot.py's PERSISTENCE_KEYS
# prefix-matched, not substring-anywhere, keeps false positives narrow
# since some of these prefixes are short
# each prefix is verified against real analyzed samples, not general reputation
# njRAT, NanoCore, and NetWire were checked and excluded on purpose:
# they use per-build random/GUID mutex names with no stable prefix
# a signature list can't catch that class, only families with a static watermark
def _validate_mutex_signature_entry(entry):
    prefixes = entry.get("prefixes")
    if not isinstance(prefixes, list) or not prefixes:
        return "'prefixes' must be a non-empty list"
    if not all(isinstance(p, str) and p for p in prefixes):
        return "'prefixes' must contain only non-empty strings"
    return None


MUTEX_SIGNATURES = load_rule_file(
    "mutex_signatures.yml",
    required_fields=["family", "confidence", "prefixes"],
    validate_entry=_validate_mutex_signature_entry,
)


def classify_mutex_event(name, emit, pid=None):
    """
    checks a newly-created mutex's name against MUTEX_SIGNATURES.
    emits at most one known_malware_mutex event (first matching family
    wins). most mutex names won't match anything, that's expected, not
    a failure.
    """
    for sig in MUTEX_SIGNATURES:
        for prefix in sig["prefixes"]:
            if name.startswith(prefix):
                emit(
                    category="mutex_behavior",
                    event="known_malware_mutex",
                    confidence=sig["confidence"],
                    data={"pid": pid, "family": sig["family"], "mutex": name, "attck": "T1480.001"},
                )
                return


class MutexMonitor:
    def __init__(self, emit_func, poll_interval=5, root_pid=None, baseline=None):
        self.emit = emit_func
        self.poll_interval = poll_interval
        self.root_pid = root_pid
        self.running = True
        # None means "capture it yourself on run()"
        # an explicit dict (even {}) is used as-is and never re-captured
        # this lets a caller (ghostrun.py) snapshot the baseline before the
        # sample launches instead of after
        # closes the race where an early single-instance mutex gets baselined
        # away as "pre-existing"
        self._baseline = baseline
        self._degraded_notified = False
        self._scan_lock = threading.Lock()
        self._wake_event = threading.Event()
        # set by trigger_scan(), cleared when a scan starts
        # kept separate from _wake_event because stop() also sets the wake event
        # to wake run() promptly, so the wake event alone can't tell run()
        # whether a trigger is still owed a scan when running=False
        self._scan_requested = False

    def trigger_scan(self):
        """
        requests one scan as soon as possible, outside the periodic timer.
        safe to call from another thread. returns immediately, the scan
        itself runs later on run()'s own thread, not the caller's.
        several calls arriving before run()'s loop wakes up coalesce into
        exactly one scan (threading.Event.set() is idempotent), not one
        scan per call, so a burst of triggers can't queue up a backlog.
        a trigger still pending when stop() is called gets one final
        scan before run() exits (teardown relies on this last-chance scan).
        """
        self._scan_requested = True
        self._wake_event.set()

    def _scan(self):
        self._scan_requested = False
        with self._scan_lock:
            try:
                self._poll_once()
            except Exception as exc:
                self.emit("ghostrun_status", "mutex_scan_failed", {"error": str(exc)})

    def _poll_once(self):
        current, sources = list_all_named_objects()
        if not current:
            # a genuinely empty result across every directory is implausible
            # the system always has some long-lived mutexes/events
            # treat it as a failed/transient enumeration, not real state
            # skip the diff and the baseline update
            # otherwise self._baseline could corrupt to {} and the next good poll
            # would report every pre-existing mutex as "newly created"
            if not self._degraded_notified:
                self.emit("ghostrun_status", "mutex_monitor_degraded", {
                    "reason": "named-object enumeration returned no data this cycle",
                })
                self._degraded_notified = True
            return
        self._degraded_notified = False

        new_names = diff_mutexes(self._baseline, current)
        for name in new_names:
            data = {"name": name, "pid": self.root_pid, "note": _ATTRIBUTION_NOTE}
            source = sources.get(name)
            if source is not None:
                data["directory"] = source
            self.emit("mutex", "mutex_created", data)
            classify_mutex_event(name, self.emit, pid=self.root_pid)
        self._baseline = current

    def run(self):
        self.emit("mutex", "monitor_start", {"root_pid": self.root_pid})
        try:
            if self._baseline is None:
                self._baseline, _ = list_all_named_objects()
            # prime the wake event so the first iteration scans right away
            # instead of waiting a full poll_interval for its first pass
            # every iteration after this one waits on a real wake, trigger or timeout, as usual
            self._wake_event.set()
            while True:
                self._wake_event.wait(timeout=self.poll_interval)
                self._wake_event.clear()
                if not self.running:
                    # a trigger_scan() that landed before or with stop() is still owed its scan
                    # run it once, then exit
                    if self._scan_requested:
                        self._scan()
                    break
                self._scan()
        finally:
            self.emit("mutex", "monitor_stop", {})

    def stop(self):
        self.running = False
        self._wake_event.set()  # wake run() now instead of waiting up to poll_interval
