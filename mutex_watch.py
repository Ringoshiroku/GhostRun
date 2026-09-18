import ctypes
import time
from ctypes import wintypes


def diff_mutexes(before, after):
    return sorted(
        name for name, obj_type in after.items()
        if obj_type == "Mutant" and before.get(name) != "Mutant"
    )


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT),
                ("Buffer", wintypes.LPWSTR)]


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


_STATUS_NO_MORE_ENTRIES = 0x8000001A


def list_named_objects(directory_path=r"\BaseNamedObjects"):
    """
    enumerates an nt kernel object directory (default \\BaseNamedObjects,
    where named mutexes/events/semaphores live) via NtQueryDirectoryObject.
    returns {} on any failure instead of raising, since this touches
    undocumented low-level windows internals.
    """
    ntdll = ctypes.WinDLL("ntdll")
    name = _UNICODE_STRING(len(directory_path) * 2, len(directory_path) * 2 + 2, directory_path)
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

        while True:
            returned = wintypes.ULONG(0)
            status = ntdll.NtQueryDirectoryObject(
                handle, buf, buf_size, False, restart_scan,
                ctypes.byref(context), ctypes.byref(returned),
            )
            restart_scan = False

            if status == _STATUS_NO_MORE_ENTRIES or status != 0:
                break

            entries = ctypes.cast(buf, ctypes.POINTER(_OBJECT_DIRECTORY_INFORMATION))
            i = 0
            while True:
                entry = entries[i]
                if entry.Name.Length == 0:
                    break  # empty entry marks the end of this batch
                obj_name = ctypes.wstring_at(entry.Name.Buffer, entry.Name.Length // 2)
                obj_type = ctypes.wstring_at(entry.TypeName.Buffer, entry.TypeName.Length // 2)
                results[obj_name] = obj_type
                i += 1
    finally:
        ntdll.NtClose(handle)

    return results


class MutexMonitor:
    def __init__(self, emit_func, poll_interval=5, root_pid=None):
        self.emit = emit_func
        self.poll_interval = poll_interval
        self.root_pid = root_pid
        self.running = True
        self._baseline = {}

    def _poll_once(self):
        current = list_named_objects()
        new_names = diff_mutexes(self._baseline, current)
        for name in new_names:
            self.emit("mutex", "mutex_created", {"name": name, "pid": self.root_pid})
        self._baseline = current

    def run(self):
        self._baseline = list_named_objects()
        while self.running:
            time.sleep(self.poll_interval)
            if not self.running:
                break
            self._poll_once()

    def stop(self):
        self.running = False
