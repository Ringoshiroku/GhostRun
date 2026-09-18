import ctypes
import threading
from ctypes import wintypes

_advapi32 = ctypes.WinDLL("advapi32") if hasattr(ctypes, "WinDLL") else None

REG_NOTIFY_CHANGE_NAME = 0x00000001
REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
_DEFAULT_FILTER = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET

_HIVE_MAP = {}
if hasattr(ctypes, "WinDLL"):
    import winreg
    _HIVE_MAP = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}

_DEFAULT_ROOTS = [
    ("HKCU", "Software"),
    ("HKLM", "Software"),
    ("HKLM", r"SYSTEM\CurrentControlSet\Services"),
]


class RegistryWatcher:
    """
    watches broad registry roots for any change, at any depth, using
    RegNotifyChangeKeyValue in watch-subtree mode.

    doesn't know or care what changed, only that something did under a
    given root. the caller runs a targeted diff in response.
    """

    def __init__(self, on_change, roots=None):
        self.on_change = on_change
        self.watched_roots = roots if roots is not None else list(_DEFAULT_ROOTS)
        self._threads = []
        self._stop_event = threading.Event()
        self._fired_event = threading.Event()

    def start(self):
        for hive, path in self.watched_roots:
            t = threading.Thread(
                target=self._watch_loop, args=(hive, path), daemon=True
            )
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stop_event.set()

    def wait_for_fire(self, timeout=None):
        return self._fired_event.wait(timeout=timeout)

    def _watch_loop(self, hive, path):
        import winreg

        try:
            key = winreg.OpenKey(_HIVE_MAP[hive], path)
        except OSError:
            return

        handle = key.handle if hasattr(key, "handle") else int(key)
        while not self._stop_event.is_set():
            result = _advapi32.RegNotifyChangeKeyValue(
                wintypes.HANDLE(handle),
                True,               # watch subtree
                _DEFAULT_FILTER,
                None,
                False,              # synchronous, blocks until a change fires
            )
            if result != 0:
                return
            if self._stop_event.is_set():
                return
            self._fired_event.set()
            self.on_change(hive, path)
