import sys
import re

if sys.platform == "win32":
    import winreg
    _HIVE_MAP = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
else:
    # stub for testing on non-Windows platforms
    winreg = None
    _HIVE_MAP = {}

# =========================================================
# persistence monitoring
# =========================================================

PERSISTENCE_KEYS = [
    # --- Run / RunOnce (T1547.001) ---
    {"hive": "HKCU", "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
     "mode": "values", "category": "run_key", "attck": "T1547.001", "confidence": "high"},
    {"hive": "HKCU", "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "mode": "values", "category": "run_key", "attck": "T1547.001", "confidence": "high"},
    {"hive": "HKLM", "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
     "mode": "values", "category": "run_key", "attck": "T1547.001", "confidence": "high"},
    {"hive": "HKLM", "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "mode": "values", "category": "run_key", "attck": "T1547.001", "confidence": "high"},
    {"hive": "HKLM", "path": r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
     "mode": "values", "category": "run_key", "attck": "T1547.001", "confidence": "high"},

    # --- Winlogon Shell/Userinit (T1547.004) ---
    {"hive": "HKLM", "path": r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
     "mode": "values", "watch_values": ["Shell", "Userinit"],
     "category": "winlogon", "attck": "T1547.004", "confidence": "high"},

    # --- Image File Execution Options debugger hijack (T1546.012) ---
    {"hive": "HKLM",
     "path": r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
     "mode": "subkey_values", "watch_values": ["Debugger"],
     "category": "ifeo_debugger", "attck": "T1546.012", "confidence": "high"},

    # --- AppInit_DLLs (T1546.010) ---
    {"hive": "HKLM", "path": r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
     "mode": "values", "watch_values": ["AppInit_DLLs", "LoadAppInit_DLLs"],
     "category": "appinit_dlls", "attck": "T1546.010", "confidence": "high"},

    # --- Services (T1543.003) ---
    {"hive": "HKLM", "path": r"SYSTEM\CurrentControlSet\Services",
     "mode": "subkey_values", "watch_values": ["ImagePath", "Start", "Type"],
     "category": "new_service", "attck": "T1543.003", "confidence": "high"},

    # --- Scheduled Tasks (T1053.005) ---
    {"hive": "HKLM",
     "path": r"Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
     "mode": "subkey_presence", "category": "scheduled_task",
     "attck": "T1053.005", "confidence": "medium"},

    # --- LSA Security/Authentication Packages (T1547.005) ---
    {"hive": "HKLM", "path": r"SYSTEM\CurrentControlSet\Control\Lsa",
     "mode": "values",
     "watch_values": ["Authentication Packages", "Security Packages", "Notification Packages"],
     "category": "lsa_packages", "attck": "T1547.005", "confidence": "high"},

    # --- Browser Helper Objects (T1185 adjacent, tracked as execution persistence) ---
    {"hive": "HKLM",
     "path": r"Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
     "mode": "subkey_presence", "category": "browser_helper_object",
     "attck": "T1547", "confidence": "medium"},
]


# =========================================================
# CLASSIFICATION HEURISTICS
# =========================================================

EXEC_PATTERN = re.compile(
    r"\.(exe|dll|ps1|bat|cmd|vbs|js|hta)",
    re.IGNORECASE,
)


# =========================================================
# SNAPSHOT
# =========================================================

def _open_key(hive, path):
    return winreg.OpenKey(_HIVE_MAP[hive], path)


def _enum_values(key):
    values = []
    i = 0
    while True:
        try:
            name, data, _ = winreg.EnumValue(key, i)
        except OSError:
            break
        values.append((name, data))
        i += 1
    return values


def _enum_subkeys(key):
    # handles come back open, not closed here with a `with` block.
    # this lets the caller read values through them after this returns.
    # the caller must close each handle once it's done with it.
    # see _read_subkey_values_key / _read_subkey_presence_key below.
    subkeys = []
    i = 0
    while True:
        try:
            name = winreg.EnumKey(key, i)
        except OSError:
            break
        subkeys.append((name, winreg.OpenKey(key, name)))
        i += 1
    return subkeys


def _get_value(key, name):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def _read_values_key(entry):
    full_key = f"{entry['hive']}\\{entry['path']}"
    snapshot = {}
    try:
        key = _open_key(entry["hive"], entry["path"])
    except OSError:
        return snapshot

    watch_values = entry.get("watch_values")
    for name, data in _enum_values(key):
        if watch_values is None or name in watch_values:
            snapshot.setdefault(full_key, {})[name] = data
    return snapshot


def _read_subkey_values_key(entry):
    base_key_name = f"{entry['hive']}\\{entry['path']}"
    snapshot = {}
    try:
        key = _open_key(entry["hive"], entry["path"])
    except OSError:
        return snapshot

    for sub_name, sub_key in _enum_subkeys(key):
        child_key_name = f"{base_key_name}\\{sub_name}"
        try:
            for value_name in entry["watch_values"]:
                data = _get_value(sub_key, value_name)
                if data is not None:
                    snapshot.setdefault(child_key_name, {})[value_name] = data
        finally:
            if winreg is not None:
                winreg.CloseKey(sub_key)
    return snapshot


def _read_subkey_presence_key(entry):
    full_key = f"{entry['hive']}\\{entry['path']}"
    snapshot = {}
    try:
        key = _open_key(entry["hive"], entry["path"])
    except OSError:
        return snapshot

    for sub_name, sub_key in _enum_subkeys(key):
        snapshot.setdefault(full_key, {})[sub_name] = "present"
        if winreg is not None:
            winreg.CloseKey(sub_key)
    return snapshot


_MODE_READERS = {
    "values": _read_values_key,
    "subkey_values": _read_subkey_values_key,
    "subkey_presence": _read_subkey_presence_key,
}


def snapshot_registry():
    """
    returns:
        {"HKCU\\Software\\Foo": {"ValueName": "ValueData", ...}, ...}
    """
    snapshot = {}
    for entry in PERSISTENCE_KEYS:
        reader = _MODE_READERS[entry["mode"]]
        try:
            partial = reader(entry)
        except Exception:
            continue
        for key, values in partial.items():
            snapshot.setdefault(key, {}).update(values)
    return snapshot


# =========================================================
# DIFF + EMIT (RAW + DERIVED)
# =========================================================

def diff_registry(before, after, emit, root_pid=None):
    """
    Emit:
      - registry_raw:value_added
      - registry_raw:value_modified
      - registry_behavior:* (derived)
    """

    #if root_pid not in MALWARE_PIDS:
    #    return
    
    for key in after:
        before_vals = before.get(key, {})
        after_vals = after.get(key, {})

        for name, data in after_vals.items():
            # -------------------------
            # VALUE ADDED
            # -------------------------
            if name not in before_vals:
                raw_event = {
                    "pid": root_pid,
                    "key": key,
                    "value_name": name,
                    "value_data": str(data),
                }

                emit(
                    category="registry_raw",
                    event="value_added",
                    data=raw_event,
                )

                classify_registry_event(raw_event, emit)

            # -------------------------
            # VALUE MODIFIED
            # -------------------------
            elif before_vals[name] != data:
                raw_event = {
                    "pid": root_pid,
                    "key": key,
                    "value_name": name,
                    "before": str(before_vals[name]),
                    "after": str(data),
                }

                emit(
                    category="registry_raw",
                    event="value_modified",
                    data=raw_event,
                )

                classify_registry_event(raw_event, emit)


# =========================================================
# CLASSIFIER (DERIVED EVIDENCE)
# =========================================================

_PERSISTENCE_KEY_LOOKUP = {
    f"{entry['hive']}\\{entry['path']}": entry for entry in PERSISTENCE_KEYS
}


def _find_persistence_entry(key_path):
    # try an exact match first (values/subkey_presence style).
    # then walk up one level for subkey_values style (child key under a
    # watched container).
    if key_path in _PERSISTENCE_KEY_LOOKUP:
        return _PERSISTENCE_KEY_LOOKUP[key_path]
    parent, _, _ = key_path.rpartition("\\")
    return _PERSISTENCE_KEY_LOOKUP.get(parent)


def classify_registry_event(raw_event, emit):
    """
    build forensic-grade behavior evidence from a curated,
    already-known-relevant registry location. don't overclaim.
    """
    key_path = raw_event.get("key", "")
    value_data = (
        raw_event.get("value_data")
        or raw_event.get("after")
        or ""
    )
    value_data_l = str(value_data).lower()

    if EXEC_PATTERN.search(value_data_l):
        emit(
            category="registry_behavior",
            event="execution_reference_detected",
            confidence="medium",
            data={
                "pid": raw_event.get("pid"),
                "path": value_data,
                "location": key_path,
                "value": raw_event.get("value_name"),
            },
        )

    entry = _find_persistence_entry(key_path)
    if entry is not None:
        emit(
            category="registry_behavior",
            event="known_persistence_location",
            confidence=entry["confidence"],
            data={
                "pid": raw_event.get("pid"),
                "category": entry["category"],
                "attck": entry["attck"],
                "location": key_path,
                "value": raw_event.get("value_name"),
            },
        )
