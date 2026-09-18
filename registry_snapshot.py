import sys
import re

if sys.platform == "win32":
    import winreg
else:
    # stub for testing on non-Windows platforms
    winreg = None

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

def snapshot_registry():
    """
    Returns:
        {
            "HKCU\\Software\\Foo": {
                "ValueName": "ValueData",
                ...
            }
        }
    """
    snapshot = {}

    for hive_name, hive, base_path in TARGET_HIVES:
        try:
            with winreg.OpenKey(hive, base_path) as root:
                _walk_key(
                    snapshot,
                    hive_name,
                    base_path,
                    root,
                    depth=0,
                )
        except Exception:
            continue

    return snapshot


def _walk_key(snapshot, hive_name, path, key, depth):
    if depth > MAX_DEPTH:
        return

    full_key = f"{hive_name}\\{path}"

    # --- Enumerate values ---
    try:
        i = 0
        while True:
            name, data, _ = winreg.EnumValue(key, i)
            snapshot.setdefault(full_key, {})[name] = data
            i += 1
    except OSError:
        pass

    # --- Enumerate subkeys ---
    try:
        i = 0
        while True:
            sub = winreg.EnumKey(key, i)
            with winreg.OpenKey(key, sub) as subkey:
                _walk_key(
                    snapshot,
                    hive_name,
                    f"{path}\\{sub}",
                    subkey,
                    depth + 1,
                )
            i += 1
    except OSError:
        pass


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

def classify_registry_event(raw_event, emit):
    """
    Create derived, forensic-grade behavior evidence.
    NO overclaim.
    """
    key_path = raw_event.get("key", "")
    value_data = (
        raw_event.get("value_data")
        or raw_event.get("after")
        or ""
    )

    value_data_l = value_data.lower()
    key_l = key_path.lower()

    # -----------------------------------------------------
    # Execution reference
    # -----------------------------------------------------
    if EXEC_PATTERN.search(value_data_l):
        emit(
            category="registry_behavior",
            event="execution_reference_detected",
            confidence="medium",
            data={
                "path": value_data,
                "location": key_path,
                "value": raw_event.get("value_name"),
            },
        )

    # -----------------------------------------------------
    # Suspicious registry location
    # -----------------------------------------------------
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in key_l:
            emit(
                category="registry_behavior",
                event="suspicious_registry_location",
                confidence="low",
                data={
                    "keyword": kw,
                    "location": key_path,
                    "value": raw_event.get("value_name"),
                },
            )
            break
