import sys
import re

from rules_loader import load_rule_file

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

# subkey_values and subkey_child_values modes each need their own
# extra field (watch_values / watch_subkeys).
# required_fields alone can't express a conditional requirement like
# that, so this file's loader call also passes a validate_entry hook
# just for that.
_MODE_CONDITIONAL_FIELDS = {
    "subkey_values": "watch_values",
    "subkey_child_values": "watch_subkeys",
}


def _validate_persistence_key_entry(entry):
    mode = entry.get("mode")
    required = _MODE_CONDITIONAL_FIELDS.get(mode)
    if required and required not in entry:
        return f"mode '{mode}' requires '{required}'"
    return None


PERSISTENCE_KEYS = load_rule_file(
    "registry_persistence_keys.yml",
    required_fields=["hive", "path", "mode", "category", "attck", "confidence"],
    validate_entry=_validate_persistence_key_entry,
)


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
        try:
            sub_key = winreg.OpenKey(key, name)
        except OSError:
            # EnumKey lists a subkey's name without needing the permission that
            # opening it actually requires.
            # a specific subkey (e.g. one owned by an AppContainer SID) can
            # legitimately deny that even from an elevated process.
            # skip it, don't let it crash the whole walk.
            i += 1
            continue
        subkeys.append((name, sub_key))
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


def _read_subkey_child_values_key(entry):
    # like _read_subkey_values_key, but the watched value sits one level
    # deeper: under a named sub-subkey of each child (e.g.
    # CLSID\{guid}\InprocServer32's default value), not on the child itself.
    # reads only the default value (name "") of each entry["watch_subkeys"]
    # sub-subkey found under each child.
    # a child missing every watched sub-subkey gets no entry in the result.
    base_key_name = f"{entry['hive']}\\{entry['path']}"
    snapshot = {}
    try:
        key = _open_key(entry["hive"], entry["path"])
    except OSError:
        return snapshot

    for sub_name, sub_key in _enum_subkeys(key):
        child_key_name = f"{base_key_name}\\{sub_name}"
        try:
            for subsubkey_name in entry["watch_subkeys"]:
                try:
                    grandchild = winreg.OpenKey(sub_key, subsubkey_name)
                except OSError:
                    continue
                try:
                    data = _get_value(grandchild, "")
                finally:
                    if winreg is not None:
                        winreg.CloseKey(grandchild)
                if data is not None:
                    snapshot.setdefault(child_key_name, {})[subsubkey_name] = data
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
    "subkey_child_values": _read_subkey_child_values_key,
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
        except Exception as e:
            print(f"[DEBUG] snapshot failed: {entry['hive']}\\{entry['path']} -> {type(e).__name__}: {e}")
            continue
        for key, values in partial.items():
            snapshot.setdefault(key, {}).update(values)
    return snapshot


def _walk_subtree(hive_name, path, key, depth, max_depth, snapshot):
    full_key = f"{hive_name}\\{path}"
    for name, data in _enum_values(key):
        snapshot.setdefault(full_key, {})[name] = data

    if depth >= max_depth:
        return

    for sub_name, sub_key in _enum_subkeys(key):
        try:
            _walk_subtree(hive_name, f"{path}\\{sub_name}", sub_key, depth + 1, max_depth, snapshot)
        finally:
            if winreg is not None:
                winreg.CloseKey(sub_key)


def snapshot_registry_subtree(hive, path, max_depth=4):
    """
    recursive, depth-capped snapshot of one registry subtree.
    returns the same {full_key: {name: data}} shape as
    snapshot_registry(), so diff_registry() works on it unchanged.

    unlike snapshot_registry()'s curated PERSISTENCE_KEYS dispatch,
    this walks everything under the given root up to max_depth
    (default 4, matching the original tool's MAX_DEPTH before the
    curated list replaced it).

    used for RegistryWatcher's broad catch-all roots, which exist to
    catch activity outside the curated list.
    """
    snapshot = {}
    try:
        key = _open_key(hive, path)
    except OSError:
        return snapshot
    try:
        _walk_subtree(hive, path, key, depth=0, max_depth=max_depth, snapshot=snapshot)
    finally:
        if winreg is not None:
            winreg.CloseKey(key)
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


def strip_curated_keys(snapshot):
    """
    drops any key already covered by the curated PERSISTENCE_KEYS
    list from a snapshot_registry_subtree()-shaped dict, using the
    same exact/parent match _find_persistence_entry uses.

    a curated key can sit inside one of RegistryWatcher's broad
    catch-all roots (e.g. the Run key lives inside HKCU\\Software).
    without this, a change there gets reported twice: once by the
    curated snapshot_registry()/diff_registry() pass, and again by
    the broad root's own diff against the same unfiltered data.
    """
    return {
        key: values
        for key, values in snapshot.items()
        if _find_persistence_entry(key) is None
    }


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
