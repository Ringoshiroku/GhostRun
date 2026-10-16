# native_paths.py
# FILETIME epoch offset: number of 100-nanosecond intervals between
# 1601-01-01 (the FILETIME epoch) and 1970-01-01 (the Unix epoch).
# this is a standard, widely documented constant, not something
# specific to this project.
_FILETIME_EPOCH_OFFSET_100NS = 116444736000000000


def filetime_to_epoch_seconds(filetime):
    """
    converts a Windows FILETIME value (100-nanosecond intervals since
    1601-01-01) into Unix epoch seconds.

    this value shows up as WFP's FWPM_NET_EVENT_HEADER3.timeStamp and
    as the ETW EVENT_RECORD callback's EventHeader.TimeStamp, once
    ETW has converted it to system time (the default for a real-time
    PROCESS_TRACE_MODE_EVENT_RECORD session).

    Unix epoch seconds is the format the rest of the attribution
    pipeline already uses (Suricata timestamp parsing in
    network_watch.py, resolve_pid).
    """
    return (filetime - _FILETIME_EPOCH_OFFSET_100NS) / 10_000_000


import re

# matches an NT device-form path's device prefix
# (e.g. \Device\HarddiskVolume3) and captures the rest separately,
# so the rest's casing and content stay exact while only the
# prefix gets looked up and replaced.
_DEVICE_PATH_RE = re.compile(r"^(\\[Dd][Ee][Vv][Ii][Cc][Ee]\\[^\\]+)(\\.*)?$")


def to_dos_path(path, device_map):
    """
    rewrites an NT device-form path (e.g.
    \\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe, the form
    WFP's appId and ETW's ImageName report paths in) into its DOS
    drive-letter form (e.g. C:\\Windows\\System32\\notepad.exe), using
    device_map (see build_device_path_map).

    a path that doesn't match the device-path pattern at all (e.g.
    it's already a DOS path), or whose device prefix has no entry in
    device_map, is returned unchanged: it's either already usable or
    unresolvable.

    ProcessMonitor.resolve_path_to_pid's existing ambiguity-safe design
    already treats "couldn't match" as None rather than guessing, so
    an unrewritten path just won't match there, instead of silently
    becoming a wrong one.
    """
    if not path:
        return path
    match = _DEVICE_PATH_RE.match(path)
    if not match:
        return path
    device_prefix, rest = match.group(1), match.group(2) or ""
    drive = device_map.get(device_prefix.lower())
    if drive is None:
        return path
    return drive + rest


import ctypes


def build_device_path_map():
    """
    enumerates drive letters A: through Z: via QueryDosDeviceW,
    building {device_prefix.lower(): "C:"} for every drive letter
    that's actually mapped to a device.

    this lets to_dos_path rewrite an NT device-form path into the
    DOS form ProcessMonitor.resolve_path_to_pid's existing
    os.path.normcase comparison already expects.

    returns {} on any failure, including on a non-Windows host
    (where ctypes.WinDLL doesn't even exist), rather than raising.
    this matches mutex_watch.py's list_named_objects degrade
    contract for the same kind of native-only, best-effort lookup.
    """
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        device_map = {}
        buf = ctypes.create_unicode_buffer(260)
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:"
            length = kernel32.QueryDosDeviceW(drive, buf, len(buf))
            if length == 0:
                continue
            device_map[buf.value.lower()] = drive
        return device_map
    except Exception:
        return {}
