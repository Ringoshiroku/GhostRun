import subprocess

_SUBCATEGORY = "Filtering Platform Connection"


def query_filtering_platform_connection_audit():
    """
    returns True if the subcategory's setting includes Success auditing.
    returns False if it's set to "No Auditing".
    returns None if the setting can't be determined at all:
    auditpol missing, a non-zero exit, or output that doesn't match
    the expected table format.
    never raises: this runs during WfpConnectionWatcher.start(),
    which must degrade gracefully like every other optional
    capability here.
    """
    try:
        result = subprocess.run(
            ["auditpol.exe", "/get", f"/subcategory:{_SUBCATEGORY}"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        if _SUBCATEGORY in line:
            tail = line.split(_SUBCATEGORY, 1)[1].strip()
            if "Success" in tail:
                return True
            if "No Auditing" in tail:
                return False
    return None


def set_filtering_platform_connection_audit(enabled):
    """
    enables or disables Success auditing for the subcategory,
    via auditpol.exe.
    returns whether the call succeeded (exit code 0).
    never raises.
    """
    value = "enable" if enabled else "disable"
    try:
        result = subprocess.run(
            ["auditpol.exe", "/set", f"/subcategory:{_SUBCATEGORY}", f"/success:{value}"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return False
    return result.returncode == 0
