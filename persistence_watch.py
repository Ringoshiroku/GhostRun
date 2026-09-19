import sys
import types

try:
    import wmi
except ImportError:
    # wmi (and its dependency pywin32) is windows-only and won't
    # be installed on a non-windows host (e.g. this dev/test machine).
    # build a minimal stand-in module exposing just what this file
    # needs (x_wmi, x_wmi_timed_out, WMI) so `import wmi` keeps
    # working here, and register it in sys.modules so any other
    # `import wmi` / `__import__("wmi")` elsewhere in the process
    # (including test fakes) resolves to this same object instead
    # of re-attempting a real import that would fail.
    # actually connecting still fails loudly, just deferred to
    # call time (inside WMI()) instead of import time.
    # same pattern as process_mon.py.
    wmi = types.ModuleType("wmi")

    class x_wmi(Exception):
        pass

    class x_wmi_timed_out(x_wmi):
        pass

    def _WMI(**kwargs):
        raise RuntimeError(
            "the 'wmi' package (Windows-only, requires pywin32) is not "
            "available on this platform; persistence monitoring via WMI "
            "events requires Windows"
        )

    wmi.x_wmi = x_wmi
    wmi.x_wmi_timed_out = x_wmi_timed_out
    wmi.WMI = _WMI
    sys.modules.setdefault("wmi", wmi)


_WATCHED_CLASSES = ["__EventFilter", "__EventConsumer", "__FilterToConsumerBinding"]

# same disclaimer wording persistence_detector.py already uses
# for its capture-derived, pid-stamped-but-not-per-process
# findings.
# root\subscription is a system-wide namespace: any WMI event
# filter/consumer/binding created by any process during the
# analysis window, not just the sample, gets stamped with
# root_pid here.
_ATTRIBUTION_NOTE = (
    "pid is capture-derived, stamped with the analysis root PID, "
    "not per-process attributed."
)


def _wmi_object_properties(wmi_obj):
    result = {}
    for key in wmi_obj.properties.keys():
        value = getattr(wmi_obj, key, None)
        if value is not None:
            result[key] = value
    return result


def _persistence_event_to_evidence(wmi_event, class_name):
    return {
        "wmi_class": class_name,
        "attck": "T1546.003",
        "properties": _wmi_object_properties(wmi_event),
        "note": _ATTRIBUTION_NOTE,
    }


def _connect_subscription_namespace():
    return wmi.WMI(namespace="root\\subscription")


class PersistenceWatcher:
    def __init__(self, emit_func, root_pid=None):
        self.emit = emit_func
        self.root_pid = root_pid
        self.running = True

    def _poll_class(self, watcher, class_name):
        try:
            event = watcher(timeout_ms=500)
        except wmi.x_wmi_timed_out:
            return
        evidence = _persistence_event_to_evidence(event, class_name)
        evidence["pid"] = self.root_pid
        self.emit("persistence", "wmi_event_subscription_created", evidence)

    def run(self):
        self.emit("persistence", "monitor_start", {"root_pid": self.root_pid})

        # pywin32/wmi needs COM initialized on any thread before its
        # first COM call (wmi.WMI() does this under the hood).
        # pywin32 only auto-initializes COM for the main thread at
        # import time, not for threads created later (this runs on a
        # worker thread started by ghostrun.py), so without this,
        # wmi.WMI() raises a com_error and this thread dies before
        # doing anything. same fix as process_mon.py's
        # ProcessMonitor.run().
        pythoncom = None
        try:
            import pythoncom
            pythoncom.CoInitialize()
        except ImportError:
            # pythoncom (part of pywin32) isn't installed on this platform
            # (e.g. this non-windows dev/test host). nothing to initialize.
            pythoncom = None

        try:
            try:
                conn = _connect_subscription_namespace()
                watchers = {
                    class_name: getattr(conn, class_name).watch_for("creation")
                    for class_name in _WATCHED_CLASSES
                }

                while self.running:
                    for class_name, watcher in watchers.items():
                        self._poll_class(watcher, class_name)
            except wmi.x_wmi as exc:
                # covers COM errors, RPC failures, or WMI provider restarts
                # beyond a plain timeout (already handled inside _poll_class).
                # record the degradation via ghostrun_status (exempt from
                # emit()'s pid filter, so it's actually recorded) instead of
                # letting the thread die silently with no evidence trail.
                self.emit("ghostrun_status", "persistence_watcher_degraded", {
                    "reason": f"{type(exc).__name__}: {exc}",
                })
        finally:
            if pythoncom is not None:
                pythoncom.CoUninitialize()
            self.emit("persistence", "monitor_stop", {})

    def stop(self):
        self.running = False
