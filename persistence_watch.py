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
        conn = _connect_subscription_namespace()
        watchers = {
            class_name: getattr(conn, class_name).watch_for("creation")
            for class_name in _WATCHED_CLASSES
        }

        while self.running:
            for class_name, watcher in watchers.items():
                self._poll_class(watcher, class_name)

    def stop(self):
        self.running = False
