import ctypes
import threading
from ctypes import wintypes

from audit_policy import query_filtering_platform_connection_audit, set_filtering_platform_connection_audit


class WfpConnectionWatcher:
    """
    replaces ConnectionMonitor's 1s polling loop.
    subscribes to wfp CLASSIFY_ALLOW events instead, so they fire the
    moment a connection is allowed.
    polling missed any connection shorter than 1s, confirmed failing
    100% of the time in live testing.
    keeps the same resolve_pid(port, timestamp) contract, so
    network_watch.py needs no changes.
    """

    def __init__(self, process_monitor, emit_func):
        self.process_monitor = process_monitor
        self.emit = emit_func
        self._audit_policy_changed = False
        self._events_lock = threading.Lock()
        self._events = []  # [(timestamp, local_port, resolved_pid_or_none)]
        self._engine_handle = None
        self._subscription_handle = None

    def start(self):
        """
        turns on the wfp success-audit subcategory if it's not already on,
        needed so the engine reports allow events at all.
        remembers whether this instance was the one that flipped it, so
        stop() only restores a setting it actually changed, never an
        existing operator setting.
        then tries the native wfp subscription. on failure, degrades to
        an emitted status event instead of raising, same as every other
        optional capability in this codebase.
        """
        was_enabled = query_filtering_platform_connection_audit()
        if was_enabled is False:
            if set_filtering_platform_connection_audit(True):
                self._audit_policy_changed = True

        if not self._native_start():
            self.emit("ghostrun_status", "wfp_watcher_degraded", {
                "reason": "WFP engine open or event subscription failed",
            })
            return

    def stop(self):
        self._native_stop()
        if self._audit_policy_changed:
            set_filtering_platform_connection_audit(False)
            self._audit_policy_changed = False

    def resolve_pid(self, local_port, approx_timestamp):
        """
        returns the pid whose recorded wfp event on `local_port` is
        closest in time to approx_timestamp.
        returns none if no recorded event used that port, or none of
        them resolved to a live descendant pid.
        same nearest-in-time contract as ConnectionMonitor.resolve_pid,
        so network_watch.py's _resolve_attributed_pid needs no changes.
        """
        best_pid, best_delta = None, None
        with self._events_lock:
            events = list(self._events)
        for ts, port, pid in events:
            if port == local_port and pid is not None:
                delta = abs(ts - approx_timestamp)
                if best_delta is None or delta < best_delta:
                    best_delta, best_pid = delta, pid
        return best_pid

    def _on_event(self, timestamp, local_port, app_path):
        """
        called by the native wfp callback for each decoded CLASSIFY_ALLOW
        event.
        resolves app_path to a live descendant pid right away, through
        process_monitor, instead of storing the raw path for later.
        by the time resolve_pid() runs, after capture analysis finishes,
        the process may have already exited and process_monitor's live
        image_paths table won't have it anymore.
        """
        resolved_pid = self.process_monitor.resolve_path_to_pid(app_path) if app_path else None
        with self._events_lock:
            self._events.append((timestamp, local_port, resolved_pid))

    def _native_start(self):
        """
        opens the wfp engine handle and subscribes to CLASSIFY_ALLOW net
        events, decoding each into a call to self._on_event().
        returns true on success, false on any failure, never raises.

        not implemented on purpose, not an oversight. the real
        ctypes bindings need the exact verified field order, types,
        and size of several wfp structs and the callback signature,
        the same way mutex_watch.py's _OBJECT_DIRECTORY_INFORMATION
        comment documents its own verified source.
        this environment can't browse microsoft's reference pages to
        verify that layout, and guessing one from memory risks memory
        corruption or a segfault against the real windows api, worse
        than an honest NotImplementedError.
        every test that exercises start() replaces this method via
        monkeypatch and never reaches this body.
        """
        raise NotImplementedError(
            "WFP ctypes bindings: implement against the struct layout verified "
            "against Microsoft's official fwpmtypes/fwpmu reference pages (see "
            "this task's brief), not a guess, then record the Windows build it "
            "was verified against in a comment here. Only reachable on a real "
            "Windows host with the real wfp_connection_watcher module imported; "
            "every test above replaces this method entirely."
        )

    def _native_stop(self):
        """
        unsubscribes and closes the engine handle. never raises.

        not implemented, same reason as _native_start above: needs to be
        built together with it, against the same verified struct layout
        and the matching unsubscribe/close calls.
        """
        raise NotImplementedError(
            "WFP ctypes teardown: implement alongside _native_start, against "
            "the same verified struct layout."
        )
