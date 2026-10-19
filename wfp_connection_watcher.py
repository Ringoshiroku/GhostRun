import collections
import ctypes
import threading
from ctypes import wintypes

from audit_policy import query_filtering_platform_connection_audit, set_filtering_platform_connection_audit
from native_paths import build_device_path_map, filetime_to_epoch_seconds, to_dos_path

_MAX_TRACKED_EVENTS = 10000


# wfp native struct/enum declarations.
#
# verification status (fetched 2026-10-16):
# - FWP_BYTE_BLOB, fwpm_net_event_header3, fwpm_net_event_subscription0,
#   FwpmEngineOpen0, FwpmNetEventSubscribe4, FwpmNetEventUnsubscribe0,
#   FwpmEngineClose0: confirmed against learn.microsoft.com's fwpmtypes
#   and fwpmu pages before this session, used as given.
# - FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW's value and
#   fwpm_net_event_callback4's parameter order: confirmed this session,
#   see each definition's own comment below.
# - appId's content encoding: not confirmed despite checking several
#   microsoft pages, see _decode_app_id's docstring for the full story.


class _FWP_BYTE_BLOB(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]


class _FWP_BYTE_ARRAY16(ctypes.Structure):
    _fields_ = [("byteArray16", ctypes.c_ubyte * 16)]


class _LocalAddrUnion(ctypes.Union):
    _fields_ = [("localAddrV4", ctypes.c_uint32), ("localAddrV6", _FWP_BYTE_ARRAY16)]


class _RemoteAddrUnion(ctypes.Union):
    _fields_ = [("remoteAddrV4", ctypes.c_uint32), ("remoteAddrV6", _FWP_BYTE_ARRAY16)]


class _FWPM_NET_EVENT_HEADER3(ctypes.Structure):
    # confirmed against learn.microsoft.com's fwpm_net_event_header3 page,
    # fetched 2026-10-16.
    _anonymous_ = ("_local", "_remote")
    _fields_ = [
        ("timeStamp", wintypes.FILETIME),
        ("flags", ctypes.c_uint32),
        ("ipVersion", ctypes.c_int),
        ("ipProtocol", ctypes.c_uint8),
        ("_local", _LocalAddrUnion),
        ("_remote", _RemoteAddrUnion),
        ("localPort", ctypes.c_uint16),
        ("remotePort", ctypes.c_uint16),
        ("scopeId", ctypes.c_uint32),
        ("appId", _FWP_BYTE_BLOB),
        ("userId", ctypes.c_void_p),       # *sid is opaque here, never dereferenced
        ("addressFamily", ctypes.c_int),
        ("packageSid", ctypes.c_void_p),   # *sid is opaque here, never dereferenced
        ("enterpriseId", ctypes.c_wchar_p),
        ("policyFlags", ctypes.c_uint64),
        ("effectiveName", _FWP_BYTE_BLOB),
    ]


class _FWPM_NET_EVENT5(ctypes.Structure):
    # named fwpm_net_event5, not fwpm_net_event4: learn.microsoft.com's
    # fwpm_net_event_callback4 page (fetched 2026-10-16) shows the real
    # callback signature takes a fwpm_net_event5*.
    # fwpm_net_event5 has the same layout as fwpm_net_event4 (header, type,
    # union of payload pointers) plus one extra union member at the end, so
    # header/type offsets don't move. this is a naming fix, not a layout
    # change.
    # the union is declared below as one generic void pointer instead of
    # every payload struct: this module only reads header.appId,
    # header.localPort, header.timeStamp, and the type discriminant, so
    # anything more would be guessed surface area for no benefit.
    _fields_ = [
        ("header", _FWPM_NET_EVENT_HEADER3),
        ("type", ctypes.c_int),
        ("data", ctypes.c_void_p),
    ]


class _GUID(ctypes.Structure):
    # ctypes.wintypes.GUID doesn't exist, confirmed empirically
    # (AttributeError on this dev host; wintypes.py is pure python on every
    # platform, so it's missing everywhere, not just here).
    # this is the standard 16-byte win32 guid layout from guiddef.h,
    # unchanged since win32 introduced it and used the same way by every
    # ctypes codebase that needs one (comtypes, pywin32, etc.).
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_uint8 * 8),
    ]


class _FWPM_NET_EVENT_SUBSCRIPTION0(ctypes.Structure):
    # confirmed against fwpm_net_event_subscription0's page, fetched
    # 2026-10-16. enumTemplate=null matches all net events.
    # this module relies on audit_policy.py's success-audit gating, not an
    # enum template filter, to restrict what actually reaches it.
    _fields_ = [
        ("enumTemplate", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("sessionKey", _GUID),
    ]


# confirmed against fwpm_net_event_type's page, fetched 2026-10-16: the
# enum is 0-based in this exact order, and CLASSIFY_ALLOW is 6, matching
# what was already used here.
_FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW = 6


def _decode_app_id(byte_blob, device_path_map):
    """
    decodes a wfp appid blob (FWPM_NET_EVENT_HEADER3.appId) into a
    dos-form file path, or none if the blob is unset.

    appid's content encoding isn't confirmed by any microsoft source
    checked (the header page, fwp_condition_value0,
    FwpmGetAppIdFromFileName0, the official sample, and a broader web
    search). decoding it as nul-terminated utf-16 matches common wfp
    developer convention, but it's still an assumption, not a verified
    fact.

    this is a bounded-risk assumption though, not a struct-layout guess:
    FWP_BYTE_BLOB's {size, data} shape is verified, and this function
    only reads exactly `size` bytes, so a wrong encoding can't corrupt
    memory. worst case is a garbled path string, which downstream code
    already treats safely as a non-match. confirm against a live capture
    before trusting app_path attribution in production.
    """
    if not byte_blob.size or not byte_blob.data:
        return None
    try:
        raw_bytes = ctypes.string_at(ctypes.addressof(byte_blob.data.contents), byte_blob.size)
        # decoded explicitly as utf-16-le instead of ctypes.wstring_at.
        # wstring_at uses the host's native wchar_t size, 2 bytes on windows but
        # 4 on linux/glibc, so it would misread this buffer on a non-windows
        # host (confirmed while writing this function's test).
        # windows api strings are always utf-16le regardless of host, so
        # decoding explicitly avoids that trap and is correct everywhere this
        # module runs.
        app_path = raw_bytes.decode("utf-16-le").rstrip("\x00")
    except (UnicodeDecodeError, ValueError):
        return None
    return to_dos_path(app_path, device_path_map)


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
        self._events = collections.deque(maxlen=_MAX_TRACKED_EVENTS)  # [(timestamp, local_port, resolved_pid_or_none)]
        self._engine_handle = None
        self._subscription_handle = None
        self._callback_ref = None  # keeps the ctypes callback alive, see _native_start
        self._device_path_map = None
        self._callback_failure_notified = False

    def start(self):
        """
        turns on the wfp success-audit subcategory if it's not already on,
        needed so the engine reports allow events at all.
        remembers whether this instance was the one that flipped it, so
        stop() only restores a setting it actually changed, never an
        existing operator setting.
        then tries the native wfp subscription. on failure, whether a
        false return or a raised exception (today's NotImplementedError
        stub, or a real failure later), degrades to an emitted status
        event instead of raising or crashing the caller, same as every
        other optional capability in this codebase.
        also reverts the audit-policy flip before returning on that path:
        a watcher that never actually started shouldn't leave the host's
        audit policy changed, especially since a caller that treats a
        degraded start as "never ran" has no reason to call stop().
        """
        was_enabled = query_filtering_platform_connection_audit()
        if was_enabled is False:
            if set_filtering_platform_connection_audit(True):
                self._audit_policy_changed = True

        try:
            native_started = self._native_start()
            native_start_error = None
        except Exception as exc:
            native_started = False
            native_start_error = str(exc)

        if not native_started:
            self._revert_audit_policy_if_changed()
            reason = "WFP engine open or event subscription failed"
            if native_start_error:
                # native_start_error names which call failed and with what status
                # code, see _native_start.
                # a live run that only surfaced the generic reason above, with no way
                # to tell FwpmEngineOpen0 apart from FwpmNetEventSubscribe4 or see the
                # actual status, left nothing to actually diagnose.
                reason = f"{reason}: {native_start_error}"
            self.emit("ghostrun_status", "wfp_watcher_degraded", {
                "reason": reason,
            })
            return

    def stop(self):
        # best-effort teardown.
        # a failing or raising _native_stop() (e.g. today's NotImplementedError
        # stub) must not stop the audit-policy restore below from running.
        try:
            self._native_stop()
        except Exception:
            pass
        self._revert_audit_policy_if_changed()

    def _revert_audit_policy_if_changed(self):
        """
        turns the audit subcategory back off, but only if this instance
        is the one that turned it on (self._audit_policy_changed).
        shared by stop()'s normal teardown and start()'s degrade path, so
        a watcher that flips the policy on and then fails to start
        doesn't leave it changed.

        if the revert call itself fails (e.g. auditpol becomes
        unavailable mid-run), that failure is surfaced as an emitted
        event instead of staying silent. self._audit_policy_changed is
        still cleared either way, so a later stop() call won't retry.
        """
        if self._audit_policy_changed:
            reverted = set_filtering_platform_connection_audit(False)
            if not reverted:
                self.emit("ghostrun_status", "audit_policy_revert_failed", {
                    "reason": "set_filtering_platform_connection_audit(False) returned False",
                })
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

    def _handle_native_event(self, net_event_ptr):
        """
        body of the native wfp callback (see _native_start), kept as a
        method so it's testable without ctypes.WINFUNCTYPE.
        never lets an exception escape: ctypes silently swallows one
        raised inside a native callback, so an unguarded failure here
        (a decode error, a resolve_path_to_pid bug) would drop events
        with no trail at all.
        same contract as ProcessMonitor._etw_event_record_callback,
        except the degrade status is only emitted on the first failure.
        wfp fires per connection, so a systematic failure would otherwise
        flood the evidence stream with one status event per connection.
        later events are still attempted normally, so one bad event
        doesn't cost the rest of the run.
        """
        try:
            net_event = net_event_ptr.contents
            if net_event.type != _FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW:
                return
            header = net_event.header
            app_path = _decode_app_id(header.appId, self._device_path_map)
            timestamp = filetime_to_epoch_seconds(
                header.timeStamp.dwLowDateTime | (header.timeStamp.dwHighDateTime << 32)
            )
            self._on_event(timestamp=timestamp, local_port=header.localPort, app_path=app_path)
        except Exception as exc:
            if not self._callback_failure_notified:
                self._callback_failure_notified = True
                try:
                    self.emit("ghostrun_status", "wfp_watcher_degraded", {
                        "reason": f"WFP event handling failed: {type(exc).__name__}: {exc}",
                    })
                except Exception:
                    pass

    def _native_start(self):
        """
        opens the wfp engine handle and subscribes to CLASSIFY_ALLOW net
        events, decoding each into a call to self._on_event().
        returns true on success. raises oserror naming the failed call
        and its status code on a documented native failure
        (FwpmEngineOpen0 or FwpmNetEventSubscribe4 returning non-zero),
        so start()'s emitted wfp_watcher_degraded reason is actionable
        instead of generic. start() still wraps this call in try/except
        as defense in depth either way.

        struct/enum layout verified against learn.microsoft.com's
        fwpmtypes/fwpmu pages, see the module-level comment above
        _FWP_BYTE_BLOB and each struct's own comment for what was
        checked and when. only reachable on a real windows host, every
        test that exercises start() replaces this method via monkeypatch,
        except the live-windows-only
        test_wfp_unsubscribe_and_close_succeeds_on_live_windows.

        ctypes.WINFUNCTYPE is built here, not at module level, because
        it doesn't exist at all on a non-windows host (confirmed
        empirically, same as ctypes.WinDLL). building it eagerly at
        import time would break importing this module on every
        non-windows host, which is exactly the degrade contract every
        other optional native capability here avoids breaking.
        """
        fwpuclnt = ctypes.WinDLL("Fwpuclnt")
        # every FwpmXxx0 function returns a dword, per learn.microsoft.com's
        # signature blocks cited throughout this file.
        # ctypes defaults an unconfigured function's return to signed c_int, and
        # every realistic failure status (FWP_E_* and RPC_*) is >= 0x80000000,
        # so it comes back negative under that default. that silently broke the
        # hex status this method's error messages need to show.
        # confirmed live: the unfixed code rendered a real FWP_E_* code as
        # "status=0x-7fcdffff", not a hex value an analyst could look up.
        fwpuclnt.FwpmEngineOpen0.restype = wintypes.DWORD
        fwpuclnt.FwpmNetEventSubscribe4.restype = wintypes.DWORD
        fwpuclnt.FwpmEngineClose0.restype = wintypes.DWORD

        engine_handle = wintypes.HANDLE()
        status = fwpuclnt.FwpmEngineOpen0(None, 1, None, None, ctypes.byref(engine_handle))  # RPC_C_AUTHN_WINNT = 1
        if status != 0:
            # raises instead of returning false, matching
            # _wfp_unsubscribe_and_close's pattern, so start()'s emitted
            # wfp_watcher_degraded reason names which native call failed and with
            # what status code, instead of a generic message. this is the exact gap
            # a live windows run hit.
            # status 0x80320001-0x80320039 is an FWP_E_* code, 0x80010001-0x80010122
            # is an RPC_* code, see fwpmengineopen0's return-value table on
            # learn.microsoft.com.
            raise OSError(f"FwpmEngineOpen0 failed: status=0x{status:08x}")

        self._device_path_map = build_device_path_map()

        callback_type = ctypes.WINFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(_FWPM_NET_EVENT5))

        def _callback(context, net_event_ptr):
            self._handle_native_event(net_event_ptr)

        self._callback_ref = callback_type(_callback)  # keeps this alive, ctypes doesn't hold its own reference

        subscription = _FWPM_NET_EVENT_SUBSCRIPTION0()
        events_handle = wintypes.HANDLE()
        status = fwpuclnt.FwpmNetEventSubscribe4(
            engine_handle, ctypes.byref(subscription), self._callback_ref, None, ctypes.byref(events_handle)
        )
        if status != 0:
            fwpuclnt.FwpmEngineClose0(engine_handle)
            raise OSError(f"FwpmNetEventSubscribe4 failed: status=0x{status:08x}")

        self._engine_handle = engine_handle
        self._subscription_handle = events_handle
        return True

    def _native_stop(self):
        """
        unsubscribes and closes the engine handle.
        idempotent: calling this when _engine_handle is already none
        (never started, or already stopped) is a no-op instead of trying
        to re-close an already-closed or never-opened handle.
        """
        if self._engine_handle is None:
            return
        _wfp_unsubscribe_and_close(self._engine_handle, self._subscription_handle)
        self._engine_handle = None
        self._subscription_handle = None


def _wfp_unsubscribe_and_close(engine_handle, subscription_handle):
    """
    raw native teardown, split out of _native_stop so the idempotency
    guard above it is testable on this non-windows host without needing
    ctypes.WinDLL to exist.
    calls FwpmNetEventUnsubscribe0 then FwpmEngineClose0, both confirmed
    against learn.microsoft.com. only reachable on a real windows host
    with real handles. every test above replaces this function via
    monkeypatch to test _native_stop's guard logic, except the
    live-windows test test_wfp_unsubscribe_and_close_succeeds_on_live_windows.
    """
    fwpuclnt = ctypes.WinDLL("Fwpuclnt")
    # same restype fix as _native_start, same reason: both are documented
    # dword-returning functions, and ctypes' unconfigured default (signed
    # c_int) would sign-extend any realistic failure status into a negative
    # int.
    fwpuclnt.FwpmNetEventUnsubscribe0.restype = wintypes.DWORD
    fwpuclnt.FwpmEngineClose0.restype = wintypes.DWORD
    status = fwpuclnt.FwpmNetEventUnsubscribe0(engine_handle, subscription_handle)
    if status != 0:
        raise OSError(f"FwpmNetEventUnsubscribe0 failed: status=0x{status:08x}")
    status = fwpuclnt.FwpmEngineClose0(engine_handle)
    if status != 0:
        raise OSError(f"FwpmEngineClose0 failed: status=0x{status:08x}")
