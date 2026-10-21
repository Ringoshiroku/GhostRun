import collections
import ctypes
import threading
import time

import etw_session

# =============================================================================
# Microsoft-Windows-Kernel-Network-specific ETW provider knowledge.
#
# provider-agnostic ETW session/TDH plumbing (native struct layouts,
# StartTraceW/EnableTraceEx2/OpenTraceW/ProcessTrace/ControlTraceW, and
# TRACE_EVENT_INFO decoding) lives in etw_session.py, shared with
# process_mon.py's Kernel-Process consumer. see that module's comment
# for those citations. this file only covers what's specific to this
# one provider.
#
# verification status (this task):
# - provider GUID {7dd42a49-5329-4832-8dfd-43d979153a88}
#   (Microsoft-Windows-Kernel-Network): confirmed live on FlareVM via
#   logman/tracerpt and a pywintrace spike, real PIDs across several
#   processes. see this task's design doc for details.
# - connection-attempted (TCP, event ID 12) and the UDP data-sent event
#   (ID 42): both confirmed live on FlareVM under real traffic with
#   correct PID attribution. UDP has no handshake, so the first ID 42
#   for a flow stands in for WFP's CLASSIFY_ALLOW event.
# - PID property name ("PID"): not independently verified against a
#   decoded event on this dev host. backed by real evidence though:
#   Velociraptor's published artifact for this exact provider GUID
#   reads the process from EventData.PID. deliberately not using
#   EVENT_HEADER.ProcessId, since Microsoft's own docs warn some
#   network events get logged by a separate thread, making that PID
#   unreliable.
# - local/remote address and port property names
#   (_PROPERTY_LOCAL_PORT, _PROPERTY_REMOTE_PORT,
#   _PROPERTY_LOCAL_ADDRESS, _PROPERTY_REMOTE_ADDRESS): confirmed live
#   on FlareVM as "sport"/"dport"/"saddr"/"daddr". a real "Connection
#   attempted" event's own TDH decode error named the "dport" property
#   directly, see etw_session.py's _TDH_INTYPE_UINT16 citation. a
#   public capture of this same provider/event independently
#   corroborates the full field layout, see wiki.tcl-lang.org/page/
#   Event+Tracing+for+Windows.
# - keyword mask: deliberately 0 (MatchAnyKeyword), not a guessed bit.
#   the real per-event keyword wasn't confirmed this session, unlike
#   Kernel-Process's confirmed keyword. EnableTraceEx2's own docs say
#   a 0 mask enables all keywords, a safe documented default. can be
#   narrowed later once the real keyword is known.
# =============================================================================


# Microsoft-Windows-Kernel-Network provider GUID: {7dd42a49-5329-4832-8dfd-43d979153a88}.
_KERNEL_NETWORK_PROVIDER_GUID = etw_session.GUID(
    0x7DD42A49, 0x5329, 0x4832,
    (ctypes.c_uint8 * 8)(0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88),
)

# "Connection attempted." is TCP connection establishment.
# "Data sent over UDP protocol." is the UDP analog, since UDP has no
# handshake.
# both confirmed live via logman/tracerpt, see the module comment above.
_TCP_CONNECTION_ATTEMPTED_EVENT_ID = 12
_UDP_DATA_SENT_EVENT_ID = 42
_CONNECTION_EVENT_IDS = (_TCP_CONNECTION_ATTEMPTED_EVENT_ID, _UDP_DATA_SENT_EVENT_ID)

# confirmed, see module comment above: Velociraptor's published artifact
# for this exact provider GUID reads the process from EventData.PID.
_PROPERTY_PID = "PID"

# confirmed, see module comment above.
_PROPERTY_LOCAL_PORT = "sport"
_PROPERTY_REMOTE_PORT = "dport"
_PROPERTY_LOCAL_ADDRESS = "saddr"
_PROPERTY_REMOTE_ADDRESS = "daddr"

# MatchAnyKeyword=0 enables all keywords, see module comment above.
_KERNEL_NETWORK_KEYWORD_MASK = 0

_MAX_TRACKED_EVENTS = 10000


class EtwConnectionWatcher:
    """
    event-driven per-process network attribution via the
    Microsoft-Windows-Kernel-Network ETW provider.

    replaces WfpConnectionWatcher: its FwpmNetEventSubscribe4
    subscription was confirmed, via live FlareVM testing, to deliver
    zero events under every condition tested. see this task's design
    doc for the full account.

    keeps the same resolve_pid(port, timestamp) contract, so
    network_watch.py's _resolve_attributed_pid needs no changes.

    unlike the old WFP path, this watcher sees every network event on
    the box, not just ones already mapped to a known descendant. so
    the malware-tree filter (process_monitor.is_descendant) is applied
    explicitly here, at storage time in _on_event_record, so an
    unrelated process's connection can never get attributed to the
    malware by port/timing coincidence.
    """

    def __init__(self, process_monitor, emit_func):
        self.process_monitor = process_monitor
        self.emit = emit_func
        self._events_lock = threading.Lock()
        self._events = collections.deque(maxlen=_MAX_TRACKED_EVENTS)  # [(timestamp, local_port, pid)]
        self._callback_failure_notified = False
        self._thread = None
        # diagnostic-only counters, not used by resolve_pid.
        # a run where resolve_pid matches nothing looks the same either way:
        # zero events delivered, or plenty delivered and the malware-tree
        # filter discarded them all. connection_monitor_summary (see stop())
        # reports both counts so that distinction doesn't need ad hoc
        # instrumentation every time it comes up.
        self._events_received = 0
        self._events_stored = 0
        self._session = etw_session.EtwSession(
            session_name="GhostRunNetworkMonitor",
            provider_guid=_KERNEL_NETWORK_PROVIDER_GUID,
            keyword_mask=_KERNEL_NETWORK_KEYWORD_MASK,
            trace_level=etw_session._TRACE_LEVEL_INFORMATION,
            event_record_callback=self._etw_event_record_callback,
        )

    def resolve_pid(self, local_port, approx_timestamp):
        """
        returns the PID whose recorded connection on `local_port` is
        closest in time to approx_timestamp, or None if that port was
        never recorded.

        same contract as WfpConnectionWatcher.resolve_pid
        (wfp_connection_watcher.py:465), carried over unchanged: pure
        and provider-agnostic.
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

    def _on_event_record(self, props):
        """
        applies the malware-tree filter and records the event, only
        for a confirmed descendant of the sample's own root_pid.

        timestamped with time.time() when this handler runs. delivery
        is real-time so the delay against the event's own kernel
        timestamp is negligible, and resolve_pid only needs
        nearest-in-time anyway, so there's no need to decode a payload
        timestamp field whose name was never confirmed.
        """
        pid = props[_PROPERTY_PID]
        if not self.process_monitor.is_descendant(pid, self.process_monitor.root_pid):
            return
        local_port = props[_PROPERTY_LOCAL_PORT]
        timestamp = time.time()
        with self._events_lock:
            self._events.append((timestamp, local_port, pid))
            self._events_stored += 1

    def _etw_event_record_callback(self, event_record_ptr):
        """
        EventRecordCallback for the real-time trace session (see
        etw_session.EtwSession.process_trace). dispatches TCP
        connection-attempted (event ID 12) and UDP data-sent (event ID
        42) events to _on_event_record.

        never lets an exception escape this ctypes callback, since
        ctypes silently swallows one raised inside a native callback.
        same contract as WfpConnectionWatcher._handle_native_event and
        process_mon.py's _etw_event_record_callback.

        the degrade status is only emitted on the first failure, since
        this fires per connection and a systematic failure would
        otherwise flood the evidence stream with one status event per
        connection. later events are still attempted normally.
        """
        event_record = event_record_ptr.contents
        event_id = event_record.EventHeader.EventDescriptor.Id
        if event_id not in _CONNECTION_EVENT_IDS:
            return
        self._events_received += 1

        try:
            props = etw_session.decode_event_properties(event_record_ptr)
            self._on_event_record(props)
        except Exception as exc:
            if not self._callback_failure_notified:
                self._callback_failure_notified = True
                try:
                    self.emit("ghostrun_status", "connection_monitor_degraded", {
                        "reason": f"ETW event handling failed: {type(exc).__name__}: {exc}",
                    })
                except Exception:
                    pass

    def start(self):
        """
        starts the ETW session synchronously, so a start failure is
        caught and reported before this method returns. mirrors
        process_mon.py's process_monitor_degraded pattern, so a
        failure here is never silent.

        only on success does it spin up a dedicated thread to run the
        blocking event pump (EtwSession.process_trace). same
        run()-as-thread-target/stop()-via-ControlTraceW model as
        ProcessMonitor. no COM initialization needed, unlike the old
        WFP watcher's FwpmNetEventSubscribe4 subscription.
        """
        try:
            self._session.start()
        except Exception as exc:
            self.emit("ghostrun_status", "connection_monitor_degraded", {"error": str(exc)})
            return

        self._thread = threading.Thread(target=self._run, daemon=True, name="EtwConnectionWatcher")
        self._thread.start()

    def _run(self):
        """
        thread target: blocks in EtwSession.process_trace until stop()
        calls ControlTraceW to unblock it, or a genuine error occurs.

        degrades rather than raising, same contract as start()'s own
        session-start failure path.
        """
        try:
            self._session.process_trace()
        except Exception as exc:
            self.emit("ghostrun_status", "connection_monitor_degraded", {"error": str(exc)})
        finally:
            self._session.stop()

    def stop(self):
        """
        stops the session (ControlTraceW, which also unblocks the
        dedicated thread's process_trace call) and waits for that
        thread to finish.

        idempotent: EtwSession.stop() is already a no-op when never
        started or already stopped, and a None/dead self._thread
        (start() never called or never succeeded) is simply skipped.

        emits a connection_monitor_summary status with the raw
        received/stored counts after the thread has joined, so nothing
        is still writing to them. this is the clearest way to tell a
        "provider delivered nothing" run apart from a "provider
        delivered plenty but the malware-tree filter discarded all of
        it" run, since the two otherwise look the same from
        resolve_pid's output alone. only emitted when start() actually
        ran (self._thread is not None); a watcher that never started
        has nothing to report.
        """
        self._session.stop()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=10)
        if self._thread is not None:
            self.emit("ghostrun_status", "connection_monitor_summary", {
                "events_received": self._events_received,
                "events_stored": self._events_stored,
            })
