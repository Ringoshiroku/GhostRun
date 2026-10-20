import os
import hashlib
import shlex
import ctypes

import etw_session
from native_paths import build_device_path_map, filetime_to_epoch_seconds, to_dos_path

_HASH_CACHE = {}


def _hash_image(path):
    if not path:
        return None

    if path in _HASH_CACHE:
        return _HASH_CACHE[path]

    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
    except OSError:
        return None

    _HASH_CACHE[path] = digest
    return digest


def _normalize_cmdline(cmdline_raw):
    """
    always return a list of strings, no matter the source.
    wmi's CommandLine is a single string (or none), psutil's cmdline is already a list.
    downstream code (persistence_detector, timeline_builder, report_builder) does
    " ".join(cmdline) and must never see none or a bare string, joining a string
    joins its characters, not its words.
    """
    if not cmdline_raw:
        return []
    if isinstance(cmdline_raw, list):
        return [str(part) for part in cmdline_raw]
    try:
        return shlex.split(cmdline_raw)
    except ValueError:
        # if the quoting is malformed, shlex raises
        # fall back to a plain split instead of losing the command line
        return cmdline_raw.split()


def _build_process_create_evidence(pid, ppid, name, cmdline_raw, image_path, create_time):
    return {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "cmdline": _normalize_cmdline(cmdline_raw),
        "image_path": image_path,
        "image_sha256": _hash_image(image_path) if image_path else None,
        "create_time": create_time,
    }


def _etw_process_start_to_evidence(pid, ppid, name, image_path, create_time):
    """
    builds the same evidence shape _build_process_create_evidence
    already produces from wmi, but from an etw-decoded processstart event.
    ProcessStartArgs (template v0) carries no CommandLine field like
    wmi's win32_process did, so cmdline is always [] here, matching
    _normalize_cmdline's contract for an absent cmdline_raw.
    if a later live test needs CommandLine and a newer template version
    still doesn't have it, that's a new finding to raise then, not a
    guess to make now.
    """
    return _build_process_create_evidence(
        pid=pid, ppid=ppid, name=name, cmdline_raw=None,
        image_path=image_path, create_time=create_time,
    )


# =============================================================================
# microsoft-windows-kernel-process-specific etw provider knowledge.
#
# provider-agnostic etw session/tdh plumbing (native struct layouts,
# StartTraceW/EnableTraceEx2/OpenTraceW/ProcessTrace/ControlTraceW, and
# TRACE_EVENT_INFO decoding) moved to etw_session.py, shared with any later
# etw consumer built the same way, see its own module comment for those
# citations. what stays here is specific to this one provider:
#
# verification status (fetched 2026-10-16):
# - provider guid {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716} (microsoft-windows-kernel-process):
#   confirmed via winevt-kb.readthedocs.io and velociraptor's windows.etw.kernelprocess docs.
# - processstart (event id 1, template v0, ProcessStartArgs) fields: confirmed from
#   raw.githubusercontent.com/repnz/etw-providers-docs manifest xml for kernel-process.
# - processstop (event id 2, template v0, ProcessStopArgs) fields: same manifest, event id 2
#   template. note ImageName is AnsiString here, UnicodeString in processstart, per the manifest.
# - processstart template versions 1-3 and processstop versions 1-2: re-read from the same
#   repnz manifest url. a live session sends the newest version (processstart v3, template
#   ProcessRundownArgs_V1), which carries a win:sid MandatoryLabel before ImageName, see
#   etw_session.decode_event_properties for how that's walked.
# - WINEVENT_KEYWORD_PROCESS = 0x10: same manifest's <keywords> block, events 1 and 2 are
#   both declared under it.
# =============================================================================


# {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, microsoft-windows-kernel-process
_KERNEL_PROCESS_PROVIDER_GUID = etw_session.GUID(
    0x22FB2CD6, 0x0E7B, 0x422B,
    (ctypes.c_uint8 * 8)(0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16),
)

_PROCESS_START_EVENT_ID = 1
_PROCESS_STOP_EVENT_ID = 2

# microsoft-windows-kernel-process manifest <keywords> block (repnz url above):
# WINEVENT_KEYWORD_PROCESS mask="0x10", events 1 (ProcessStart) and 2 (ProcessStop)
# are declared under it
# passed as EnableTraceEx2's MatchAnyKeyword instead of 0: per its own remarks, for a
# manifest provider a MatchAnyKeyword of 0 is treated the same as 0xffffffffffffffff,
# i.e. it enables all event keywords (thread, image-load, job, ...), which only adds
# real-time buffer pressure for events this module discards
_WINEVENT_KEYWORD_PROCESS = 0x10


def _resolve_image_name_and_path(raw_image_name, device_path_map):
    """
    shared by the ProcessStart/ProcessStop decode paths.
    resolves a decoded ImageName (an nt device-form path, per
    native_paths.py's to_dos_path docstring) to its dos-form path, and
    derives a short display name from it like a file's own basename.
    returns (image_path, name), both none if raw_image_name was empty/none.
    """
    if not raw_image_name:
        return None, None
    image_path = to_dos_path(raw_image_name, device_path_map)
    name = os.path.basename(image_path) if image_path else None
    return image_path, name


class ProcessMonitor:
    def __init__(self, root_pid, emit_func, malware_pids=None, mutex_monitor=None):
        self.root_pid = root_pid
        self.emit = emit_func
        self.mutex_monitor = mutex_monitor

        self.parent_map = {}
        self.image_paths = {}  # pid to image path, updated live as descendants appear and exit
        # shared mutable set, same object as ghostrun.py's MALWARE_PIDS global
        # passed by reference, not copied
        # grows as this monitor discovers real descendants
        # that's what lets emit()'s noise filter correctly accept network evidence
        # for a child process instead of dropping it
        self.malware_pids = malware_pids if malware_pids is not None else set()

        self._device_path_map = None
        self._session = etw_session.EtwSession(
            session_name="GhostRunProcessMonitor",
            provider_guid=_KERNEL_PROCESS_PROVIDER_GUID,
            keyword_mask=_WINEVENT_KEYWORD_PROCESS,
            trace_level=etw_session._TRACE_LEVEL_INFORMATION,
            event_record_callback=self._etw_event_record_callback,
        )

    def _trigger_mutex_scan(self):
        """
        requests a triggered mutexmonitor scan.
        trigger_scan() (mutex_watch.py) is non-blocking, it only sets a wake
        event, so this call can't fail the way the old synchronous version
        could. a scan failure now shows up via MutexMonitor.run()'s own
        ghostrun_status emission, on its own thread, not here.
        """
        if self.mutex_monitor is None:
            return
        self.mutex_monitor.trigger_scan()

    def is_descendant(self, pid, root_pid):
        """
        check if pid is a descendant of root_pid.
        guards against a cycle in parent_map (e.g. pid reuse making
        parent_map[a]=b and parent_map[b]=a), which would otherwise loop forever.
        needed because this now gets called with arbitrary system-wide pids from
        the network-attribution path, not just ones already known safe.
        """
        current = pid
        visited = set()
        while current:
            if current == root_pid:
                return True
            if current in visited:
                return False
            visited.add(current)
            current = self.parent_map.get(current)
        return False

    def resolve_path_to_pid(self, path):
        """
        return the one tracked descendant pid whose image path matches `path`.
        returns none if zero or more than one match.
        two live descendants with the same executable path are treated as
        no match on purpose, picking a specific wrong process would be worse.

        comparison is case-insensitive (os.path.normcase): windows paths are
        case-insensitive by convention, and different sources (wmi, psutil,
        wfp/etw) can report the same real path with different casing.
        nt device-style paths (e.g. \\Device\\HarddiskVolume3\\...) are
        resolved to dos form by to_dos_path before reaching here.
        """
        # list() takes a snapshot before iterating
        # _handle_etw_process_start/_handle_etw_process_stop mutate image_paths
        # from another thread, iterating it live could raise
        # "dictionary changed size during iteration"
        # image_paths can legitimately hold none (psutil AccessDenied on exe during
        # seeding, or an empty etw ImageName), skip those instead of letting
        # normcase(none) raise TypeError, which on the wfp native-callback path
        # would otherwise kill attribution silently
        normalized = os.path.normcase(path)
        matches = [
            pid for pid, image_path in list(self.image_paths.items())
            if image_path and os.path.normcase(image_path) == normalized
        ]
        return matches[0] if len(matches) == 1 else None

    def _handle_etw_process_start(self, pid, ppid, image_path, create_time, name):
        # run() starts the etw session before seeding (to close the gap a child
        # spawned mid-seed would otherwise fall into), so the same live pid can
        # be reported by both
        # the first sighting wins, a second one must not emit a duplicate
        # process_create
        if pid in self.malware_pids and pid in self.image_paths:
            return
        self.parent_map[pid] = ppid
        if self.is_descendant(pid, self.root_pid):
            self.malware_pids.add(pid)
            self.image_paths[pid] = image_path
            self.emit("process", "process_create", _etw_process_start_to_evidence(
                pid=pid, ppid=ppid, name=name, image_path=image_path, create_time=create_time,
            ))
            self._trigger_mutex_scan()

    def _handle_etw_process_stop(self, pid, name):
        # ProcessStop's own ImageName is confirmed, via two separate live windows
        # runs, to come back from the kernel genuinely truncated to a short fixed
        # length (e.g. "ghostrun_test_" for "ghostrun_test_harness.exe"), with
        # nothing after it in the raw UserData buffer at all
        # not a manifest-declared fixed-length property, that case is handled
        # correctly elsewhere in etw_session.decode_event_properties, confirmed
        # because fixing that case didn't change this symptom between the two runs
        # whatever the real reason this field is short on exit telemetry, the fix
        # doesn't need to know why: this pid's own ProcessStart event already
        # recorded its full, untruncated image path, so prefer that over
        # ProcessStop's own unreliable value whenever we have it
        tracked_path = self.image_paths.pop(pid, None)
        if tracked_path:
            name = os.path.basename(tracked_path)
        if self.is_descendant(pid, self.root_pid):
            self.emit("process", "process_terminate", {"pid": pid, "name": name})
            self._trigger_mutex_scan()

    def _seed_existing_processes(self):
        """
        backfill lineage for every process already running when we attach
        to the session. also emit process_create for the root sample and
        any descendants already running.
        an etw real-time session only sees events for processes created
        after the session starts, so without this, the root sample's own
        creation, and anything that needs to see a process_create first,
        would never show up.
        """
        import psutil

        for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "exe"]):
            try:
                info = proc.info
                pid = info["pid"]
                ppid = info["ppid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            self.parent_map[pid] = ppid
            if self.is_descendant(pid, self.root_pid):
                self.malware_pids.add(pid)
                image_path = info.get("exe")
                self.image_paths[pid] = image_path
                self.emit("process", "process_create", _build_process_create_evidence(
                    pid=pid,
                    ppid=ppid,
                    name=info.get("name"),
                    cmdline_raw=info.get("cmdline"),
                    image_path=image_path,
                    create_time=None,
                ))
                self._trigger_mutex_scan()

    def _etw_event_record_callback(self, event_record_ptr):
        """
        EventRecordCallback for the real-time trace session (see
        etw_session.EtwSession.process_trace). dispatches ProcessStart (event id 1) and
        ProcessStop (event id 2) to the handlers above.
        any decode failure degrades (emits ghostrun_status) instead of
        raising out of this ctypes callback: an uncaught exception here
        would otherwise just be silently printed or ignored by ctypes on
        etw's own callback thread, losing the event (and every later one,
        if the cause repeats) with no trail.
        """
        event_record = event_record_ptr.contents
        event_id = event_record.EventHeader.EventDescriptor.Id
        if event_id not in (_PROCESS_START_EVENT_ID, _PROCESS_STOP_EVENT_ID):
            return

        try:
            props = etw_session.decode_event_properties(event_record_ptr)
            if event_id == _PROCESS_START_EVENT_ID:
                pid = props["ProcessID"]
                ppid = props["ParentProcessID"]
                create_time = filetime_to_epoch_seconds(props["CreateTime"])
                image_path, name = _resolve_image_name_and_path(props.get("ImageName"), self._device_path_map)
                self._handle_etw_process_start(
                    pid=pid, ppid=ppid, image_path=image_path, create_time=create_time, name=name,
                )
            else:
                pid = props["ProcessID"]
                _, name = _resolve_image_name_and_path(props.get("ImageName"), self._device_path_map)
                self._handle_etw_process_stop(pid=pid, name=name)
        except Exception as exc:
            self.emit("ghostrun_status", "process_monitor_degraded", {
                "error": f"ETW event decode/dispatch failed: {exc}",
            })

    def run(self):
        self.emit("process", "monitor_start", {"root_pid": self.root_pid})
        self._device_path_map = build_device_path_map()
        # the etw session starts before seeding: the sample is already running
        # (popen happens before this thread starts), so seeding first would
        # leave a window where a child spawned after psutil's enumeration but
        # before the session went live is never seen, losing its whole subtree
        # seeding still runs unconditionally, whether the start succeeded or
        # failed: a failed etw start must not also cost the already-running-
        # process lineage backfill on top of losing live tracking
        # a pid seen by both is handled by _handle_etw_process_start's already-
        # seeded check
        try:
            self._session.start()
            start_error = None
        except Exception as exc:
            start_error = exc
        try:
            self._seed_existing_processes()
        except Exception:
            # a session that did start must not be leaked by a seeding failure
            # (it would outlive this process, see EtwSession.start's
            # ERROR_ALREADY_EXISTS handling)
            self._session.stop()
            raise
        if start_error is not None:
            self.emit("ghostrun_status", "process_monitor_degraded", {"error": str(start_error)})
            self.emit("process", "monitor_stop", {})
            return
        try:
            self._session.process_trace()
        except Exception as exc:
            self.emit("ghostrun_status", "process_monitor_degraded", {"error": str(exc)})
        finally:
            # defensive: normally stop() already did this (ProcessTrace's return is
            # what that produces), but a ProcessTrace exit for any other reason (a
            # real error, not stop() being called) must not leave the etw session
            # running forever either
            self._session.stop()
            self.emit("process", "monitor_stop", {})

    def stop(self):
        self._session.stop()
