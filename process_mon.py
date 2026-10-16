import os
import hashlib
import shlex
import ctypes
from ctypes import wintypes

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
# etw native struct/constant declarations.
#
# verification status (fetched 2026-10-16):
# - provider guid {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716} (microsoft-windows-kernel-process):
#   confirmed via winevt-kb.readthedocs.io and velociraptor's windows.etw.kernelprocess docs.
# - processstart (event id 1, template v0, ProcessStartArgs) fields: confirmed from
#   raw.githubusercontent.com/repnz/etw-providers-docs manifest xml for kernel-process.
# - processstop (event id 2, template v0, ProcessStopArgs) fields: same manifest, event id 2
#   template. note ImageName is AnsiString here, UnicodeString in processstart, per the manifest.
# - EVENT_RECORD, EVENT_HEADER, EVENT_DESCRIPTOR, ETW_BUFFER_CONTEXT: fields from
#   learn.microsoft.com's evntcons/evntprov/relogger pages, cross-checked against elastic's
#   go etw consumer (github.com/elastic/beats, libbeat/reader/etw/syscall_tdh.go), which match.
# - EVENT_TRACE_PROPERTIES, WNODE_HEADER, EVENT_TRACE_LOGFILEW: fields pre-verified against
#   learn.microsoft.com's evntrace pages, used as given.
# - StartTraceW / ControlTraceW signatures: fetched from learn.microsoft.com's dedicated pages.
#   those pages' parameter prose is stale, so the signature was resolved from
#   EnableTraceEx2's worked c example instead. CONTROLTRACE_ID is confirmed (via system
#   informer's phnt headers, cross-checked against elastic's go bindings) to be a renamed
#   alias of the classic TraceHandle (ulong64), not a new type. OpenTraceW / ProcessTrace
#   signatures fetched from their own learn.microsoft.com pages.
# - numeric constants (EVENT_TRACE_CONTROL_STOP, process_trace_mode_*, EVENT_TRACE_REAL_TIME_MODE,
#   WNODE_FLAG_TRACED_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION): not
#   given as literal values on microsoft's docs pages, so confirmed against two independent
#   sources instead: the wine project's evntrace.h/wmistr.h headers and elastic's go etw
#   consumer, which agree on every value.
# - TRACE_EVENT_INFO, EVENT_PROPERTY_INFO: fields fetched from learn.microsoft.com's tdh pages,
#   cross-checked byte-for-byte against elastic's go structs (syscall_tdh.go), which match.
#   TdhGetEventInformation's and TdhFormatProperty's signatures fetched from their own pages;
#   TdhFormatProperty is deliberately not used here, see _tdh_decode_event_properties's docstring.
# =============================================================================


class _GUID(ctypes.Structure):
    # standard 16-byte win32 guid layout from guiddef.h, unchanged since win32
    # same convention wfp_connection_watcher.py's own _GUID uses
    # (ctypes.wintypes has no guid type on this platform)
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_uint8 * 8),
    ]


# {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, microsoft-windows-kernel-process
_KERNEL_PROCESS_PROVIDER_GUID = _GUID(
    0x22FB2CD6, 0x0E7B, 0x422B,
    (ctypes.c_uint8 * 8)(0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16),
)

_PROCESS_START_EVENT_ID = 1
_PROCESS_STOP_EVENT_ID = 2

_SESSION_NAME = "GhostRunProcessMonitor"
_MAXIMUM_SESSION_NAME = 1024  # learn.microsoft.com/.../nf-evntrace-starttracew
_MAX_PATH = 260

_WNODE_FLAG_TRACED_GUID = 0x00020000
_EVENT_TRACE_REAL_TIME_MODE = 0x00000100
_PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
_PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
_EVENT_TRACE_CONTROL_STOP = 1
_EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
_TRACE_LEVEL_INFORMATION = 4
_ERROR_INSUFFICIENT_BUFFER = 122
# this module only runs ProcessTrace with one real-time session handle
# on 64-bit windows (GhostRun's only supported target), so
# INVALID_PROCESSTRACE_HANDLE is always the 64-bit form
# (OpenTraceW's doc table: windows vista+, 64-bit: 0xffffffffffffffff)
# matches elastic's go consumer's own constant
_INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF


class _EVENT_DESCRIPTOR(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-evntprov-event_descriptor, fetched 2026-10-16
    _fields_ = [
        ("Id", ctypes.c_uint16),
        ("Version", ctypes.c_uint8),
        ("Channel", ctypes.c_uint8),
        ("Level", ctypes.c_uint8),
        ("Opcode", ctypes.c_uint8),
        ("Task", ctypes.c_uint16),
        ("Keyword", ctypes.c_uint64),
    ]


class _ETW_BUFFER_CONTEXT(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-relogger-etw_buffer_context, fetched 2026-10-16
    # the ProcessorNumber/alignment-vs-ProcessorIndex union is collapsed to its
    # single uint16 member, this module never reads either side of it
    _fields_ = [
        ("ProcessorIndex", ctypes.c_uint16),
        ("LoggerId", ctypes.c_uint16),
    ]


class _EVENT_HEADER(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-evntcons-event_header, fetched 2026-10-16
    # the KernelTime/UserTime-vs-ProcessorTime union is collapsed to its single
    # uint64 member, this module never reads either side of it
    _fields_ = [
        ("Size", ctypes.c_uint16),
        ("HeaderType", ctypes.c_uint16),
        ("Flags", ctypes.c_uint16),
        ("EventProperty", ctypes.c_uint16),
        ("ThreadId", ctypes.c_uint32),
        ("ProcessId", ctypes.c_uint32),
        ("TimeStamp", ctypes.c_int64),
        ("ProviderId", _GUID),
        ("EventDescriptor", _EVENT_DESCRIPTOR),
        ("ProcessorTime", ctypes.c_uint64),
        ("ActivityId", _GUID),
    ]


class _EVENT_RECORD(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-evntcons-event_record, fetched 2026-10-16
    _fields_ = [
        ("EventHeader", _EVENT_HEADER),
        ("BufferContext", _ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount", ctypes.c_uint16),
        ("UserDataLength", ctypes.c_uint16),
        ("ExtendedData", ctypes.c_void_p),  # never dereferenced by this module
        ("UserData", ctypes.c_void_p),
        ("UserContext", ctypes.c_void_p),
    ]


class _WNODE_HEADER(ctypes.Structure):
    # given by the implementation brief, pre-verified against
    # learn.microsoft.com/.../wnode-header, used as given
    class _Ctx(ctypes.Union):
        class _VersionLinkage(ctypes.Structure):
            _fields_ = [("Version", ctypes.c_ulong), ("Linkage", ctypes.c_ulong)]
        _fields_ = [("HistoricalContext", ctypes.c_uint64), ("VersionLinkage", _VersionLinkage)]

    class _TimeOrHandle(ctypes.Union):
        _fields_ = [("KernelHandle", wintypes.HANDLE), ("TimeStamp", ctypes.c_longlong)]

    _fields_ = [
        ("BufferSize", ctypes.c_ulong),
        ("ProviderId", ctypes.c_ulong),
        ("_ctx", _Ctx),
        ("_time_or_handle", _TimeOrHandle),
        ("Guid", _GUID),
        ("ClientContext", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
    ]


class _EVENT_TRACE_PROPERTIES(ctypes.Structure):
    # given by the implementation brief, pre-verified against
    # learn.microsoft.com/.../ns-evntrace-event_trace_properties, used as given
    class _AgeLimitUnion(ctypes.Union):
        _fields_ = [("AgeLimit", ctypes.c_long), ("FlushThreshold", ctypes.c_long)]

    _fields_ = [
        ("Wnode", _WNODE_HEADER),
        ("BufferSize", ctypes.c_ulong),
        ("MinimumBuffers", ctypes.c_ulong),
        ("MaximumBuffers", ctypes.c_ulong),
        ("MaximumFileSize", ctypes.c_ulong),
        ("LogFileMode", ctypes.c_ulong),
        ("FlushTimer", ctypes.c_ulong),
        ("EnableFlags", ctypes.c_ulong),
        ("_age_limit", _AgeLimitUnion),
        ("NumberOfBuffers", ctypes.c_ulong),
        ("FreeBuffers", ctypes.c_ulong),
        ("EventsLost", ctypes.c_ulong),
        ("BuffersWritten", ctypes.c_ulong),
        ("LogBuffersLost", ctypes.c_ulong),
        ("RealTimeBuffersLost", ctypes.c_ulong),
        ("LoggerThreadId", wintypes.HANDLE),
        ("LogFileNameOffset", ctypes.c_ulong),
        ("LoggerNameOffset", ctypes.c_ulong),
    ]


class _TRACE_LOGFILE_HEADER_OPAQUE(ctypes.Structure):
    # EVENT_TRACE_LOGFILEW embeds TRACE_LOGFILE_HEADER as output-only,
    # never read by this module, declared as an opaque, generously sized
    # byte buffer instead of guessing its layout
    # verify the real size with sizeof() on a live windows host, widen if it fails
    _fields_ = [("_opaque", ctypes.c_byte * 256)]


class _EVENT_TRACE_OPAQUE(ctypes.Structure):
    # same rationale as _TRACE_LOGFILE_HEADER_OPAQUE above, for
    # EVENT_TRACE_LOGFILEW's CurrentEvent field
    _fields_ = [("_opaque", ctypes.c_byte * 128)]


class _ProcessTraceModeUnion(ctypes.Union):
    _fields_ = [("LogFileMode", ctypes.c_ulong), ("ProcessTraceMode", ctypes.c_ulong)]


class _EventCallbackUnion(ctypes.Union):
    _fields_ = [("EventCallback", ctypes.c_void_p), ("EventRecordCallback", ctypes.c_void_p)]


class _EVENT_TRACE_LOGFILEW(ctypes.Structure):
    # given by the implementation brief, pre-verified against
    # learn.microsoft.com/.../ns-evntrace-event_trace_logfilew, used as given
    _anonymous_ = ("_mode", "_cb")
    _fields_ = [
        ("LogFileName", wintypes.LPWSTR),
        ("LoggerName", wintypes.LPWSTR),
        ("CurrentTime", ctypes.c_longlong),
        ("BuffersRead", ctypes.c_ulong),
        ("_mode", _ProcessTraceModeUnion),
        ("CurrentEvent", _EVENT_TRACE_OPAQUE),
        ("LogfileHeader", _TRACE_LOGFILE_HEADER_OPAQUE),
        ("BufferCallback", ctypes.c_void_p),
        ("BufferSize", ctypes.c_ulong),
        ("Filled", ctypes.c_ulong),
        ("EventsLost", ctypes.c_ulong),
        ("_cb", _EventCallbackUnion),
        ("IsKernelTrace", ctypes.c_ulong),
        ("Context", ctypes.c_void_p),
    ]


class _EVENT_PROPERTY_INFO_NONSTRUCT(ctypes.Structure):
    _fields_ = [("InType", ctypes.c_uint16), ("OutType", ctypes.c_uint16), ("MapNameOffset", ctypes.c_uint32)]


class _EVENT_PROPERTY_INFO(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-tdh-event_property_info, fetched 2026-10-16
    # cross-checked against elastic's go EventPropertyInfo struct
    # the nonStructType/structType/customSchemaType union is collapsed to
    # nonStructType alone, ProcessStart/ProcessStopArgs fields are all flat
    # scalars so this module never reads the other two union members
    _fields_ = [
        ("Flags", ctypes.c_int32),
        ("NameOffset", ctypes.c_uint32),
        ("nonStructType", _EVENT_PROPERTY_INFO_NONSTRUCT),
        ("count", ctypes.c_uint16),
        ("length", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint32),
    ]


class _TRACE_EVENT_INFO(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-tdh-trace_event_info, fetched 2026-10-16
    # cross-checked against elastic's go TraceEventInfo struct
    # two offset unions are each collapsed to one uint32 member (same byte
    # offset either way, never read)
    # EventPropertyInfoArray uses ANYSIZE_ARRAY=1 per the real struct's
    # trailing flexible-array convention: the real array can hold far more
    # than PropertyCount entries, more than this fixed field declares, so
    # _tdh_decode_event_properties walks it by raw byte offset instead of
    # indexing this field past index 0
    _fields_ = [
        ("ProviderGuid", _GUID),
        ("EventGuid", _GUID),
        ("EventDescriptor", _EVENT_DESCRIPTOR),
        ("DecodingSource", ctypes.c_int32),
        ("ProviderNameOffset", ctypes.c_uint32),
        ("LevelNameOffset", ctypes.c_uint32),
        ("ChannelNameOffset", ctypes.c_uint32),
        ("KeywordsNameOffset", ctypes.c_uint32),
        ("TaskNameOffset", ctypes.c_uint32),
        ("OpcodeNameOffset", ctypes.c_uint32),
        ("EventMessageOffset", ctypes.c_uint32),
        ("ProviderMessageOffset", ctypes.c_uint32),
        ("BinaryXMLOffset", ctypes.c_uint32),
        ("BinaryXMLSize", ctypes.c_uint32),
        ("EventNameOffset", ctypes.c_uint32),
        ("EventAttributesOffset", ctypes.c_uint32),
        ("PropertyCount", ctypes.c_uint32),
        ("TopLevelPropertyCount", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("EventPropertyInfoArray", _EVENT_PROPERTY_INFO * 1),
    ]


# tdh input types this module decodes directly from raw UserData bytes
# values confirmed against learn.microsoft.com/.../ne-tdh-_tdh_in_type
# cross-checked against elastic's go TdhIntype* constants, which agree
_TDH_INTYPE_UNICODESTRING = 1
_TDH_INTYPE_ANSISTRING = 2
_TDH_INTYPE_UINT32 = 8
_TDH_INTYPE_UINT64 = 10
_TDH_INTYPE_FILETIME = 17

# fixed wire widths (bytes) for the scalar in-types this module decodes
# not derived from EVENT_PROPERTY_INFO.length (only guaranteed nonzero
# for some fixed-size properties, zero for variable-sized types like strings)
# these are each in-type's own standard microsoft-documented wire encoding,
# the same convention every etw/tdh consumer (including elastic's go one) uses
_TDH_FIXED_WIDTHS = {
    _TDH_INTYPE_UINT32: 4,
    _TDH_INTYPE_UINT64: 8,
    _TDH_INTYPE_FILETIME: 8,
}


def _tdh_string_at(info_buf, offset):
    """
    reads a null-terminated utf-16le string at a byte offset inside a
    TRACE_EVENT_INFO buffer (e.g. EVENT_PROPERTY_INFO.NameOffset), per
    TRACE_EVENT_INFO's documented "offset from the beginning of this
    structure" convention.
    offset == 0 means "not present" per the same documentation.

    decoded explicitly as utf-16le with a manual 2-byte-nul scan, not
    via ctypes.wstring_at: wstring_at uses the host's native wchar_t
    size (2 bytes on windows, 4 on linux/glibc), which silently misreads
    this buffer on a non-windows host (confirmed by this function's own
    test failing with a ValueError before this fix). same trap
    wfp_connection_watcher.py's _decode_app_id already documents and
    avoids. windows api string data is always utf-16le regardless of
    host, so decoding explicitly as such is correct everywhere this
    module actually runs.
    """
    if not offset:
        return None
    buf_len = ctypes.sizeof(info_buf)
    if offset >= buf_len:
        return None
    raw = ctypes.string_at(ctypes.addressof(info_buf) + offset, buf_len - offset)
    end = 0
    while end + 2 <= len(raw) and raw[end:end + 2] != b"\x00\x00":
        end += 2
    return raw[:end].decode("utf-16-le")


def _tdh_get_event_info(event_record_ptr):
    """
    calls TdhGetEventInformation (tdh.dll), growing the buffer using the
    documented ERROR_INSUFFICIENT_BUFFER two-call pattern: probe with a
    zero-size buffer, then allocate what the probe reports and call again.
    returns the raw ctypes buffer backing a _TRACE_EVENT_INFO (its own
    fields plus the trailing EventPropertyInfoArray and name-string table
    all live in this one buffer).
    raises oserror on any non-success status.
    verified against learn.microsoft.com/.../nf-tdh-TdhGetEventInformation,
    fetched 2026-10-16, the two-call growth pattern matches elastic's go
    consumer's own call site.
    """
    tdh = ctypes.WinDLL("tdh")
    tdh.TdhGetEventInformation.argtypes = [
        ctypes.POINTER(_EVENT_RECORD), ctypes.c_ulong, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong),
    ]
    tdh.TdhGetEventInformation.restype = ctypes.c_ulong

    buffer_size = ctypes.c_ulong(0)
    status = tdh.TdhGetEventInformation(event_record_ptr, 0, None, None, ctypes.byref(buffer_size))
    if status != _ERROR_INSUFFICIENT_BUFFER:
        raise OSError(f"TdhGetEventInformation (size probe) failed: {status}")

    info_buf = ctypes.create_string_buffer(buffer_size.value)
    status = tdh.TdhGetEventInformation(
        event_record_ptr, 0, None, ctypes.cast(info_buf, ctypes.c_void_p), ctypes.byref(buffer_size),
    )
    if status != 0:
        raise OSError(f"TdhGetEventInformation failed: {status}")
    return info_buf


def _tdh_decode_event_properties(event_record_ptr):
    """
    decodes a manifest-based event's UserData into {property_name: value}.
    uses TdhGetEventInformation for property metadata (names, in-types,
    fixed lengths), looked up by name and walked in order rather than a
    fixed byte offset, so this stays correct even if a live build fires a
    newer template version that only appends fields.

    deliberately does not call TdhFormatProperty, even though microsoft's
    own guidance for decoding UserData names it. TdhFormatProperty returns
    a formatted, locale-dependent display string for every property,
    including a human-readable date for filetime, not the raw 100ns-tick
    integer filetime_to_epoch_seconds (native_paths.py) needs. using it
    would mean re-parsing a formatted string instead of reading the
    documented wire encoding directly, trading one risk for a worse one.

    instead this reads each property's raw bytes per its in-type's own
    standard wire encoding: uint32/uint64 are fixed-width little-endian
    integers, filetime is a little-endian 100ns-tick integer (what
    filetime_to_epoch_seconds expects), unicode/AnsiString is a
    null-terminated string. that's the same approach every etw/tdh
    consumer takes for primitive types, TdhFormatProperty exists mainly
    for types this module never needs (maps, arrays, structs, ipv6, ...).

    an in-type outside this small supported set makes decoding the rest
    of the event's properties unsafe (their byte offsets can't be
    located anymore), so this raises rather than guessing. callers treat
    that like any other decode failure: skip the event, emit a degrade
    status, never crash.
    """
    info_buf = _tdh_get_event_info(event_record_ptr)
    info = ctypes.cast(info_buf, ctypes.POINTER(_TRACE_EVENT_INFO)).contents
    array_offset = _TRACE_EVENT_INFO.EventPropertyInfoArray.offset
    prop_size = ctypes.sizeof(_EVENT_PROPERTY_INFO)
    base_addr = ctypes.addressof(info_buf)

    event_record = event_record_ptr.contents
    data_length = event_record.UserDataLength
    data = ctypes.string_at(event_record.UserData, data_length) if data_length and event_record.UserData else b""

    result = {}
    pos = 0
    for i in range(info.TopLevelPropertyCount):
        prop = ctypes.cast(base_addr + array_offset + i * prop_size, ctypes.POINTER(_EVENT_PROPERTY_INFO)).contents
        name = _tdh_string_at(info_buf, prop.NameOffset)
        in_type = prop.nonStructType.InType

        if in_type in (_TDH_INTYPE_UNICODESTRING, _TDH_INTYPE_ANSISTRING):
            is_wide = in_type == _TDH_INTYPE_UNICODESTRING
            step = 2 if is_wide else 1
            terminator = b"\x00\x00" if is_wide else b"\x00"
            end = pos
            while end + step <= len(data) and data[end:end + step] != terminator:
                end += step
            value = data[pos:end].decode("utf-16-le" if is_wide else "ascii", errors="replace")
            pos = min(end + step, len(data))
        elif in_type in _TDH_FIXED_WIDTHS:
            width = _TDH_FIXED_WIDTHS[in_type]
            if pos + width > len(data):
                raise OSError(f"ETW UserData truncated decoding property '{name}' (in-type {in_type})")
            value = int.from_bytes(data[pos:pos + width], "little", signed=False)
            pos += width
        else:
            raise OSError(f"unsupported TDH in-type {in_type} decoding property '{name}'")

        if name is not None:
            result[name] = value

    return result


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
        self._session_handle = None
        self._props_buf = None
        self._trace_handle = None
        self._callback_ref = None  # keep the ctypes callback alive, see _process_trace

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
        normalized = os.path.normcase(path)
        matches = [
            pid for pid, image_path in list(self.image_paths.items())
            if os.path.normcase(image_path) == normalized
        ]
        return matches[0] if len(matches) == 1 else None

    def _handle_etw_process_start(self, pid, ppid, image_path, create_time, name):
        self.parent_map[pid] = ppid
        if self.is_descendant(pid, self.root_pid):
            self.malware_pids.add(pid)
            self.image_paths[pid] = image_path
            self.emit("process", "process_create", _etw_process_start_to_evidence(
                pid=pid, ppid=ppid, name=name, image_path=image_path, create_time=create_time,
            ))
            self._trigger_mutex_scan()

    def _handle_etw_process_stop(self, pid, name):
        self.image_paths.pop(pid, None)
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
        _process_trace). dispatches ProcessStart (event id 1) and
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
            props = _tdh_decode_event_properties(event_record_ptr)
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

    def _start_etw_session(self):
        """
        StartTraceW + EnableTraceEx2, following microsoft's own reference
        example at learn.microsoft.com/.../nf-evntrace-EnableTraceEx2,
        fetched 2026-10-16, using this module's session name and the
        kernel-process provider guid, with EnableParameters=null (no
        payload/scope filtering needed).
        raises oserror on any native failure, run() catches it and
        degrades. see the module-level verification comment above for
        what was fetched/confirmed for each struct, signature, and
        constant used here.
        """
        buffer_size = ctypes.sizeof(_EVENT_TRACE_PROPERTIES) + (_MAXIMUM_SESSION_NAME + _MAX_PATH) * 2
        props_buf = ctypes.create_string_buffer(buffer_size)
        props = ctypes.cast(props_buf, ctypes.POINTER(_EVENT_TRACE_PROPERTIES)).contents
        props.Wnode.BufferSize = buffer_size
        props.Wnode.Flags = _WNODE_FLAG_TRACED_GUID
        props.LogFileMode = _EVENT_TRACE_REAL_TIME_MODE
        props.LoggerNameOffset = ctypes.sizeof(_EVENT_TRACE_PROPERTIES)
        # LogFileNameOffset left 0: no backing file, real-time only
        # Wnode.Guid left all-zero: etw generates a new session guid

        advapi32 = ctypes.WinDLL("advapi32")
        advapi32.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_wchar_p, ctypes.c_void_p]
        advapi32.StartTraceW.restype = ctypes.c_ulong

        session_handle = ctypes.c_uint64(0)
        status = advapi32.StartTraceW(
            ctypes.byref(session_handle), _SESSION_NAME, ctypes.cast(props_buf, ctypes.c_void_p),
        )
        if status != 0:
            raise OSError(f"StartTraceW failed: {status}")

        self._session_handle = session_handle.value
        self._props_buf = props_buf  # keep alive, ControlTraceW (stop) reuses this same buffer

        advapi32.EnableTraceEx2.argtypes = [
            ctypes.c_uint64, ctypes.POINTER(_GUID), ctypes.c_ulong, ctypes.c_uint8,
            ctypes.c_uint64, ctypes.c_uint64, ctypes.c_ulong, ctypes.c_void_p,
        ]
        advapi32.EnableTraceEx2.restype = ctypes.c_ulong
        status = advapi32.EnableTraceEx2(
            self._session_handle, ctypes.byref(_KERNEL_PROCESS_PROVIDER_GUID),
            _EVENT_CONTROL_CODE_ENABLE_PROVIDER, _TRACE_LEVEL_INFORMATION,
            0, 0, 0, None,
        )
        if status != 0:
            self._stop_etw_session()
            raise OSError(f"EnableTraceEx2 failed: {status}")

    def _stop_etw_session(self):
        """
        ControlTraceW(..., EVENT_TRACE_CONTROL_STOP) stops the session,
        which also makes the blocking real-time ProcessTrace call in
        _process_trace return, per its documented remarks.
        safe to call from a different thread than the one blocked in
        ProcessTrace, that's the point: stop() runs on whatever thread
        calls it.
        idempotent: calling it when _session_handle is already none
        (never started, or already stopped) is a no-op.
        """
        if self._session_handle is None:
            return
        try:
            advapi32 = ctypes.WinDLL("advapi32")
            advapi32.ControlTraceW.argtypes = [
                ctypes.c_uint64, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_ulong,
            ]
            advapi32.ControlTraceW.restype = ctypes.c_ulong
            advapi32.ControlTraceW(
                self._session_handle, None, ctypes.cast(self._props_buf, ctypes.c_void_p),
                _EVENT_TRACE_CONTROL_STOP,
            )
        finally:
            self._session_handle = None
            self._props_buf = None

    def _process_trace(self):
        """
        OpenTraceW + the blocking ProcessTrace call. attaches to this
        module's own already-started real-time session by name
        (LoggerName, not LogFileName) and delivers events to
        _etw_event_record_callback via PROCESS_TRACE_MODE_EVENT_RECORD.
        blocks until stop() calls ControlTraceW (_stop_etw_session) or a
        genuine error occurs.
        raises oserror on a native failure opening the trace or from
        ProcessTrace itself, run() catches this and degrades.
        """
        advapi32 = ctypes.WinDLL("advapi32")
        advapi32.OpenTraceW.argtypes = [ctypes.c_void_p]
        advapi32.OpenTraceW.restype = ctypes.c_uint64
        advapi32.ProcessTrace.argtypes = [
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p,
        ]
        advapi32.ProcessTrace.restype = ctypes.c_ulong

        logfile = _EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = _SESSION_NAME
        logfile.ProcessTraceMode = _PROCESS_TRACE_MODE_REAL_TIME | _PROCESS_TRACE_MODE_EVENT_RECORD
        callback_type = ctypes.WINFUNCTYPE(None, ctypes.POINTER(_EVENT_RECORD))
        self._callback_ref = callback_type(self._etw_event_record_callback)
        logfile.EventRecordCallback = ctypes.cast(self._callback_ref, ctypes.c_void_p)

        trace_handle = advapi32.OpenTraceW(ctypes.byref(logfile))
        if trace_handle == _INVALID_PROCESSTRACE_HANDLE:
            raise OSError("OpenTraceW failed")
        self._trace_handle = trace_handle

        try:
            handle_array = (ctypes.c_uint64 * 1)(trace_handle)
            status = advapi32.ProcessTrace(handle_array, 1, None, None)
            if status != 0:
                raise OSError(f"ProcessTrace failed: {status}")
        finally:
            advapi32.CloseTrace.argtypes = [ctypes.c_uint64]
            advapi32.CloseTrace.restype = ctypes.c_ulong
            advapi32.CloseTrace(self._trace_handle)
            self._trace_handle = None

    def run(self):
        self.emit("process", "monitor_start", {"root_pid": self.root_pid})
        # seeding runs unconditionally, before the trace-session-start attempt,
        # not nested in the same try/except: a failed etw start must not also
        # cost us the already-running-process lineage backfill on top of losing
        # live tracking
        self._seed_existing_processes()
        self._device_path_map = build_device_path_map()
        try:
            self._start_etw_session()
        except Exception as exc:
            self.emit("ghostrun_status", "process_monitor_degraded", {"error": str(exc)})
            self.emit("process", "monitor_stop", {})
            return
        try:
            self._process_trace()
        except Exception as exc:
            self.emit("ghostrun_status", "process_monitor_degraded", {"error": str(exc)})
        finally:
            # defensive: normally stop() already did this (ProcessTrace's return is
            # what that produces), but a ProcessTrace exit for any other reason (a
            # real error, not stop() being called) must not leave the etw session
            # running forever either
            self._stop_etw_session()
            self.emit("process", "monitor_stop", {})

    def stop(self):
        self._stop_etw_session()
