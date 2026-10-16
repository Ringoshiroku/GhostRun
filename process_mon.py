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
# - EVENT_TRACE_PROPERTIES, WNODE_HEADER: fields pre-verified against learn.microsoft.com's
#   evntrace/wnode-header pages, used as given.
# - EVENT_TRACE_LOGFILEW and every struct it embeds by value (event_trace, EVENT_TRACE_HEADER,
#   TRACE_LOGFILE_HEADER, TIME_ZONE_INFORMATION, systemtime): re-fetched and declared with
#   their real full layouts, not opaque buffers, see each struct's own comment for the exact
#   page and offset arithmetic, and the comment above _SYSTEMTIME for why this matters.
# - processstart template versions 1-3 and processstop versions 1-2: re-read from the same
#   repnz manifest url. a live session sends the newest version (processstart v3, template
#   ProcessRundownArgs_V1), which carries a win:sid MandatoryLabel before ImageName, see
#   _tdh_decode_event_properties for how that's walked.
# - WINEVENT_KEYWORD_PROCESS = 0x10: same manifest's <keywords> block, events 1 and 2 are
#   both declared under it.
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
# learn.microsoft.com/.../system-error-codes--0-499- (fetched 2026-10-16):
# ERROR_ALREADY_EXISTS = 183 (0xb7)
# StartTraceW's own page: "a session with the same name or guid is already running"
_ERROR_ALREADY_EXISTS = 183
# microsoft-windows-kernel-process manifest <keywords> block (repnz url above):
# WINEVENT_KEYWORD_PROCESS mask="0x10", events 1 (ProcessStart) and 2 (ProcessStop)
# are declared under it
# passed as EnableTraceEx2's MatchAnyKeyword instead of 0: per its own remarks, for a
# manifest provider a MatchAnyKeyword of 0 is treated the same as 0xffffffffffffffff,
# i.e. it enables all event keywords (thread, image-load, job, ...), which only adds
# real-time buffer pressure for events this module discards
_WINEVENT_KEYWORD_PROCESS = 0x10
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


# EVENT_TRACE_LOGFILEW and the structs it embeds by value (event_trace,
# EVENT_TRACE_HEADER, TRACE_LOGFILE_HEADER, TIME_ZONE_INFORMATION, systemtime)
# are declared below with their real, full field layouts, not as opaque byte buffers.
# CurrentEvent and LogfileHeader sit in the middle of EVENT_TRACE_LOGFILEW, so a size
# error in them shifts every later field, including EventRecordCallback, the pointer
# ProcessTrace actually calls
# an earlier "generously sized" opaque declaration (128/256 bytes instead of the real
# 88/280) put EventRecordCallback at offset 440 instead of the real 424 on x64, so the
# callback would never have been invoked on a live host
#
# every win32 ulong/long/word/wchar below uses an explicit fixed-width ctypes type
# (c_uint32/c_int32/c_uint16), never c_ulong/c_long/c_wchar: those are 8/8/4 bytes on
# a 64-bit linux host versus 4/4/2 on windows, so fixed widths keep this layout
# identical on both and let test_EVENT_TRACE_LOGFILEW_matches_real_x64_layout prove
# the real windows offsets on this non-windows dev host. pointer-typed fields
# (lpwstr/pvoid/callback pointers) are pointer-sized on both
#
# expected x64 sizes/offsets, derived by hand from the cited syntax blocks (natural
# alignment, no pragma pack in evntrace.h): systemtime 16, TIME_ZONE_INFORMATION 172,
# EVENT_TRACE_HEADER 48, event_trace 88, TRACE_LOGFILE_HEADER 280,
# EVENT_TRACE_LOGFILEW 448 with EventRecordCallback at 424


class _SYSTEMTIME(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-minwinbase-systemtime, fetched 2026-10-16
    # eight words, 16 bytes
    _fields_ = [
        ("wYear", ctypes.c_uint16),
        ("wMonth", ctypes.c_uint16),
        ("wDayOfWeek", ctypes.c_uint16),
        ("wDay", ctypes.c_uint16),
        ("wHour", ctypes.c_uint16),
        ("wMinute", ctypes.c_uint16),
        ("wSecond", ctypes.c_uint16),
        ("wMilliseconds", ctypes.c_uint16),
    ]


class _TIME_ZONE_INFORMATION(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-timezoneapi-time_zone_information, fetched
    # 2026-10-16: long bias; wchar StandardName[32]; systemtime StandardDate; long
    # StandardBias; wchar DaylightName[32]; systemtime DaylightDate; long DaylightBias
    # 4+64+16+4+64+16+4 = 172 bytes (max member alignment 4, no tail padding)
    # wchar is declared as c_uint16, not c_wchar (4 bytes on linux); this module never
    # reads these names
    _fields_ = [
        ("Bias", ctypes.c_int32),
        ("StandardName", ctypes.c_uint16 * 32),
        ("StandardDate", _SYSTEMTIME),
        ("StandardBias", ctypes.c_int32),
        ("DaylightName", ctypes.c_uint16 * 32),
        ("DaylightDate", _SYSTEMTIME),
        ("DaylightBias", ctypes.c_int32),
    ]


class _EVENT_TRACE_HEADER(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-evntrace-event_trace_header, fetched
    # 2026-10-16: ushort size; a 2-byte union; a 4-byte union; ulong ThreadId; ulong
    # ProcessId; LARGE_INTEGER TimeStamp; a 16-byte union (guid or ulonglong); a final
    # 8-byte union
    # 2+2+4+4+4=16, TimeStamp at 16, guid at 24, the last union at 40, 48 bytes total
    # each union is collapsed to one member of its exact width, this module never reads
    # any of these fields (CurrentEvent is output-only), they only need the right size
    _fields_ = [
        ("Size", ctypes.c_uint16),
        ("FieldTypeFlags", ctypes.c_uint16),
        ("Version", ctypes.c_uint32),
        ("ThreadId", ctypes.c_uint32),
        ("ProcessId", ctypes.c_uint32),
        ("TimeStamp", ctypes.c_int64),
        ("Guid", _GUID),
        ("ProcessorTime", ctypes.c_uint64),
    ]


class _EVENT_TRACE(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-evntrace-event_trace, fetched 2026-10-16:
    # EVENT_TRACE_HEADER header; ulong instanceid; ulong ParentInstanceId; guid
    # ParentGuid; pvoid MofData; ulong MofLength; a 4-byte union
    # 48+4+4+16=72, MofData at 72, MofLength at 80, the union at 84, 88 bytes total
    # the union is collapsed to its ulong member (ETW_BUFFER_CONTEXT is also 4 bytes)
    _fields_ = [
        ("Header", _EVENT_TRACE_HEADER),
        ("InstanceId", ctypes.c_uint32),
        ("ParentInstanceId", ctypes.c_uint32),
        ("ParentGuid", _GUID),
        ("MofData", ctypes.c_void_p),
        ("MofLength", ctypes.c_uint32),
        ("ClientContext", ctypes.c_uint32),
    ]


class _TRACE_LOGFILE_HEADER(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-evntrace-trace_logfile_header, fetched
    # 2026-10-16: ulong BufferSize; a 4-byte union; ulong ProviderVersion; ulong
    # NumberOfProcessors; LARGE_INTEGER EndTime; ulong TimerResolution; ulong
    # MaximumFileSize; ulong LogFileMode; ulong BuffersWritten; a 16-byte union
    # (LogInstanceGuid); lpwstr LoggerName; lpwstr LogFileName; TIME_ZONE_INFORMATION
    # TimeZone; LARGE_INTEGER BootTime; LARGE_INTEGER PerfFreq; LARGE_INTEGER StartTime;
    # ulong ReservedFlags; ulong BuffersLost
    # (the page's syntax block renders the LoggerName/LogFileName/TimeZone #if/#else
    # confusingly, but its members and remarks sections confirm all three are present
    # in the user-mode build: two pointers then the time zone)
    # x64: 16 bytes of ulongs, EndTime at 16, four ulongs to 40, the guid union at 40,
    # LoggerName at 56, LogFileName at 64, TimeZone at 72 (172 bytes, to 244), BootTime
    # 8-aligned at 248, PerfFreq 256, StartTime 264, ReservedFlags 272, BuffersLost 276,
    # 280 bytes total
    _fields_ = [
        ("BufferSize", ctypes.c_uint32),
        ("Version", ctypes.c_uint32),
        ("ProviderVersion", ctypes.c_uint32),
        ("NumberOfProcessors", ctypes.c_uint32),
        ("EndTime", ctypes.c_int64),
        ("TimerResolution", ctypes.c_uint32),
        ("MaximumFileSize", ctypes.c_uint32),
        ("LogFileMode", ctypes.c_uint32),
        ("BuffersWritten", ctypes.c_uint32),
        ("LogInstanceGuid", _GUID),
        ("LoggerName", ctypes.c_void_p),   # lpwstr, never read ("do not use this field")
        ("LogFileName", ctypes.c_void_p),  # lpwstr, never read ("do not use this field")
        ("TimeZone", _TIME_ZONE_INFORMATION),
        ("BootTime", ctypes.c_int64),
        ("PerfFreq", ctypes.c_int64),
        ("StartTime", ctypes.c_int64),
        ("ReservedFlags", ctypes.c_uint32),
        ("BuffersLost", ctypes.c_uint32),
    ]


class _ProcessTraceModeUnion(ctypes.Union):
    _fields_ = [("LogFileMode", ctypes.c_uint32), ("ProcessTraceMode", ctypes.c_uint32)]


class _EventCallbackUnion(ctypes.Union):
    _fields_ = [("EventCallback", ctypes.c_void_p), ("EventRecordCallback", ctypes.c_void_p)]


class _EVENT_TRACE_LOGFILEW(ctypes.Structure):
    # verified against learn.microsoft.com/.../ns-evntrace-EVENT_TRACE_logfilew, fetched
    # 2026-10-16: lpwstr LogFileName; lpwstr LoggerName; longlong CurrentTime; ulong
    # BuffersRead; a 4-byte union (LogFileMode/ProcessTraceMode); EVENT_TRACE
    # CurrentEvent; TRACE_LOGFILE_HEADER LogfileHeader; a callback pointer; ulong
    # BufferSize; ulong filled; ulong EventsLost; a callback-pointer union; ulong
    # IsKernelTrace; pvoid context
    # x64: CurrentEvent at 32 (88 bytes), LogfileHeader at 120 (280 bytes),
    # BufferCallback at 400, BufferSize/filled/EventsLost at 408/412/416,
    # EventRecordCallback 8-aligned at 424, IsKernelTrace 432, context 440, 448 bytes total
    _anonymous_ = ("_mode", "_cb")
    _fields_ = [
        ("LogFileName", wintypes.LPWSTR),
        ("LoggerName", wintypes.LPWSTR),
        ("CurrentTime", ctypes.c_int64),
        ("BuffersRead", ctypes.c_uint32),
        ("_mode", _ProcessTraceModeUnion),
        ("CurrentEvent", _EVENT_TRACE),
        ("LogfileHeader", _TRACE_LOGFILE_HEADER),
        ("BufferCallback", ctypes.c_void_p),
        ("BufferSize", ctypes.c_uint32),
        ("Filled", ctypes.c_uint32),
        ("EventsLost", ctypes.c_uint32),
        ("_cb", _EventCallbackUnion),
        ("IsKernelTrace", ctypes.c_uint32),
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
# learn.microsoft.com/.../ne-tdh-_TDH_IN_TYPE (re-fetched 2026-10-16) declares
# _TDH_IN_TYPE as a plain 0-based c enum with no explicit values
# TDH_INTYPE_SID is its 20th member (null=0, unicodestring=1, ansistring=2,
# int8..uint64=3..10, float=11, double=12, boolean=13, binary=14, guid=15,
# pointer=16, filetime=17, systemtime=18, sid=19), consistent with the values above
_TDH_INTYPE_SID = 19

# fixed part of a sid's wire form: ms-dtyp 2.4.2.2 "sid, packet representation"
# (learn.microsoft.com/.../ms-dtyp/..., fetched 2026-10-16): revision (1 byte),
# SubAuthorityCount (1 byte, max 15), IdentifierAuthority (6 bytes), then
# SubAuthorityCount unsigned 32-bit subauthority values
# total length is 8 + 4 * SubAuthorityCount
# also winnt.h's sid struct (a "variable-length structure"), which is what
# win:sid carries per the EventManifest InputType table
_SID_FIXED_HEADER_SIZE = 8
_SID_MAX_SUB_AUTHORITIES = 15

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
    fixed byte offset, so this stays correct across template versions
    whether a newer one appends fields or inserts them mid-template
    (ProcessStopArgs_V2 inserts ProcessSequenceNumber at position 2,
    ProcessStart v3's ProcessRundownArgs_V1 inserts several fields,
    including a variable-length win:sid MandatoryLabel, before ImageName).
    what by-name walking can't absorb is an in-type this function can't
    size, TDH_INTYPE_SID is supported for exactly that reason (see its
    branch below).

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
    null-terminated string, sid is a self-sizing 8 + 4*n byte structure
    kept as raw bytes. that's the same approach every etw/tdh consumer
    takes for primitive types, TdhFormatProperty exists mainly for types
    this module never needs (maps, arrays, structs, ipv6, ...).

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
        elif in_type == _TDH_INTYPE_SID:
            # variable length, self-describing: byte 1 is the sub-authority count n,
            # total length 8 + 4*n (see _SID_FIXED_HEADER_SIZE)
            # only skipped, never decoded to a string, nothing downstream needs the
            # value (ProcessStart v3's MandatoryLabel), only the correct offset of
            # what follows it
            if pos + _SID_FIXED_HEADER_SIZE > len(data):
                raise OSError(f"ETW UserData truncated decoding SID property '{name}'")
            sub_authority_count = data[pos + 1]
            if sub_authority_count > _SID_MAX_SUB_AUTHORITIES:
                raise OSError(
                    f"malformed SID property '{name}': {sub_authority_count} sub-authorities "
                    f"(max {_SID_MAX_SUB_AUTHORITIES})"
                )
            sid_length = _SID_FIXED_HEADER_SIZE + 4 * sub_authority_count
            if pos + sid_length > len(data):
                raise OSError(f"ETW UserData truncated decoding SID property '{name}'")
            value = data[pos:pos + sid_length]
            pos += sid_length
        else:
            raise OSError(f"unsupported TDH in-type {in_type} decoding property '{name}'")

        if name is not None:
            result[name] = value

    return result


def _new_trace_properties_buffer():
    """
    a zeroed EVENT_TRACE_PROPERTIES buffer with room for the session name
    after it, set up the way both StartTraceW and a ControlTraceW stop
    need it (Wnode.BufferSize, Wnode.Flags = WNODE_FLAG_TRACED_GUID,
    LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES)).
    LogFileNameOffset is left 0 (no backing file, real-time only) and
    Wnode.Guid all-zero (etw generates a new session guid).
    callers set LogFileMode themselves when starting a session.
    """
    buffer_size = ctypes.sizeof(_EVENT_TRACE_PROPERTIES) + (_MAXIMUM_SESSION_NAME + _MAX_PATH) * 2
    props_buf = ctypes.create_string_buffer(buffer_size)
    props = ctypes.cast(props_buf, ctypes.POINTER(_EVENT_TRACE_PROPERTIES)).contents
    props.Wnode.BufferSize = buffer_size
    props.Wnode.Flags = _WNODE_FLAG_TRACED_GUID
    props.LoggerNameOffset = ctypes.sizeof(_EVENT_TRACE_PROPERTIES)
    return props_buf


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
        advapi32 = ctypes.WinDLL("advapi32")
        advapi32.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_wchar_p, ctypes.c_void_p]
        advapi32.StartTraceW.restype = ctypes.c_ulong
        advapi32.ControlTraceW.argtypes = [
            ctypes.c_uint64, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_ulong,
        ]
        advapi32.ControlTraceW.restype = ctypes.c_ulong

        props_buf = _new_trace_properties_buffer()
        props = ctypes.cast(props_buf, ctypes.POINTER(_EVENT_TRACE_PROPERTIES)).contents
        props.LogFileMode = _EVENT_TRACE_REAL_TIME_MODE

        session_handle = ctypes.c_uint64(0)
        status = advapi32.StartTraceW(
            ctypes.byref(session_handle), _SESSION_NAME, ctypes.cast(props_buf, ctypes.c_void_p),
        )
        if status == _ERROR_ALREADY_EXISTS:
            # _SESSION_NAME is fixed, and an etw session outlives the process that
            # started it (StartTraceW remarks: the session stays active until it's
            # stopped or the computer restarts)
            # so a previous run that crashed or was killed before stop() leaves it
            # running, and every later run would fail here until reboot
            # StartTraceW's own guidance for this case: clean up the orphaned
            # session instead of creating a second one
            # stop it by name (ControlTraceW needs InstanceName when TraceHandle is
            # 0, a fresh _new_trace_properties_buffer() sets up what a stop needs)
            # and retry once
            # a second ERROR_ALREADY_EXISTS (someone else restarted it meanwhile, or
            # the stop silently failed) falls through to the normal failure path
            # below instead of looping
            stale_props_buf = _new_trace_properties_buffer()
            advapi32.ControlTraceW(
                0, _SESSION_NAME, ctypes.cast(stale_props_buf, ctypes.c_void_p), _EVENT_TRACE_CONTROL_STOP,
            )
            props_buf = _new_trace_properties_buffer()
            props = ctypes.cast(props_buf, ctypes.POINTER(_EVENT_TRACE_PROPERTIES)).contents
            props.LogFileMode = _EVENT_TRACE_REAL_TIME_MODE
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
            _WINEVENT_KEYWORD_PROCESS, 0, 0, None,
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
            self._start_etw_session()
            start_error = None
        except Exception as exc:
            start_error = exc
        try:
            self._seed_existing_processes()
        except Exception:
            # a session that did start must not be leaked by a seeding failure
            # (it would outlive this process, see _start_etw_session's
            # ERROR_ALREADY_EXISTS handling)
            self._stop_etw_session()
            raise
        if start_error is not None:
            self.emit("ghostrun_status", "process_monitor_degraded", {"error": str(start_error)})
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
