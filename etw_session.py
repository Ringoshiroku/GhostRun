import ctypes
from ctypes import wintypes

# etw native struct/constant declarations.
#
# this module holds the provider-agnostic etw session/tdh plumbing shared by
# every real-time etw consumer in this codebase (process_mon.py's
# kernel-process consumer, and any later provider built the same way).
# provider-specific details (guid, event ids, keyword mask, event templates)
# live in the consumer module, not here. see process_mon.py's module comment
# for those citations.
#
# verification status (fetched 2026-10-16 unless noted):
# - event_record, EVENT_HEADER, EVENT_DESCRIPTOR, ETW_BUFFER_CONTEXT: full
#   field lists from learn.microsoft.com (evntcons/evntprov/relogger pages),
#   cross-checked against elastic's go etw consumer (beats,
#   libbeat/reader/etw/syscall_tdh.go), which matches exactly.
# - EVENT_TRACE_PROPERTIES, WNODE_HEADER: given by this task's brief,
#   pre-verified against learn.microsoft.com (evntrace/wnode-header) before
#   this session; used as given.
# - EVENT_TRACE_LOGFILEW and everything it embeds by value (event_trace,
#   EVENT_TRACE_HEADER, TRACE_LOGFILE_HEADER, TIME_ZONE_INFORMATION,
#   systemtime): re-fetched and declared with their real full layouts. see
#   the comment above _SYSTEMTIME for why, and each struct's own comment for
#   page and offset math.
# - StartTraceW's and ControlTraceW's signatures: fetched from their own
#   learn.microsoft.com pages. those pages' parameter prose is stale, but
#   EnableTraceEx2's worked c example resolves it. CONTROLTRACE_ID is
#   confirmed (via system informer's phnt headers, cross-checked against
#   elastic's go bindings) to just be the classic TraceHandle (ulong64), not
#   a new type. OpenTraceW's and ProcessTrace's signatures came from their
#   own dedicated pages, same session.
# - EVENT_TRACE_CONTROL_STOP, PROCESS_TRACE_MODE_REAL_TIME,
#   PROCESS_TRACE_MODE_EVENT_RECORD, EVENT_TRACE_REAL_TIME_MODE,
#   WNODE_FLAG_TRACED_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
#   TRACE_LEVEL_INFORMATION: not given as literal values on any
#   learn.microsoft.com page fetched this session (just named constants).
#   cross-confirmed against wine's evntrace.h/wmistr.h headers and elastic's
#   go consumer, which agree on every value.
# - TRACE_EVENT_INFO, EVENT_PROPERTY_INFO (the riskiest item in this plan):
#   fetched from their own dedicated learn.microsoft.com pages (full syntax
#   blocks, not inferred from examples), cross-checked byte-for-byte against
#   elastic's go structs, which match exactly. TdhGetEventInformation's
#   signature came from its own page, same session. TdhFormatProperty's
#   signature was also fetched and confirmed, but deliberately not used here;
#   see decode_event_properties's docstring for why.


class GUID(ctypes.Structure):
    # standard 16-byte win32 guid layout from guiddef.h, unchanged since
    # win32's start. same convention wfp_connection_watcher.py's own _GUID
    # uses (ctypes.wintypes has no guid type here).
    # public (no leading underscore): every etw consumer module builds its
    # own provider guid with this type.
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_uint8 * 8),
    ]


_MAXIMUM_SESSION_NAME = 1024  # see learn.microsoft.com/.../nf-evntrace-starttracew
_MAX_PATH = 260

_WNODE_FLAG_TRACED_GUID = 0x00020000
_EVENT_TRACE_REAL_TIME_MODE = 0x00000100
_PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
_PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
_EVENT_TRACE_CONTROL_STOP = 1
_EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
_TRACE_LEVEL_INFORMATION = 4
_ERROR_INSUFFICIENT_BUFFER = 122
# ERROR_ALREADY_EXISTS = 183 (0xb7), see learn.microsoft.com's system
# error codes page (fetched 2026-10-16). StartTraceW's own docs say
# it means "a session with the same name or guid is already running."
_ERROR_ALREADY_EXISTS = 183
# this module only runs ProcessTrace with one real-time session handle
# on 64-bit windows (GhostRun's only target), so
# INVALID_PROCESSTRACE_HANDLE is always the 64-bit form (see
# OpenTraceW's doc table), matching elastic's go consumer's constant.
_INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF


class _EVENT_DESCRIPTOR(ctypes.Structure):
    # verified against learn.microsoft.com's evntprov/event_descriptor page
    # (fetched 2026-10-16).
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
    # verified against learn.microsoft.com's relogger/etw_buffer_context
    # page (fetched 2026-10-16). the ProcessorNumber/alignment-vs-
    # ProcessorIndex union is collapsed to its single uint16 member, this
    # module never reads either side.
    _fields_ = [
        ("ProcessorIndex", ctypes.c_uint16),
        ("LoggerId", ctypes.c_uint16),
    ]


class _EVENT_HEADER(ctypes.Structure):
    # verified against learn.microsoft.com's evntcons/event_header page
    # (fetched 2026-10-16). the KernelTime/UserTime-vs-ProcessorTime union
    # is collapsed to its single uint64 member, this module never reads
    # either side.
    _fields_ = [
        ("Size", ctypes.c_uint16),
        ("HeaderType", ctypes.c_uint16),
        ("Flags", ctypes.c_uint16),
        ("EventProperty", ctypes.c_uint16),
        ("ThreadId", ctypes.c_uint32),
        ("ProcessId", ctypes.c_uint32),
        ("TimeStamp", ctypes.c_int64),
        ("ProviderId", GUID),
        ("EventDescriptor", _EVENT_DESCRIPTOR),
        ("ProcessorTime", ctypes.c_uint64),
        ("ActivityId", GUID),
    ]


class _EVENT_RECORD(ctypes.Structure):
    # verified against learn.microsoft.com's evntcons/event_record page
    # (fetched 2026-10-16).
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
    # given by this task's brief (pre-verified against
    # learn.microsoft.com's etw/wnode-header page before this session);
    # used as given.
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
        ("Guid", GUID),
        ("ClientContext", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
    ]


class _EVENT_TRACE_PROPERTIES(ctypes.Structure):
    # given by this task's brief (pre-verified against
    # learn.microsoft.com's evntrace/event_trace_properties page before
    # this session); used as given.
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
# EVENT_TRACE_HEADER, TRACE_LOGFILE_HEADER, TIME_ZONE_INFORMATION,
# systemtime) are declared below with their real, full field layouts,
# not as opaque byte buffers.
#
# CurrentEvent and LogfileHeader sit in the middle of
# EVENT_TRACE_LOGFILEW, so a size error in them shifts every later
# field, including EventRecordCallback, the pointer ProcessTrace
# actually calls. an earlier "generously sized" opaque declaration put
# EventRecordCallback at the wrong offset (440 instead of the real 424
# on x64), so the callback would never have fired on a live host.
#
# every win32 ulong/long/word/wchar below uses an explicit fixed-width
# ctypes type (c_uint32/c_int32/c_uint16), never c_ulong/c_long/c_wchar:
# those are 8/8/4 bytes on 64-bit linux versus 4/4/2 on windows. fixed
# widths keep the layout identical on both, so
# test_EVENT_TRACE_LOGFILEW_matches_real_x64_layout can prove the real
# windows offsets from this non-windows dev host. pointer fields
# (lpwstr/pvoid/callback pointers) are pointer-sized on both.
#
# expected x64 sizes/offsets, worked out by hand from each struct's
# cited syntax block (natural alignment, no pragma pack in evntrace.h):
# systemtime 16, TIME_ZONE_INFORMATION 172, EVENT_TRACE_HEADER 48,
# event_trace 88, TRACE_LOGFILE_HEADER 280, EVENT_TRACE_LOGFILEW 448
# with EventRecordCallback at 424.


class _SYSTEMTIME(ctypes.Structure):
    # verified against learn.microsoft.com's minwinbase/systemtime page
    # (fetched 2026-10-16): eight words, 16 bytes.
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
    # verified against learn.microsoft.com's timezoneapi/
    # time_zone_information page (fetched 2026-10-16): long bias; wchar
    # StandardName[32]; systemtime StandardDate; long StandardBias; wchar
    # DaylightName[32]; systemtime DaylightDate; long DaylightBias.
    # 4+64+16+4+64+16+4 = 172 bytes (max alignment 4, no tail padding).
    # wchar is declared as c_uint16, not c_wchar (4 bytes on linux); this
    # module never reads these names.
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
    # verified against learn.microsoft.com's evntrace/event_trace_header
    # page (fetched 2026-10-16): ushort size; union{ushort FieldTypeFlags;
    # struct{uchar HeaderType; uchar MarkerFlags}}; union{ulong version;
    # struct{uchar type; uchar level; ushort version} class}; ulong
    # ThreadId; ulong ProcessId; LARGE_INTEGER TimeStamp; union{guid guid;
    # ulonglong GuidPtr}; union{struct{ulong KernelTime; ulong UserTime};
    # ulong64 ProcessorTime; struct{ulong ClientContext; ulong flags}}.
    # 2+2+4+4+4 = 16, TimeStamp at 16, guid at 24, the last union at 40, 48
    # bytes total. each union is collapsed to one member of its exact
    # width since this module never reads any of these fields (CurrentEvent
    # is output-only), they just need to occupy the right number of bytes.
    _fields_ = [
        ("Size", ctypes.c_uint16),
        ("FieldTypeFlags", ctypes.c_uint16),
        ("Version", ctypes.c_uint32),
        ("ThreadId", ctypes.c_uint32),
        ("ProcessId", ctypes.c_uint32),
        ("TimeStamp", ctypes.c_int64),
        ("Guid", GUID),
        ("ProcessorTime", ctypes.c_uint64),
    ]


class _EVENT_TRACE(ctypes.Structure):
    # verified against learn.microsoft.com's evntrace/event_trace page
    # (fetched 2026-10-16): EVENT_TRACE_HEADER header; ulong instanceid;
    # ulong ParentInstanceId; guid ParentGuid; pvoid MofData; ulong
    # MofLength; union{ulong ClientContext; etw_buffer_context
    # BufferContext}. 48+4+4+16 = 72, MofData at 72, MofLength at 80, the
    # 4-byte union at 84, 88 bytes total. the union collapses to its ulong
    # member (etw_buffer_context is also 4 bytes, see
    # _ETW_BUFFER_CONTEXT).
    _fields_ = [
        ("Header", _EVENT_TRACE_HEADER),
        ("InstanceId", ctypes.c_uint32),
        ("ParentInstanceId", ctypes.c_uint32),
        ("ParentGuid", GUID),
        ("MofData", ctypes.c_void_p),
        ("MofLength", ctypes.c_uint32),
        ("ClientContext", ctypes.c_uint32),
    ]


class _TRACE_LOGFILE_HEADER(ctypes.Structure):
    # verified against learn.microsoft.com's evntrace/trace_logfile_header
    # page (fetched 2026-10-16): ulong BufferSize; union{ulong version;
    # struct{4 x uchar} VersionDetail}; ulong ProviderVersion; ulong
    # NumberOfProcessors; LARGE_INTEGER EndTime; ulong TimerResolution;
    # ulong MaximumFileSize; ulong LogFileMode; ulong BuffersWritten;
    # union{guid LogInstanceGuid; struct{4 x ulong}}; lpwstr LoggerName;
    # lpwstr LogFileName; TIME_ZONE_INFORMATION TimeZone; LARGE_INTEGER
    # BootTime; LARGE_INTEGER PerfFreq; LARGE_INTEGER StartTime; ulong
    # ReservedFlags; ulong BuffersLost.
    #
    # the page's syntax block renders the #if/#else around LoggerName/
    # LogFileName/TimeZone confusingly, but its members/remarks sections
    # confirm the user-mode build has all three: two pointers then the
    # time zone.
    #
    # x64: 16 bytes of ulongs, EndTime at 16, four ulongs to 40, the guid
    # union at 40, LoggerName at 56, LogFileName at 64, TimeZone at 72
    # (172 bytes, to 244), BootTime 8-aligned at 248, PerfFreq 256,
    # StartTime 264, ReservedFlags 272, BuffersLost 276, 280 bytes total.
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
        ("LogInstanceGuid", GUID),
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
    # verified against learn.microsoft.com's evntrace/event_trace_logfilew
    # page (fetched 2026-10-16): lpwstr LogFileName; lpwstr LoggerName;
    # longlong CurrentTime; ulong BuffersRead; union{ulong LogFileMode;
    # ulong ProcessTraceMode}; event_trace CurrentEvent; TRACE_LOGFILE_HEADER
    # LogfileHeader; PEVENT_TRACE_BUFFER_CALLBACKW BufferCallback; ulong
    # BufferSize; ulong filled; ulong EventsLost; union{PEVENT_CALLBACK
    # EventCallback; PEVENT_RECORD_CALLBACK EventRecordCallback}; ulong
    # IsKernelTrace; pvoid context.
    #
    # x64: CurrentEvent at 32 (88 bytes), LogfileHeader at 120 (280 bytes),
    # BufferCallback at 400, BufferSize/filled/EventsLost at 408/412/416,
    # EventRecordCallback 8-aligned at 424, IsKernelTrace 432, context 440,
    # 448 bytes total.
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
    # verified against learn.microsoft.com's tdh/event_property_info page
    # (fetched 2026-10-16), cross-checked byte-for-byte against elastic's
    # go EventPropertyInfo struct (see the module-level verification
    # comment above). the nonStructType/structType/customSchemaType union
    # collapses to nonStructType alone: ProcessStart/ProcessStopArgs's
    # fields are all flat scalars, so this module never reads the other
    # two union members.
    _fields_ = [
        ("Flags", ctypes.c_int32),
        ("NameOffset", ctypes.c_uint32),
        ("nonStructType", _EVENT_PROPERTY_INFO_NONSTRUCT),
        ("count", ctypes.c_uint16),
        ("length", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint32),
    ]


class _TRACE_EVENT_INFO(ctypes.Structure):
    # verified against learn.microsoft.com's tdh/trace_event_info page
    # (fetched 2026-10-16), cross-checked byte-for-byte against elastic's
    # go TraceEventInfo struct (see the module-level verification comment
    # above). the EventNameOffset/activityidnameoffset union and
    # EventAttributesOffset/RelatedActivityIDNameOffset union each collapse
    # to one uint32 member (same byte offset either way, this module never
    # reads either).
    #
    # eventpropertyinfoarray is declared with ANYSIZE_ARRAY=1 per the real
    # struct's trailing flexible-array convention: the real array can hold
    # far more than this fixed-size field declares, so
    # decode_event_properties walks it by raw byte offset
    # (EventPropertyInfoArray.offset + i * sizeof(_EVENT_PROPERTY_INFO))
    # instead of indexing this field past index 0.
    _fields_ = [
        ("ProviderGuid", GUID),
        ("EventGuid", GUID),
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


# tdh input types this module decodes directly from raw UserData
# bytes. values confirmed against learn.microsoft.com's tdh/_tdh_in_type
# page, cross-checked against elastic's go TdhIntype* constants, which
# cite the same page and agree on every value.
_TDH_INTYPE_UNICODESTRING = 1
_TDH_INTYPE_ANSISTRING = 2
_TDH_INTYPE_UINT32 = 8
_TDH_INTYPE_UINT64 = 10
_TDH_INTYPE_FILETIME = 17
# learn.microsoft.com's tdh/_TDH_IN_TYPE page (re-fetched 2026-10-16)
# declares _TDH_IN_TYPE as a plain 0-based c enum with no explicit
# values. TDH_INTYPE_SID is its 20th member (null=0, unicodestring=1,
# ansistring=2, int8..uint64=3..10, float=11, double=12, boolean=13,
# binary=14, guid=15, pointer=16, filetime=17, systemtime=18, sid=19),
# consistent with the values above.
_TDH_INTYPE_SID = 19

# fixed part of a sid's wire form: ms-dtyp 2.4.2.2 "sid, packet
# representation" (see learn.microsoft.com's openspecs ms-dtyp page,
# fetched 2026-10-16): revision (1 byte), SubAuthorityCount (1 byte,
# max 15), IdentifierAuthority (6 bytes), then SubAuthorityCount
# unsigned 32-bit subauthority values. total length is 8 + 4 *
# SubAuthorityCount.
#
# this is also winnt.h's sid struct ("a variable-length structure",
# see learn.microsoft.com's winnt/sid page), which is what win:sid
# carries per the EventManifest InputType table.
_SID_FIXED_HEADER_SIZE = 8
_SID_MAX_SUB_AUTHORITIES = 15

# EVENT_PROPERTY_INFO.Flags bits relevant to string decoding.
# confirmed against learn.microsoft.com's tdh/property_flags page
# (fetched 2026-10-19): for a UnicodeString/AnsiString property,
# PropertyParamFixedLength set means `length` holds the manifest's
# declared fixed byte size, not a null-terminated string.
#
# a live windows run hit exactly this on processstop's ImageName:
# this codebase previously always null-scanned regardless of the flag,
# silently truncating or corrupting later properties' offsets whenever
# the fixed-length field had no nul within its declared bounds.
#
# PropertyParamLength (dynamic length looked up from an earlier
# property) is a separate case this module doesn't support. it's
# raised explicitly as unsupported rather than guessed, since nothing
# in ProcessStart/ProcessStopArgs actually uses it.
_PROPERTY_PARAM_LENGTH = 0x2
_PROPERTY_PARAM_FIXED_LENGTH = 0x10

# fixed wire widths (bytes) for the scalar in-types this module
# decodes. not derived from EVENT_PROPERTY_INFO.length (which the
# docs only guarantee is nonzero for *some* fixed-size properties,
# zero for variable-sized types like strings): these are each
# in-type's own standard, documented wire encoding, the same
# convention every etw/tdh consumer (including elastic's go one)
# relies on.
_TDH_FIXED_WIDTHS = {
    _TDH_INTYPE_UINT32: 4,
    _TDH_INTYPE_UINT64: 8,
    _TDH_INTYPE_FILETIME: 8,
}


def _tdh_string_at(info_buf, offset):
    """
    reads a null-terminated utf-16le string at a byte offset inside a
    TRACE_EVENT_INFO buffer (e.g. EVENT_PROPERTY_INFO.NameOffset), per
    TRACE_EVENT_INFO's documented offset convention. offset == 0 means
    "not present".

    decoded explicitly as utf-16le with a manual 2-byte-nul scan, not
    via ctypes.wstring_at: wstring_at uses the host's native wchar_t
    size (2 bytes on windows, 4 on linux/glibc), which silently
    misreads this buffer on a non-windows host (a test caught this
    before the fix). windows api string data is always utf-16le
    regardless of host, so decoding explicitly avoids the trap. same
    issue wfp_connection_watcher.py's _decode_app_id handles.
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
    calls TdhGetEventInformation (tdh.dll), growing the buffer with the
    documented ERROR_INSUFFICIENT_BUFFER two-call pattern: probe with a
    zero-size buffer, then allocate what the probe reports and call
    again. returns the raw ctypes buffer backing a _TRACE_EVENT_INFO
    (its fields plus the trailing EventPropertyInfoArray and name-string
    table all live in this one buffer). raises oserror on any
    non-success status.

    see learn.microsoft.com's tdh/TdhGetEventInformation page (fetched
    2026-10-16); the two-call growth pattern matches elastic's go
    consumer's own call site exactly
    (libbeat/reader/etw/manifest_provider_cache.go).
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


def decode_event_properties(event_record_ptr):
    """
    decodes a manifest-based event's UserData into {property_name:
    value}, using TdhGetEventInformation for property metadata (names,
    in-types, fixed lengths) looked up by name and walked in order,
    not by a fixed byte offset. this stays correct across template
    versions whether a newer one appends fields or inserts them
    mid-template (e.g. ProcessStopArgs_V2 inserts
    ProcessSequenceNumber at position 2; ProcessStart v3 inserts
    several fields, including a variable-length win:sid
    MandatoryLabel, before ImageName).

    what by-name walking can't absorb is an in-type this function
    can't size. TDH_INTYPE_SID is supported for exactly that reason,
    see its branch below.

    deliberately does not call TdhFormatProperty, even though
    microsoft's own guidance for decoding UserData names it:
    TdhFormatProperty returns a formatted, locale-dependent display
    string for every property, including numeric and filetime ones,
    not the raw 100ns-tick integer filetime_to_epoch_seconds
    (native_paths.py) needs. using it would mean re-parsing a
    formatted date string instead of reading the documented wire
    encoding directly.

    this function instead reads each property's raw bytes itself, per
    its in-type's standard, documented wire encoding: uint32/uint64 are
    fixed-width little-endian integers; filetime is a little-endian
    100ns-tick integer, exactly what filetime_to_epoch_seconds expects;
    unicode/AnsiString is null-terminated, unless
    EVENT_PROPERTY_INFO.Flags marks it PropertyParamFixedLength, in
    which case it's exactly `length` bytes, nul-padded but not
    necessarily nul-terminated, per the manifest's declared size (see
    _PROPERTY_PARAM_FIXED_LENGTH's module comment); sid is a
    self-sizing 8 + 4*n byte structure, kept as raw bytes. this is the
    same approach every etw/tdh consumer takes for primitive types.
    TdhFormatProperty exists mainly for types this module never needs
    (maps, arrays, structs, ipv6 addresses, ...).

    a property with an in-type outside this small, supported set makes
    decoding the rest of this event's properties unsafe, since their
    byte offsets can no longer be located. so this function raises
    rather than guessing; callers treat that like any other decode
    failure (skip this event, emit a degrade status), never a crash.
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
            if prop.Flags & _PROPERTY_PARAM_LENGTH:
                raise OSError(
                    f"unsupported dynamic-length string property '{name}' (PropertyParamLength)"
                )
            if prop.Flags & _PROPERTY_PARAM_FIXED_LENGTH:
                length = prop.length
                if pos + length > len(data):
                    raise OSError(f"ETW UserData truncated decoding fixed-length property '{name}'")
                raw = data[pos:pos + length]
                if is_wide:
                    # strip trailing nul padding in whole 2-byte utf-16le units, not raw
                    # bytes: a plain rstrip(b"\x00") would eat into the final real
                    # character's own high byte if it happens to be 0x00 (e.g. 'e' == 0x65
                    # 0x00), corrupting it instead of trimming padding.
                    while len(raw) >= step and raw[-step:] == terminator:
                        raw = raw[:-step]
                else:
                    raw = raw.rstrip(terminator)
                value = raw.decode("utf-16-le" if is_wide else "ascii", errors="replace")
                pos += length
            else:
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
            # variable length, self-describing: byte 1 is the sub-authority count
            # n, total length 8 + 4*n (see _SID_FIXED_HEADER_SIZE). only skipped,
            # never decoded to a string: nothing downstream needs the value
            # (ProcessStart v3's MandatoryLabel), only the correct offset of what
            # follows it.
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


def _new_trace_properties_buffer(session_name):
    """
    a zeroed EVENT_TRACE_PROPERTIES buffer with room for the session
    name after it, set up the way both StartTraceW and a ControlTraceW
    stop need it (see EnableTraceEx2's reference example,
    AllocateTraceProperties: Wnode.BufferSize, Wnode.Flags =
    WNODE_FLAG_TRACED_GUID, LoggerNameOffset =
    sizeof(EVENT_TRACE_PROPERTIES)). LogFileNameOffset is left 0 (no
    backing file, real-time only) and Wnode.Guid all-zero (etw
    generates a new session guid). callers set LogFileMode themselves
    when starting a session.

    session_name is a parameter, not a module constant, since
    etwsession carries its own per-instance session name.
    _MAXIMUM_SESSION_NAME is a fixed cap on the buffer's spare room,
    not the actual name's length, so the buffer's byte layout doesn't
    vary by session_name. the parameter keeps this function from
    implicitly depending on one hardcoded session, matching
    EtwSession.start()/stop()'s own per-instance session_name.
    """
    buffer_size = ctypes.sizeof(_EVENT_TRACE_PROPERTIES) + (_MAXIMUM_SESSION_NAME + _MAX_PATH) * 2
    props_buf = ctypes.create_string_buffer(buffer_size)
    props = ctypes.cast(props_buf, ctypes.POINTER(_EVENT_TRACE_PROPERTIES)).contents
    props.Wnode.BufferSize = buffer_size
    props.Wnode.Flags = _WNODE_FLAG_TRACED_GUID
    props.LoggerNameOffset = ctypes.sizeof(_EVENT_TRACE_PROPERTIES)
    return props_buf


class EtwSession:
    """
    provider-agnostic real-time etw session: StartTraceW/EnableTraceEx2
    to start and enable a provider, OpenTraceW/ProcessTrace to consume
    it, ControlTraceW to stop it. extracted from process_mon.py's
    kernel-process consumer so a second provider (kernel-network) can
    reuse the same session/tdh plumbing without duplicating it.
    """

    def __init__(self, session_name, provider_guid, keyword_mask, trace_level, event_record_callback):
        self.session_name = session_name
        self.provider_guid = provider_guid
        self.keyword_mask = keyword_mask
        self.trace_level = trace_level
        self.event_record_callback = event_record_callback

        self._session_handle = None
        self._props_buf = None
        self._trace_handle = None
        self._callback_ref = None  # keep the ctypes callback alive, see process_trace

    def start(self):
        """
        StartTraceW + EnableTraceEx2, following microsoft's own
        reference example (learn.microsoft.com's evntrace/
        EnableTraceEx2 page, fetched 2026-10-16), substituting this
        instance's session name and provider guid, with
        EnableParameters=null (no payload/scope filtering needed).
        raises oserror on any native failure, the caller catches this
        and degrades. see this module's verification comment above for
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

        props_buf = _new_trace_properties_buffer(self.session_name)
        props = ctypes.cast(props_buf, ctypes.POINTER(_EVENT_TRACE_PROPERTIES)).contents
        props.LogFileMode = _EVENT_TRACE_REAL_TIME_MODE

        session_handle = ctypes.c_uint64(0)
        status = advapi32.StartTraceW(
            ctypes.byref(session_handle), self.session_name, ctypes.cast(props_buf, ctypes.c_void_p),
        )
        if status == _ERROR_ALREADY_EXISTS:
            # self.session_name is fixed for this instance's life, and an etw
            # session outlives the process that started it (StartTraceW's own
            # remarks: the session stays active until stopped or the computer
            # restarts), so a previous run that crashed or was killed before
            # stop() leaves it running, and every later run fails here until
            # reboot.
            #
            # StartTraceW's own guidance for this case: clean up the orphaned
            # session instead of creating a second one. so stop it by name
            # (ControlTraceW needs InstanceName when TraceHandle is 0; a fresh
            # _new_trace_properties_buffer() sets everything a stop needs) and
            # retry once. a second ERROR_ALREADY_EXISTS (someone else restarted it
            # meanwhile, or the stop silently failed) falls through to the normal
            # failure path instead of looping.
            stale_props_buf = _new_trace_properties_buffer(self.session_name)
            advapi32.ControlTraceW(
                0, self.session_name, ctypes.cast(stale_props_buf, ctypes.c_void_p), _EVENT_TRACE_CONTROL_STOP,
            )
            props_buf = _new_trace_properties_buffer(self.session_name)
            props = ctypes.cast(props_buf, ctypes.POINTER(_EVENT_TRACE_PROPERTIES)).contents
            props.LogFileMode = _EVENT_TRACE_REAL_TIME_MODE
            session_handle = ctypes.c_uint64(0)
            status = advapi32.StartTraceW(
                ctypes.byref(session_handle), self.session_name, ctypes.cast(props_buf, ctypes.c_void_p),
            )
        if status != 0:
            raise OSError(f"StartTraceW failed: {status}")

        self._session_handle = session_handle.value
        self._props_buf = props_buf  # keep alive: ControlTraceW (stop) reuses this same buffer

        advapi32.EnableTraceEx2.argtypes = [
            ctypes.c_uint64, ctypes.POINTER(GUID), ctypes.c_ulong, ctypes.c_uint8,
            ctypes.c_uint64, ctypes.c_uint64, ctypes.c_ulong, ctypes.c_void_p,
        ]
        advapi32.EnableTraceEx2.restype = ctypes.c_ulong
        status = advapi32.EnableTraceEx2(
            self._session_handle, ctypes.byref(self.provider_guid),
            _EVENT_CONTROL_CODE_ENABLE_PROVIDER, self.trace_level,
            self.keyword_mask, 0, 0, None,
        )
        if status != 0:
            self.stop()
            raise OSError(f"EnableTraceEx2 failed: {status}")

    def stop(self):
        """
        ControlTraceW(..., EVENT_TRACE_CONTROL_STOP): stops the session
        (which also makes a blocking real-time ProcessTrace call in
        process_trace return, per its documented remarks). safe to call
        from a different thread than the one blocked in ProcessTrace,
        that's the whole point: stop() runs on whichever thread the
        caller calls it from. idempotent: a call when _session_handle
        is already none (never started, or already stopped) is a no-op.
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

    def process_trace(self):
        """
        OpenTraceW + the blocking ProcessTrace call: attaches to this
        instance's own already-started real-time session by name
        (LoggerName, not LogFileName) and delivers events to
        self.event_record_callback via PROCESS_TRACE_MODE_EVENT_RECORD.
        blocks until stop() calls ControlTraceW (see stop) or a genuine
        error occurs. raises oserror on a native failure either opening
        the trace or from ProcessTrace itself, the caller catches this
        and degrades.
        """
        advapi32 = ctypes.WinDLL("advapi32")
        advapi32.OpenTraceW.argtypes = [ctypes.c_void_p]
        advapi32.OpenTraceW.restype = ctypes.c_uint64
        advapi32.ProcessTrace.argtypes = [
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p,
        ]
        advapi32.ProcessTrace.restype = ctypes.c_ulong

        logfile = _EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = self.session_name
        logfile.ProcessTraceMode = _PROCESS_TRACE_MODE_REAL_TIME | _PROCESS_TRACE_MODE_EVENT_RECORD
        callback_type = ctypes.WINFUNCTYPE(None, ctypes.POINTER(_EVENT_RECORD))
        self._callback_ref = callback_type(self.event_record_callback)
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
