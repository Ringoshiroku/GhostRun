import struct
from datetime import datetime, timedelta

FILETIME_EPOCH = datetime(1601, 1, 1)

def parse_filetime(ft):
    if ft == 0:
        return None
    return FILETIME_EPOCH + timedelta(microseconds=ft / 10)

def parse_userassist_binary(blob: bytes) -> dict:
    """
    Parse UserAssist binary value (Vista+ format)
    """
    if not blob or len(blob) < 68:
        return {}

    try:
        session_id = struct.unpack_from("<I", blob, 0x00)[0]
        run_count = struct.unpack_from("<I", blob, 0x04)[0]
        focus_count = struct.unpack_from("<I", blob, 0x08)[0]
        focus_time_ms = struct.unpack_from("<I", blob, 0x0C)[0]
        last_exec_ft = struct.unpack_from("<Q", blob, 0x3C)[0]

        last_exec_time = parse_filetime(last_exec_ft)

        return {
            "session_id": session_id,
            "run_count": run_count,
            "focus_count": focus_count,
            "focus_time_ms": focus_time_ms,
            "last_execution_time": (
                last_exec_time.strftime("%Y-%m-%d %H:%M:%S UTC")
                if last_exec_time else None
            )
        }

    except struct.error:
        return {}
