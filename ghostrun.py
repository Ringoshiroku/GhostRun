import argparse
import subprocess
import threading
import time
import sys
import psutil
import json
import os
import queue
from datetime import datetime, timezone
from sender_http import PutEvidenceSender
from network_watch import NetworkCapture, CAPTURE_ACTIVITY_EVENTS
from process_mon import ProcessMonitor
from registry_snapshot import snapshot_registry, diff_registry
from registry_watch import RegistryWatcher
from persistence_detector import PersistenceDetector
from detector_network_inference import NetworkInferenceDetector
from detector_static_network import StaticNetworkIndicatorDetector
from filesystem_watch import FilesystemWatcher
from timeline_builder import TimelineBuilder
from network_finding_engine import NetworkFindingEngine
import atexit
import signal

# =========================================================
# UTIL / GLOBAL
# =========================================================
SENDER = None
NETWORK_EVENT_COUNT = 0
persistence = None
network_infer = None
EVIDENCE_QUEUE = queue.Queue()
ALL_EVIDENCE = []
network_finding = None

MALWARE_IDENTITY = {
    "pid": None,
    "path": None,
    "name": None
}

MALWARE_PIDS = set()
category = "ghostrun_status"

        
def emit(category, event, data, **meta):
    global NETWORK_EVENT_COUNT, MALWARE_PIDS
    
    pid = None
    if isinstance(data, dict):
        pid = data.get("pid")

    # ===============================
    # ACTOR-BASED FILTER
    # ===============================
    # TEMP: allow svchost/network until injection reasoning siap
    #if category == "network":
    #    pass
    #else:
    #    if pid is not None and pid not in MALWARE_PIDS:
    #        return     # DROP OS NOISE registry/filesystem

    #print(f"[DEBUG] pid : {pid}")
    #print(f"[DEBUG] MALWARE_PIDS : {MALWARE_PIDS}")

    if category not in ("ghostrun_status", "analysis", "execution"):
        if pid is None or pid not in MALWARE_PIDS:
            #print(f"[DEBUG] pid yg di filter: {pid}")
            return  # drop noise
        
    evidence = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "event": event,
        "data": data
    }

    if meta:
        evidence.update(meta)
    
    if persistence:
        persistence.ingest(category, event, data)
    
    if network_infer:
        network_infer.ingest(category, event, data)

    # allowlist of real capture activity, not a denylist of degradation notices
    # this also excludes capture_failed and this engine's own derived
    # malware_network_activity output, not just capture_unavailable
    if category == "network_behavior" and event in CAPTURE_ACTIVITY_EVENTS:
        NETWORK_EVENT_COUNT += 1

    if not SENDER:
        raise RuntimeError("Evidence sender not initialized")

    if network_finding is not None:
        network_finding.ingest(evidence)

    EVIDENCE_QUEUE.put(evidence)
    ALL_EVIDENCE.append(evidence)


def on_exit():
    pid = MALWARE_IDENTITY.get("pid")

    if not pid:
        return  # sample belum sempat start

    try:
        emit(
            category="execution",
            event="process_terminating",
            data={"pid": pid}
        )
        time.sleep(0.5)  # beri waktu sender kirim
    except:
        pass
        
def sender_worker():
    while True:
        try:
            evidence = EVIDENCE_QUEUE.get()
            if evidence is None:
                break  # shutdown signal
            SENDER.send(evidence)
        except Exception as e:
            print(f"[GhostRun] Sender error: {e}")


def dump_local_evidence(file):
    with open(file, "w", encoding="utf-8") as f:
        for ev in ALL_EVIDENCE:
            f.write(json.dumps(ev) + "\n")
    print(f"[+] Local evidence written to {file}")


def send_backup_file(file):
    emit(
        category="ghostrun_status",
        event="backup_start",
        data={"message": f"Sending backup file: {file}"}
    )

    try:
        with open(file, "rb") as f:
            raw = f.read()

        SENDER.send_raw(
            path=f"/backup/{os.path.basename(file)}",
            data=raw
        )

        emit(
            category="ghostrun_status",
            event="backup_done",
            data={"message": "Backup file sent successfully"}
        )

    except Exception as e:
        emit(
            category="ghostrun_status",
            event="backup_error",
            data={"message": str(e)}
        )
  

    
# =========================================================
# MAIN CONTROLLER
# =========================================================
def main():
    parser = argparse.ArgumentParser(description="GhostRun v1 – See the Unseen")
    parser.add_argument("-s", "--sample", required=True, help="Path to EXE sample")
    parser.add_argument("--host", required=True, help="Evidence receiver host")
    parser.add_argument("--port", type=int, default=9001)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--file", required=True, help="file to jsonl export graph")
    args = parser.parse_args()

    print("[GhostRun] Starting controller")

    global persistence, network_infer, network_finding

    FS_TARGETS = {
        "TEMP": os.environ.get("TEMP"),
        "APPDATA": os.environ.get("APPDATA"),
        "LOCALAPPDATA": os.environ.get("LOCALAPPDATA"),
        "PROGRAMDATA": os.environ.get("PROGRAMDATA"),
        "STARTUP": os.path.join(
            os.environ.get("APPDATA"),
            r"Microsoft\Windows\Start Menu\Programs\Startup"
        ),
        "DESKTOP": os.path.join(
            os.environ.get("USERPROFILE"),
            "Desktop"
        ),
        "PUBLIC": r"C:\Users\Public",
        "WINDOWS_TEMP": r"C:\Windows\Temp",
    }
        
    # execute persistence detector
    persistence = PersistenceDetector()
    
    network_infer = NetworkInferenceDetector(args.sample)
    static_net = StaticNetworkIndicatorDetector(args.sample)

    # -----------------------------------------------------
    # 1️⃣ Init Evidence Sender
    # -----------------------------------------------------    
    global SENDER
    case_id = f"ghostrun-{int(time.time())}"
    
    SENDER = PutEvidenceSender(
        host=args.host,
        port=args.port,
        case_id=case_id
    )
    print("[GhostRun] HTTP PUT EvidenceSender ready")


    # -----------------------------------------------------
    # 2️⃣ Snapshot BEFORE
    # -----------------------------------------------------
    print(f"[GhostRun] Registry snapshot: BEFORE")
    reg_before = snapshot_registry()

    triggered_roots = set()

    def _on_registry_root_changed(hive, path):
        triggered_roots.add((hive, path))

    registry_watcher = RegistryWatcher(on_change=_on_registry_root_changed)
    registry_watcher.start()

    # -----------------------------------------------------
    # 3. start network capture, then run the sample
    # -----------------------------------------------------
    # SSLKEYLOGFILE must be set before Popen() so the sample process inherits
    # it. opportunistic: only helps if the sample uses an SSLKEYLOGFILE-aware
    # TLS stack
    # capture starts before the sample launches so it doesn't miss early traffic
    # ROOTPID isn't known yet, so net_capture is built with root_pid=None and
    # patched in live once the sample's PID is known, same as FilesystemWatcher
    # above
    sslkeylogfile_path = os.path.join(os.path.dirname(args.file), "sslkeylog.txt")
    os.environ["SSLKEYLOGFILE"] = sslkeylogfile_path  # set before sample launch, opportunistic

    net_capture = NetworkCapture(
        pcap_path=os.path.join(os.path.dirname(args.file), "capture.pcap"),
        eve_log_dir=os.path.dirname(args.file),
        emit_func=emit,
        sslkeylogfile_path=sslkeylogfile_path,
        exclude_host=args.host,
        exclude_port=args.port,
    )
    net_capture.start()

    try:
        proc = subprocess.Popen(args.sample)
        ROOTPID = proc.pid
        MALWARE_PIDS.add(ROOTPID)
        net_capture.root_pid = ROOTPID

        MALWARE_IDENTITY.update({
            "pid": ROOTPID,
            "path": args.sample,
            "name": os.path.basename(args.sample)
        })

        print(f"[GhostRun] Sample executed (PID {ROOTPID})")
    except Exception as e:
        print(f"[GhostRun] ERROR: Failed to execute sample: {e}")
        sys.exit(1)

    atexit.register(on_exit)
    signal.signal(signal.SIGTERM, lambda s, f: on_exit())
    signal.signal(signal.SIGINT, lambda s, f: on_exit())

    # -----------------------------------------------------
    # 4️⃣ Start monitors (THREADING)
    # -----------------------------------------------------
    sender_thread = threading.Thread(
        target=sender_worker,
        daemon=True
    )
    sender_thread.start()

    # filesystem watcher
    # known gap: only covers events from fs_watcher.start() onward
    # there's no backfill for writes between Popen() returning and here
    # (unlike ProcessMonitor's process-seeding, past filesystem writes can't
    # be recovered after the fact)
    # so a dropper that writes its payload within milliseconds of launch
    # could be missed
    # fixing this means starting the watcher before Popen with root_pid=None,
    # then patching root_pid in live once ROOTPID is known
    # that needs _Handler (filesystem_watch.py) to read root_pid from its
    # parent FilesystemWatcher at emit time instead of a value frozen at
    # _Handler.__init__
    # that's a fast-follow for filesystem_watch.py, out of scope here since
    # that file is already reviewed and approved
    # accepted limitation for now, not an oversight
    fs_watcher = FilesystemWatcher(targets=FS_TARGETS, emit_func=emit, root_pid=ROOTPID)
    fs_watcher.start()

    # Process monitor
    proc_monitor = ProcessMonitor(
        root_pid=proc.pid,
        emit_func=emit
    )

    network_finding = NetworkFindingEngine(
        root_pid=proc.pid,
        process_monitor=proc_monitor
    )

    proc_thread = threading.Thread(
        target=proc_monitor.run,
        daemon=True
    )
    proc_thread.start()

    print("[GhostRun] Monitoring started")
    
    # -----------------------------------------------------
    # 5️⃣ Run until timeout
    # -----------------------------------------------------
    time.sleep(args.timeout)

    # -----------------------------------------------------
    # 6️⃣ Snapshot AFTER
    # -----------------------------------------------------
    print(f"[GhostRun] Registry snapshot (PID {ROOTPID}): AFTER")
    reg_after = snapshot_registry()

    registry_watcher.stop()
    diff_registry(reg_before, reg_after, emit, ROOTPID)

    for hive, path in sorted(triggered_roots):
        emit(
            category="ghostrun_status",
            event="uncataloged_registry_change",
            confidence="low",
            data={
                "hive": hive,
                "path": path,
                "note": (
                    "Registry activity observed under this broad root during "
                    "the analysis window. This mechanism cannot attribute the "
                    "change to a specific process; treat as informational "
                    "context, not a sample-attributed finding."
                ),
            },
        )

    print(f"[GhostRun] Filesystem watcher (PID {ROOTPID}): STOP")
    fs_watcher.stop()

    # -----------------------------------------------------
    # 7️⃣ Stop monitors cleanly
    # -----------------------------------------------------
    proc_monitor.stop()

    proc_thread.join(timeout=5)

    print(f"[GhostRun] Network capture (PID {ROOTPID}): STOP")
    net_capture.stop_and_analyze()

    persistence.analyze(emit)
    network_infer.analyze(emit)
    static_net.analyze(emit)
    network_finding.analyze(emit)
    
    # anti-analysis evidence, derived and emitted after all monitors stop
    # also gated on tools_available: if dumpcap/suricata were never installed,
    # a zero event count means capture never ran, not that the sample avoided
    # the network, so this heuristic must not fire
    if NETWORK_EVENT_COUNT == 0 and net_capture.tools_available:
        emit(
            category="behavior",
            event="no_network_activity_after_execution",
            data={
                "pid": proc.pid,
                "process": args.sample,
                "execution_time_sec": args.timeout,
                "network_events": 0,
                "note": (
                    "Process executed without observable network activity. "
                    "This may indicate delayed execution, environment-aware behavior, "
                    "or sandbox evasion."
                ),
            },
        )
        
    emit(
        category="execution",
        event="run_summary",
        data={
            "pid": proc.pid,
            "duration_sec": args.timeout,
            "network_events": NETWORK_EVENT_COUNT
            #"registry_diff": True
        }
    )

    tb = TimelineBuilder(ALL_EVIDENCE)
    timeline = tb.build()
    iocs = tb.extract_iocs()
    summary = tb.summary()

    emit(
        category="analysis",
        event="timeline_built",
        data={
            "total_events": len(timeline),
            "ioc_summary": summary["ioc_counts"]
        }
    )

    emit(
        category="analysis",
        event="ioc_generated",
        data=iocs
    )

    r'''
    emit(
        category="execution",
        event="exit_clean",
        data={
            "pid": ROOTPID,
            "total_events": len(ALL_EVIDENCE),
            "network_events": NETWORK_EVENT_COUNT,
            "status": "clean_exit"
        }
    )
    '''
    
    pesan_ghostrun = f"[GhostRun] Monitors PID {ROOTPID} stopped and Done. Exit clean.";
    emit(
        category="ghostrun_status",
        event="runtime_message",
        data={
            "message": pesan_ghostrun
        }
    )

    # before stopping monitors
    dump_local_evidence(args.file)
    send_backup_file(args.file)

    # Stop sender
    EVIDENCE_QUEUE.put(None)
    sender_thread.join(timeout=5)

    print("[GhostRun] Monitors stopped")
    print("[GhostRun] Done. Exit clean.")


if __name__ == "__main__":
    main()