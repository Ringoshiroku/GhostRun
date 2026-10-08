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
from registry_snapshot import snapshot_registry, snapshot_registry_subtree, diff_registry, strip_curated_keys
from registry_watch import RegistryWatcher
from persistence_detector import PersistenceDetector
from detector_network_inference import NetworkInferenceDetector
from detector_static_network import StaticNetworkIndicatorDetector
from filesystem_watch import FilesystemWatcher
from yara_scan import load_yara_rules
from persistence_watch import PersistenceWatcher
from mutex_watch import MutexMonitor, list_all_named_objects
from timeline_builder import TimelineBuilder
from network_finding_engine import NetworkFindingEngine
from process_termination import kill_process_tree
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

    # safety net: on_exit() is already registered for atexit, SIGINT, and
    # SIGTERM below
    # together those cover normal completion, an uncaught exception out of
    # main(), and the analyst interrupting the run
    # so this is the one place that reliably runs across all three, without
    # a separate try/finally wrapper
    # idempotent and safe even if the primary post-timeout kill (see section
    # 5 below) already handled it, a no-op in that case
    kill_process_tree(pid, emit, trigger="on_exit")
        
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

    # yara rules for scanning dropped files: resolved and compiled exactly
    # once here, before any baseline, before network capture starts, and
    # before the sample launches
    # resolution can prompt interactively and git clone the community ruleset;
    # doing that later would put the prompt mid-run, eat into the analysis
    # timeout, and put the clone's own github.com traffic in the
    # pcap/suricata capture (and its process activity after the baselines)
    # where it would look indistinguishable from the sample's
    # compiling once here also means each dropped file is only matched,
    # never recompiled
    yara_rules = load_yara_rules()


    # -----------------------------------------------------
    # 2️⃣ Snapshot BEFORE
    # -----------------------------------------------------
    print(f"[GhostRun] Registry snapshot: BEFORE")
    reg_before = snapshot_registry()

    # mutex/named-object baseline must be captured before Popen() below too,
    # same reasoning as reg_before
    # a single-instance mutex is usually created within the sample's first
    # few milliseconds
    # baselining after the sample is already running would permanently diff
    # it away as "pre-existing" and it would never get reported
    print(f"[GhostRun] Mutex/named-object baseline: BEFORE")
    mutex_before, _ = list_all_named_objects()

    triggered_roots = set()

    def _on_registry_root_changed(hive, path):
        triggered_roots.add((hive, path))

    registry_watcher = RegistryWatcher(on_change=_on_registry_root_changed)
    registry_watcher.start()

    # broad-root baseline for the watcher's catch-all roots, taken now for the
    # same reason as reg_before: you can't retroactively capture "before" once
    # something has already changed
    # paid once per root here; the matching AFTER walk below only runs for
    # roots that actually fired, not all of them, so a quiet run costs
    # nothing extra beyond this
    broad_root_before = {
        (hive, path): snapshot_registry_subtree(hive, path)
        for hive, path in registry_watcher.watched_roots
    }

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
    # os.path.dirname(args.file) is "" when --file is a bare filename with no
    # directory part, and suricata's -l flag rejects that outright ("logging
    # directory "" ... doesn't exist")
    # fall back to the current directory in that case
    out_dir = os.path.dirname(args.file) or "."
    sslkeylogfile_path = os.path.join(out_dir, "sslkeylog.txt")
    os.environ["SSLKEYLOGFILE"] = sslkeylogfile_path  # set before sample launch, opportunistic

    net_capture = NetworkCapture(
        pcap_path=os.path.join(out_dir, "capture.pcap"),
        eve_log_dir=out_dir,
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
    fs_watcher = FilesystemWatcher(targets=FS_TARGETS, emit_func=emit, root_pid=ROOTPID, yara_rules=yara_rules)
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

    # wmi persistence watcher (t1546.003) and named-object (mutex) monitor
    persistence_watcher = PersistenceWatcher(emit_func=emit, root_pid=ROOTPID)
    persistence_thread = threading.Thread(
        target=persistence_watcher.run,
        daemon=True
    )
    persistence_thread.start()

    mutex_monitor = MutexMonitor(emit_func=emit, root_pid=ROOTPID, baseline=mutex_before)
    mutex_thread = threading.Thread(
        target=mutex_monitor.run,
        daemon=True
    )
    mutex_thread.start()

    # hang backstop: if the main thread never reaches the primary post-timeout
    # kill above (e.g. stuck inside a blocking call in one of the teardown
    # steps below, with nothing to raise it out), this is the only one of
    # the three kill call sites that can still save the run
    # it runs on its own independent timer instead of depending on the main
    # thread's own progress
    # the 60s grace buffer covers the slowest observed teardown step
    # (suricata's offline pcap analysis) plus the three 5s monitor-thread
    # joins later in main()
    # idempotent: a no-op if the primary kill (or on_exit) already handled
    # it, which is the normal, expected outcome
    def _watchdog():
        time.sleep(args.timeout + 60)
        kill_process_tree(ROOTPID, emit, trigger="watchdog_hang")

    watchdog_thread = threading.Thread(target=_watchdog, daemon=True)
    watchdog_thread.start()

    print("[GhostRun] Monitoring started")
    
    # -----------------------------------------------------
    # 5️⃣ Run until timeout
    # -----------------------------------------------------
    time.sleep(args.timeout)

    # force-terminate the sample's full process tree now, before taking any
    # AFTER snapshot or starting teardown
    # otherwise the sample keeps running (and possibly still mutating
    # registry/mutex state) during the several-second teardown sequence below
    # and the AFTER snapshots would reflect some arbitrary mid-teardown moment
    # instead of the genuinely final state
    kill_process_tree(ROOTPID, emit, trigger="timeout")

    # -----------------------------------------------------
    # 6️⃣ Snapshot AFTER
    # -----------------------------------------------------
    print(f"[GhostRun] Registry snapshot (PID {ROOTPID}): AFTER")
    reg_after = snapshot_registry()

    registry_watcher.stop()
    diff_registry(reg_before, reg_after, emit, ROOTPID)

    # real targeted diff for whichever broad roots actually fired, instead of
    # a content-free notice
    # reuses diff_registry/classify_registry_event unchanged, which already
    # correctly withholds known_persistence_location for anything outside the
    # curated PERSISTENCE_KEYS list
    # still surfaces the raw change and, where applicable,
    # execution_reference_detected
    # strip_curated_keys() drops anything the curated diff_registry call above
    # already reported (a curated key, e.g. the Run key, can sit inside one
    # of these broad roots), so it isn't reported twice
    for hive, path in sorted(triggered_roots):
        broad_root_after = snapshot_registry_subtree(hive, path)
        diff_registry(
            strip_curated_keys(broad_root_before[(hive, path)]),
            strip_curated_keys(broad_root_after),
            emit, ROOTPID,
        )

    print(f"[GhostRun] Filesystem watcher (PID {ROOTPID}): STOP")
    fs_watcher.stop()

    # -----------------------------------------------------
    # 7️⃣ Stop monitors cleanly
    # -----------------------------------------------------
    proc_monitor.stop()
    persistence_watcher.stop()
    mutex_monitor.stop()

    proc_thread.join(timeout=5)
    persistence_thread.join(timeout=5)
    mutex_thread.join(timeout=5)

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