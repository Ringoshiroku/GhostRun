import psutil


def kill_process_tree(pid, emit_func=None, trigger=None, expected_create_time=None):
    """
    best-effort, idempotent termination of a process and every descendant
    it spawned.

    never raises: a safety mechanism that can crash the caller isn't a
    safety mechanism.

    safe to call more than once. a call against an already-dead tree is
    a silent no-op, since that's the expected case and logging every
    run would be noise.

    expected_create_time, when given, guards against PID reuse. if the
    live process at `pid` has a different create_time than expected,
    it isn't the process this caller launched (the OS already handed
    that PID to something else), so this is treated like the process
    being gone, never killed.

    returns (killed_pids, failed_pids), both empty when there was
    nothing to do.
    """
    try:
        root = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return [], []
    except Exception:
        _emit(emit_func, pid, trigger, killed_pids=[], failed_pids=[pid])
        return [], [pid]

    if expected_create_time is not None:
        try:
            if root.create_time() != expected_create_time:
                return [], []
        except Exception:
            return [], []

    try:
        children = root.children(recursive=True)
    except Exception:
        children = []

    procs = list(children) + [root]

    already_gone_pids = set()
    for proc in procs:
        try:
            proc.kill()
        except psutil.NoSuchProcess:
            already_gone_pids.add(proc.pid)
        except Exception:
            pass  # on AccessDenied or any other error, wait_procs below decides

    try:
        gone, alive = psutil.wait_procs(procs, timeout=5)
    except Exception:
        gone, alive = [], procs

    killed_pids = [p.pid for p in gone if p.pid not in already_gone_pids]
    failed_pids = [p.pid for p in alive]

    if not killed_pids and not failed_pids:
        return [], []

    _emit(emit_func, pid, trigger, killed_pids, failed_pids)
    return killed_pids, failed_pids


def _emit(emit_func, pid, trigger, killed_pids, failed_pids):
    if emit_func is None:
        return
    try:
        emit_func(
            category="execution",
            event="sample_force_terminated",
            data={
                "pid": pid,
                "trigger": trigger,
                "killed_pids": killed_pids,
                "failed_pids": failed_pids,
            },
        )
    except Exception:
        pass
