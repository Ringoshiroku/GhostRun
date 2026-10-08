import psutil


def kill_process_tree(pid, emit_func=None, trigger=None):
    """
    best-effort, idempotent termination of a process and every descendant
    it spawned.

    never raises: a safety mechanism that can crash the caller isn't a
    safety mechanism.

    safe to call more than once. a call against an already-dead tree is
    a silent no-op, since that's the expected case and logging every
    run would be noise.
    """
    try:
        root = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    except Exception:
        _emit(emit_func, pid, trigger, killed_pids=[], failed_pids=[pid])
        return

    try:
        children = root.children(recursive=True)
    except Exception:
        children = []

    procs = list(children) + [root]

    failed_pids = []
    already_gone_pids = set()
    for proc in procs:
        try:
            proc.kill()
        except psutil.NoSuchProcess:
            already_gone_pids.add(proc.pid)
        except psutil.AccessDenied:
            failed_pids.append(proc.pid)
        except Exception:
            failed_pids.append(proc.pid)

    try:
        gone, alive = psutil.wait_procs(procs, timeout=5)
    except Exception:
        gone, alive = [], procs

    failed_pid_set = set(failed_pids)
    killed_pids = [
        p.pid
        for p in gone
        if p.pid not in failed_pid_set and p.pid not in already_gone_pids
    ]
    for proc in alive:
        if proc.pid not in failed_pid_set and proc.pid not in already_gone_pids:
            failed_pids.append(proc.pid)

    if not killed_pids and not failed_pids:
        return

    _emit(emit_func, pid, trigger, killed_pids, failed_pids)


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
