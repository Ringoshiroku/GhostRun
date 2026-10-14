import time

import psutil


class ConnectionMonitor:
    """
    tracks which PID holds which local TCP/UDP port over time.
    polls psutil.net_connections() on an interval for the whole run.

    used after capture to resolve a Suricata-observed flow's local port
    back to the process that likely owned it, instead of stamping every
    network event with the sample's root PID regardless of which
    process actually generated it.

    uses a 1s poll interval, not the 5s convention MutexMonitor uses
    elsewhere, since a short-lived beacon connection is exactly the
    case worth catching here.
    """

    def __init__(self, poll_interval=1):
        self.poll_interval = poll_interval
        self.running = True
        self._snapshots = []  # [(timestamp: float, {local_port: pid})]

    def run(self):
        while self.running:
            self._poll_once()
            time.sleep(self.poll_interval)

    def stop(self):
        self.running = False

    def _poll_once(self):
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            # never let one failed poll (e.g. a permissions issue) stop the
            # monitor. just skip this tick's snapshot.
            return
        port_to_pid = {
            c.laddr.port: c.pid
            for c in conns
            if c.laddr and c.pid
        }
        self._snapshots.append((time.time(), port_to_pid))

    def resolve_pid(self, port, flow_timestamp):
        """
        returns the PID holding `port` in whichever recorded snapshot is
        closest in time to flow_timestamp.
        returns None if no snapshot ever had that port open.
        """
        best_pid, best_delta = None, None
        for ts, port_map in self._snapshots:
            if port in port_map:
                delta = abs(ts - flow_timestamp)
                if best_delta is None or delta < best_delta:
                    best_delta, best_pid = delta, port_map[port]
        return best_pid
