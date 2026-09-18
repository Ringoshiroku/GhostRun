import time
import psutil

class ProcessMonitor:
    def __init__(self, root_pid, emit_func, poll_interval=1):
        self.root_pid = root_pid
        self.emit = emit_func
        self.poll_interval = poll_interval
        self.seen = set()
        self.running = True
        
        self.parent_map = {}        

    def is_descendant(self, pid, root_pid):
        """
        Check if pid is descendant of root_pid
        """
        current = pid
        while current:
            if current == root_pid:
                return True
            current = self.parent_map.get(current)
        return False

    def run(self):
        self.emit("process", "monitor_start", {
            "root_pid": self.root_pid
        })

        while self.running:
            for proc in psutil.process_iter(
                ["pid", "ppid", "name", "cmdline", "create_time"]
            ):
                try:
                    pid = proc.info["pid"]
                    ppid = proc.info["ppid"]

                    # 🔒 simpan lineage
                    self.parent_map[pid] = ppid

                    if pid in self.seen:
                        continue

                    # root ATAU descendant
                    # root process atau child dari root
                    if self.is_descendant(pid, self.root_pid):
                        self.seen.add(pid)

                        self.emit("process", "process_create", {
                            "pid": pid,
                            "ppid": ppid,
                            "name": proc.info["name"],
                            "cmdline": proc.info["cmdline"],
                            "create_time": proc.info["create_time"],
                        })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            time.sleep(self.poll_interval)

        self.emit("process", "monitor_stop", {})

    def stop(self):
        self.running = False
