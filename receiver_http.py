from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
import threading
from urllib.parse import unquote
import argparse
import json

BASE_DIR = "cases"
HOST = "0.0.0.0"
#PORT = 9001

os.makedirs(BASE_DIR, exist_ok=True)

# every event in a case now streams to one shared <case_id>/evidence.jsonl
# path (see sender_http.py), not a unique path per event. ThreadingHTTPServer
# hands each PUT to its own thread, so without this, two concurrent writes
# to that same path could interleave mid-line and corrupt the file.
_EVIDENCE_WRITE_LOCK = threading.Lock()


class GhostRunPUTHandler(SimpleHTTPRequestHandler):
    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)

        if self.path.startswith("/backup/"):
            filename = os.path.basename(self.path)
            full_path = os.path.join(BASE_DIR, "backup", filename)

            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            with open(full_path, "wb") as f:
                f.write(raw)

            print(f"[BACKUP] Saved → {full_path}")

            self.send_response(201)
            self.end_headers()
            return

        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as e:
            print(f"[!] JSON parse error: {e}")
            self.send_response(400)
            self.end_headers()
            return

        # --- GhostRun control/status channel ---
        if data.get("category") == "ghostrun_status":
            msg = data.get("data", {}).get("message", "")
            print(f"[STATUS] {msg}")

            self.send_response(200)
            self.end_headers()
            return

        # --- Evidence storage path ---
        path = unquote(self.path).lstrip("/")
        full_path = os.path.join(BASE_DIR, path)

        print(f"[+] Evidence → {full_path}")

        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        with _EVIDENCE_WRITE_LOCK:
            with open(full_path, "ab") as f:
                f.write(raw)
                f.write(b"\n")

        self.send_response(201)
        self.end_headers()
    
    r'''    
    def do_PUT(self):
        if data.get("category") == "ghostrun_status":
            msg = data.get("data", {}).get("message", "")
            print(msg)
            return
        
        path = unquote(self.path).lstrip("/")

        # expected: cases/<case_id>/<filename>.json
        full_path = os.path.join(BASE_DIR, path)
        print(f"full_path: {full_path}")
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        length = int(self.headers.get("Content-Length", 0))
        with open(full_path, "ab") as f:
            f.write(self.rfile.read(length))
            f.write(b"\n")

        self.send_response(201)
        self.end_headers()
        reply_body = 'Saved "%s"\n' % full_path
        self.wfile.write(reply_body.encode('utf-8'))
     '''   

    def log_message(self, format, *args):
        return


def main(port):
    print(f"[+] GhostRun Receiver PUT started on host {HOST} and port {port}")
    server = ThreadingHTTPServer((HOST, port), GhostRunPUTHandler)
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GhostRun HTTP Receiver")
    parser.add_argument("--port", type=int, default=9001)
    args = parser.parse_args()  
    
    main(args.port)
