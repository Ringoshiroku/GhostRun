import http.client
import time
import json


class PutEvidenceSender:
    def __init__(self, host, port, case_id, timeout=5):
        self.host = host
        self.port = port
        self.case_id = case_id
        self.timeout = timeout

    def send(self, evidence):
        ts = int(time.time() * 1000)
        path = f"/{self.case_id}/{ts}.json"

        body = json.dumps(evidence, ensure_ascii=False).encode("utf-8")

        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        conn.request(
            "PUT",
            path,
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )

        resp = conn.getresponse()
        resp.read()
        conn.close()

        if resp.status not in (200, 201):
            raise RuntimeError(f"PUT failed: {resp.status}")
    r'''
    def send_raw(self, path, data):
        conn = http.client.HTTPConnection(self.host, self.port)
        conn.request("PUT", path, body=data)
        conn.getresponse()
        conn.close()
    '''
    
    def send_raw(self, path, data, content_type="application/octet-stream"):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

        conn.request(
            "PUT",
            path,
            body=data,
            headers={
                "Content-Type": content_type,
                "Content-Length": str(len(data)),
            },
        )

        resp = conn.getresponse()
        resp.read()
        conn.close()

        if resp.status not in (200, 201):
            raise RuntimeError(f"RAW PUT failed: {resp.status}")
