#!/usr/bin/env python3
"""Tiny HTTP front end for the stage-1 screener (Render free web service).

Endpoints:
  /          status
  /run       start one coarse-test run in the background (returns immediately)
  /results   survivors as plain share-link text (copy -> v2rayN clipboard import)
  /untested  links the tester could not cover (parse unsupported), same format
  /report    JSON counts + per-node delays
"""
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA = os.environ.get("DATA_DIR", "/app/data")
PORT = int(os.environ.get("PORT", "10000"))
state = {"running": False, "last": None}


def run_pipeline():
    state["running"] = True
    try:
        r = subprocess.run(
            ["python3", "screener.py"],
            capture_output=True, text=True, timeout=3600, cwd="/app",
        )
        state["last"] = {
            "returncode": r.returncode,
            "stdout": r.stdout[-2000:],
            "stderr": r.stderr[-2000:],
        }
    except Exception as e:  # noqa: BLE001 - surfaced in /report
        state["last"] = {"error": str(e)}
    finally:
        state["running"] = False


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        b = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _file(self, name, empty_note):
        p = os.path.join(DATA, name)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                self._send(200, f.read())
        else:
            self._send(200, empty_note)

    def do_GET(self):  # noqa: N802 - stdlib name
        if self.path == "/":
            self._send(
                200,
                "node-screener ok\nrunning=%s\n"
                "GET /run to start a coarse test\n"
                "GET /results for survivors (original links, copy to v2rayN)\n"
                "GET /untested for links this tester could not cover\n"
                "GET /report for JSON counts and delays\n" % state["running"],
            )
        elif self.path == "/run":
            if state["running"]:
                self._send(200, "already running\n")
            else:
                threading.Thread(target=run_pipeline, daemon=True).start()
                self._send(200, "started\n")
        elif self.path == "/results":
            self._file("survivors.txt", "no results yet; GET /run first\n")
        elif self.path == "/untested":
            self._file("untested.txt", "no results yet; GET /run first\n")
        elif self.path == "/report":
            p = os.path.join(DATA, "report.json")
            if os.path.exists(p):
                with open(p, encoding="utf-8") as f:
                    self._send(200, f.read(), "application/json")
            else:
                self._send(200, json.dumps({"running": state["running"], "last": state["last"]}, ensure_ascii=False), "application/json")
        else:
            self._send(404, "not found\n")

    def log_message(self, *args):  # keep logs quiet
        pass


if __name__ == "__main__":
    os.makedirs(DATA, exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
