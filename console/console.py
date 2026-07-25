#!/usr/bin/env python3
"""
Kestrel engineering console — a browser front end for the IEC-104 client.

Runs as its own container. You type the RTU's address into the page (IP or
hostname, plus port), it opens an IEC 60870-5-104 session, and you drive it with
the same commands the terminal client accepts. The session closes itself when the
maintenance handoff window lapses, which is the behaviour the RTU imposes anyway.

    ./console.py --listen 0.0.0.0 --port 8081

Nothing about the target is baked in: the console has no idea which RTU it is
talking to until someone tells it, which is the point - it is a tool found on an
OT network, not a preconfigured link.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, "/opt/kestrel/client")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "client"))

import rtu_shell  # noqa: E402
from rtu_shell import Shell  # noqa: E402

# The RTU grants ~28 s per accepted handoff. Give the session a hair less so the
# console tears down before commands would start being refused.
HANDOFF_WINDOW = 28.0
IDLE_TIMEOUT = 300.0
MAX_SESSIONS = 8
UI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui.html")

_stdout_lock = threading.Lock()


class Sink:
    """Receives every protocol frame from the client, unfolded.

    Mirrors the Transcript interface the client already writes to, so frames
    arriving on the reader thread land in the right session buffer without any
    dependency on which thread printed them.
    """

    def __init__(self, session):
        self.session = session
        self.muted_depth = 0
        self.lock = threading.Lock()

    @contextlib.contextmanager
    def muted(self):
        with self.lock:
            self.muted_depth += 1
        try:
            yield
        finally:
            with self.lock:
                self.muted_depth -= 1

    @property
    def is_muted(self):
        return self.muted_depth > 0

    def write_line(self, line, raw=False):
        self.session.emit(line)

    def write(self, s):
        for line in s.splitlines():
            if line.strip():
                self.session.emit(line)

    def close(self):
        pass


class Session:
    def __init__(self, host, port, ca, oa, hmi_port=None):
        self.id = uuid.uuid4().hex[:12]
        self.host = host
        self.port = port
        self.hmi_port = hmi_port
        self.lines: list[dict] = []
        self.seq = 0
        self.lock = threading.RLock()
        self.created = time.monotonic()
        self.touched = time.monotonic()
        self.auth_deadline = 0.0
        self.closed = False
        self.close_reason = None
        # `priv` tears the TCP session down and reopens it, because the RTU only
        # accepts a handoff as the first frame of a connection. During that gap
        # the link legitimately looks dead, so the reaper must not act on it.
        self.busy = 0
        self.dead_since = None

        self.shell = Shell(host, port, ca, oa)
        # Confirmation prompts would block a web request forever; the console is
        # an explicit operating tool, so answer them.
        self.shell._ask = lambda prompt: "y"
        self.shell.style = "human"
        self.shell.collapse = True
        if hmi_port:
            self.shell.hmi_port = hmi_port
        self.sink = Sink(self)

    # -- output ------------------------------------------------------------ #

    def emit(self, text, kind=None):
        with self.lock:
            if kind is None:
                s = text.lstrip()
                if s.startswith("you ->"):
                    kind = "tx"
                elif s.startswith("RTU ->"):
                    kind = "rx"
                elif s.startswith("[!]") or "REFUSED" in s or "ERROR" in s:
                    kind = "bad"
                elif s.startswith("[ok]") or "accepted" in s:
                    kind = "good"
                elif s.startswith("***") or "ACTION REQUIRED" in s:
                    kind = "alert"
                elif s.startswith("rtu>"):
                    kind = "cmd"
                else:
                    kind = "info"
            text = text.rstrip()
            # Periodic measurements repeat every 350 ms. Fold identical
            # consecutive lines into a counted one, the way the terminal client
            # does, or the pane is unreadable.
            if self.lines and self.lines[-1]["base"] == text:
                last = self.lines[-1]
                last["rep"] += 1
                last["t"] = f"{text}   (x{last['rep']})"
                self.seq += 1
                last["n"] = self.seq
                return
            self.seq += 1
            self.lines.append({"n": self.seq, "t": text, "base": text,
                               "rep": 1, "k": kind})
            del self.lines[:-800]

    def since(self, n):
        with self.lock:
            return [ln for ln in self.lines if ln["n"] > n]

    # -- lifecycle --------------------------------------------------------- #

    def connect(self):
        self.emit(f"connecting to {self.host}:{self.port} ...", "info")
        with _stdout_lock:
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                self.shell.cmd_open([])
            finally:
                sys.stdout = old
        for line in buf.getvalue().splitlines():
            if line.strip():
                self.emit(line)
        if self.shell.c is None:
            self.closed = True
            self.close_reason = "connect failed"
            return False
        self.shell.c.log_sink = self.sink
        self.shell.transcript = self.sink
        self.emit("session open. Send `priv` to replay the maintenance handoff, "
                  "then commands within the window.", "info")
        return True

    @property
    def window_left(self):
        return max(0.0, self.auth_deadline - time.monotonic())

    def run(self, line):
        """Execute one command line and return the newly produced output."""
        if self.closed:
            return
        self.touched = time.monotonic()
        with self.lock:
            self.busy += 1
        self.emit(f"rtu> {line}", "cmd")
        # `priv` opens (or reopens) the handoff window.
        if any(part.strip().split()[:1] == ["priv"]
               for part in line.split(";") if part.strip()):
            self.auth_deadline = time.monotonic() + HANDOFF_WINDOW
        with _stdout_lock:
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            # Detach the frame sink for the duration: the client writes every
            # frame to BOTH its log sink and stdout, and we are capturing
            # stdout, so leaving the sink attached duplicates every line.
            if self.shell.c is not None:
                self.shell.c.log_sink = None
            self.shell.transcript = None
            try:
                self.shell.run_line(line)
            except SystemExit:
                self.close("client asked to quit")
            except Exception as exc:                       # noqa: BLE001
                self.emit(f"[!] {exc!r}", "bad")
            finally:
                sys.stdout = old
                # Reattach to whichever client object exists now: `priv`
                # reconnects, so this may be a different one.
                self.shell.transcript = self.sink
                if self.shell.c is not None:
                    self.shell.c.log_sink = self.sink
                with self.lock:
                    self.busy -= 1
                    self.dead_since = None
        for out in buf.getvalue().splitlines():
            if out.strip():
                self.emit(out)

    def close(self, reason="closed"):
        if self.closed:
            return
        self.closed = True
        self.close_reason = reason
        try:
            if self.shell.c is not None:
                self.shell.c.log_sink = None
                self.shell.cmd_close([])
        except Exception:                                  # noqa: BLE001
            pass
        self.emit(f"-- session closed: {reason} --", "alert")

    def state(self):
        return {
            "id": self.id,
            "target": f"{self.host}:{self.port}",
            "hmi_port": self.hmi_port,
            "closed": self.closed,
            "reason": self.close_reason,
            "window_left": round(self.window_left, 1),
            "authorised": self.window_left > 0,
            "seq": self.seq,
        }


class Manager:
    def __init__(self):
        self.sessions: dict[str, Session] = {}
        self.lock = threading.Lock()
        threading.Thread(target=self._reaper, daemon=True).start()

    def create(self, host, port, ca, oa, hmi_port):
        with self.lock:
            live = [s for s in self.sessions.values() if not s.closed]
            if len(live) >= MAX_SESSIONS:
                raise RuntimeError("too many open sessions on this console")
            s = Session(host, port, ca, oa, hmi_port)
            self.sessions[s.id] = s
        s.connect()
        return s

    def get(self, sid):
        return self.sessions.get(sid)

    def _reaper(self):
        """Close sessions whose handoff window has lapsed, or that went idle.

        This is the behaviour the RTU forces: authorisation is granted for a
        fixed window and commands are refused afterwards. Rather than leave a
        dead-feeling terminal, the console drops the link and says why.
        """
        while True:
            time.sleep(1.0)
            now = time.monotonic()
            for s in list(self.sessions.values()):
                if s.closed:
                    if now - s.touched > 600:
                        self.sessions.pop(s.id, None)
                    continue
                if s.busy:
                    continue          # a command is mid-flight; leave it alone
                if s.auth_deadline and now > s.auth_deadline:
                    s.close("maintenance handoff expired - "
                            "reconnect and send `priv` again")
                elif now - s.touched > IDLE_TIMEOUT:
                    s.close("idle timeout")
                elif s.shell.c is None or not s.shell.c._running:
                    # Require the link to look dead twice in a row, so a
                    # reconnect between polls is never mistaken for a drop.
                    if s.dead_since is None:
                        s.dead_since = now
                    elif now - s.dead_since > 3.0:
                        s.close("the RTU dropped the link")
                else:
                    s.dead_since = None


def make_handler(mgr, banner):
    class Handler(BaseHTTPRequestHandler):
        server_version = "KestrelConsole/1.2"
        sys_version = "Python/3.12"

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n).decode())
            except ValueError:
                return {}

        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                try:
                    with open(UI_PATH, "rb") as fh:
                        body = fh.read()
                except OSError:
                    self.send_error(500, "ui.html missing")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/api/banner":
                self._json(banner)
                return
            if path == "/api/poll":
                q = dict(p.split("=", 1) for p in
                         self.path.split("?", 1)[-1].split("&") if "=" in p)
                s = mgr.get(q.get("session", ""))
                if s is None:
                    self._json({"error": "no such session"}, 404)
                    return
                since = int(q.get("since", "0") or 0)
                self._json({"lines": s.since(since), "state": s.state()})
                return
            self.send_error(404, "Not Found")

        def do_POST(self):
            path = self.path.split("?")[0]
            body = self._body()
            if path == "/api/connect":
                host = str(body.get("host", "")).strip()
                if not host:
                    self._json({"error": "enter a host or IP"}, 400)
                    return
                try:
                    port = int(body.get("port") or 2404)
                    hmi = int(body.get("hmi_port")) if body.get("hmi_port") else None
                    ca = int(body.get("ca") or 17)
                    oa = int(body.get("oa") or 0)
                except (TypeError, ValueError):
                    self._json({"error": "ports and addresses must be numbers"}, 400)
                    return
                try:
                    s = mgr.create(host, port, ca, oa, hmi)
                except Exception as exc:                    # noqa: BLE001
                    self._json({"error": str(exc)}, 400)
                    return
                self._json({"session": s.id, "state": s.state(),
                            "lines": s.since(0)})
                return
            if path == "/api/cmd":
                s = mgr.get(str(body.get("session", "")))
                if s is None:
                    self._json({"error": "no such session"}, 404)
                    return
                if s.closed:
                    self._json({"error": s.close_reason or "session closed",
                                "state": s.state()}, 409)
                    return
                line = str(body.get("line", "")).strip()
                if line:
                    s.run(line)
                self._json({"state": s.state()})
                return
            if path == "/api/disconnect":
                s = mgr.get(str(body.get("session", "")))
                if s is not None:
                    s.close("disconnected by operator")
                self._json({"ok": True})
                return
            self.send_error(404, "Not Found")

        def log_message(self, *a):
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Kestrel engineering console")
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--suggest-host", default=os.environ.get(
        "CONSOLE_SUGGEST_HOST", ""),
        help="prefill the target field (leave empty to make them find it)")
    ap.add_argument("--suggest-port", default=os.environ.get(
        "CONSOLE_SUGGEST_PORT", "2404"))
    ap.add_argument("--suggest-hmi", default=os.environ.get(
        "CONSOLE_SUGGEST_HMI", ""))
    a = ap.parse_args()

    banner = {
        "product": "Kestrel Engineering Console",
        "version": "1.2",
        "protocol": "IEC 60870-5-104",
        "handoff_window_s": HANDOFF_WINDOW,
        "suggest": {"host": a.suggest_host, "port": a.suggest_port,
                    "hmi_port": a.suggest_hmi},
    }
    mgr = Manager()
    srv = ThreadingHTTPServer((a.listen, a.port), make_handler(mgr, banner))
    print(f"Kestrel engineering console on http://{a.listen}:{a.port}/")
    print(f"handoff window {HANDOFF_WINDOW:g}s, "
          f"target must be entered in the page"
          + (f" (suggesting {a.suggest_host})" if a.suggest_host else ""))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
