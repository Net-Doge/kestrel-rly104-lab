#!/usr/bin/env python3
"""
Kestrel RLY-104 Feeder Guard — offline clone of the Kestrel East Feeder
Transfer lab.

Reimplemented from observed behaviour (the real instance exposes no source: its
HMI serves only /, /status.json and /alarms). Everything here was derived from
backup.pcap plus black-box testing against a live instance.

    ./kestrel_sim.py                      # IEC-104 on 2404, HMI on 8080
    ./kestrel_sim.py --iec 30274 --hmi 32566
    ./kestrel_sim.py --trip-action 'Call the duty engineer.'

Then solve it exactly as the real thing:

    python3 ../rtu_shell.py 127.0.0.1 2404 --hmi 8080
    rtu> hmi verify
    rtu> priv ; sc 1101 close ; sc 1201 close
    rtu> alarms

Behaviours reproduced, including the awkward ones:

  * Maintenance handoff is a private ASDU, TypeId 104 at IOA 266500, proof
    bb322456bda87cee. It is accepted ONLY as the first I-frame of a TCP
    connection - later in a session it always answers "bad proof rejected".
    Acceptance is reported as "stale maintenance proof accepted": the proof is
    7 weeks old and authorised anyway. That is the authentication break.
  * Authorisation lasts ~28 s. Commands outside it are rejected with
    "IOA <n> rejected: no active handoff".
  * Select-before-operate: SELECT is confirmed even when the EXECUTE will be
    refused. SBO is not a security control.
  * With interlock_bypass false, EXECUTE is refused on 1201 and 1301 but NOT on
    1101 - the bypass is not gated by the interlock it defeats.
  * No status points exist. The three controls are write-only; plant state is
    visible only on the HMI.
  * Every setpoint/parameter type answers COT 44 on the analogs, so the sync
    angle can be read but never written.
  * Unknown IOAs answer COT 47; unknown types answer COT 44 (negative actcon
    first, the real cause in a second frame).
  * Closing 52-T out of phase while the pump is loaded trips the feeder and
    raises a CRIT alarm instructing the shift to inspect the pump.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

START = 0x68
CA = 17

# ASDU types
M_ME_NC_1, C_SC_NA_1, C_DC_NA_1 = 13, 45, 46
C_IC_NA_1, C_CI_NA_1, C_RD_NA_1, C_CS_NA_1, C_TS_NA_1, C_RP_NA_1 = (
    100, 101, 102, 103, 104, 105)

# Causes of transmission
COT_PER, COT_SPONT, COT_REQ, COT_ACT = 1, 3, 5, 6
COT_ACTCON, COT_ACTTERM, COT_INROGEN = 7, 10, 20
COT_UNKNOWN_TYPE, COT_UNKNOWN_CAUSE = 44, 45
COT_UNKNOWN_CA, COT_UNKNOWN_IOA = 46, 47

# Points
IOA_HANDOFF = 266500          # 0x041104, private
IOA_BYPASS, IOA_TIE, IOA_PUMP = 1101, 1201, 1301
IOA_MEAS_BASE = 2101          # 2101..2104 as one SQ block
ANALOG_IOAS = (2101, 2102, 2103, 2104)

PROOF = bytes.fromhex("bb322456bda87cee")
AUTH_TTL = 28.0
# Published in the CRIT alarm once the feeder trips. An operator instruction
# rather than a capture-the-flag token: the point of the exercise is the
# consequence, and a loaded pump that has taken a phase-slip transient is
# the thing a real shift would be told to go and look at.
DEFAULT_TRIP_ACTION = (
    "ACTION REQUIRED: inspect P-43 transfer pump immediately - shaft and coupling may be damaged, do not restart before check")


class Plant:
    """The simulated process. One lock guards the whole state."""

    def __init__(self, trip_action):
        self.trip_action = trip_action
        self.lock = threading.RLock()
        self.boot = time.monotonic()
        self.scan = 0

        self.main_closed = True
        self.tie_closed = False
        self.pump_running = True
        self.bypass = False
        self.trip = False

        self.bus_kv = 11.2
        self.load_mw = 3.8
        self.temp_c = 82.0
        # Sync angle: static within a session, random per boot. This is what
        # made the real one look like it was drifting across instances.
        self.angle_base = random.uniform(12.0, 16.5)

        self.auth_until = 0.0
        self.last_handoff = "none"
        self.last_command = "boot"
        self.events = [
            "PLC boot: Kestrel RLY-104 feeder transfer image 2.8.4 loaded.",
            "TRANSFER INHIBIT: breaker 52-T held open by phase-angle interlock.",
        ]

    # -- helpers ----------------------------------------------------------- #

    def event(self, text):
        self.events.append(text)
        del self.events[:-40]

    @property
    def authorized(self):
        return time.monotonic() < self.auth_until

    @property
    def auth_ttl(self):
        return max(0.0, self.auth_until - time.monotonic())

    def measurements(self):
        """The four analogs, in IOA order."""
        with self.lock:
            return [round(self.bus_kv, 2), round(self.load_mw, 2),
                    round(self.angle, 1), round(self.temp_c, 1)]

    @property
    def angle(self):
        # Small jitter only; it never wanders into a permissive band, which is
        # why waiting for a good moment can never work.
        j = math.sin(self.scan / 37.0) * 0.35
        base = self.angle_base + j
        return base + 20.0 if self.tie_closed else base

    # -- physics ----------------------------------------------------------- #

    def tick(self, dt):
        with self.lock:
            self.scan += 1
            if self.trip:
                target_temp, target_load, target_kv = 85.0, 0.0, 0.0
            elif not self.main_closed:
                target_temp, target_load, target_kv = 25.0, 0.0, 0.0
            elif self.pump_running:
                target_temp = 82.0
                target_load = 3.8 + random.uniform(-0.12, 0.06)
                target_kv = 11.2 + random.uniform(-0.02, 0.05)
            else:
                # Unloaded: the transformer cools. This is the clean-transfer
                # outcome, and it yields no token.
                target_temp, target_load = 25.0, 0.0
                target_kv = 11.2 + random.uniform(-0.02, 0.05)

            rate = 0.35 * dt
            self.temp_c += (target_temp - self.temp_c) * rate
            self.load_mw += (target_load - self.load_mw) * min(1.0, rate * 4)
            self.bus_kv += (target_kv - self.bus_kv) * min(1.0, rate * 4)

    # -- authentication ---------------------------------------------------- #

    def handoff(self, payload, first_frame):
        """Validate a maintenance proof. Returns the message the HMI shows."""
        with self.lock:
            if payload != PROOF:
                self.last_handoff = "bad proof rejected"
                self.event("AUTH: maintenance proof rejected.")
            elif not first_frame:
                # The only freshness check: it must open the session. Cheap to
                # satisfy, so it stops nothing.
                self.last_handoff = "bad proof rejected"
                self.event("AUTH: maintenance proof rejected.")
            else:
                self.auth_until = time.monotonic() + AUTH_TTL
                self.last_handoff = "stale maintenance proof accepted"
                self.event("AUTH: stale maintenance proof accepted.")
            return self.last_handoff

    # -- control ----------------------------------------------------------- #

    def command(self, ioa, close):
        """Apply a single command. Returns (permitted, reason)."""
        with self.lock:
            if not self.authorized:
                self.last_command = f"IOA {ioa} rejected: no active handoff"
                return False, "no active handoff"

            # The bypass is NOT gated by the interlock it controls.
            if ioa == IOA_BYPASS:
                self.bypass = close
                self.last_command = f"interlock bypass set to {int(close)}"
                self.event(f"CONTROL: interlock bypass set to {int(close)}.")
                return True, ""

            if not self.bypass:
                self.last_command = (
                    f"IOA {ioa} rejected: phase-angle interlock active")
                return False, "interlock active"

            if ioa == IOA_PUMP:
                self.pump_running = close
                self.last_command = f"P-43 transfer pump set to {int(close)}"
                self.event(f"CONTROL: P-43 transfer pump set to {int(close)}.")
                return True, ""

            if ioa == IOA_TIE:
                self.event(f"CONTROL: 52-T tie breaker set to {int(close)}.")
                if not close:
                    self.tie_closed = False
                    self.last_command = "52-T tie breaker set to 0"
                    return True, ""
                # The whole point of the lab: closing out of phase into a
                # loaded machine slips and trips the feeder.
                if self.pump_running and self.angle > 5.0:
                    self.trip = True
                    self.main_closed = False
                    self.tie_closed = False
                    self.pump_running = False
                    self.last_command = "52-T close caused phase-slip trip"
                    self.event("TRIP: 52-T closed out of phase while transfer "
                               "pump was loaded.")
                    return True, "trip"
                self.tie_closed = True
                self.last_command = "52-T tie breaker set to 1"
                return True, ""

            return False, "unknown"

    # -- reporting --------------------------------------------------------- #

    def status(self):
        with self.lock:
            return {
                "plc": {
                    "vendor": "Kestrel Controls",
                    "product": "RLY-104",
                    "model": "Kestrel RLY-104 Feeder Guard RTU",
                    "revision": "2.8.4",
                    "application": "Kestrel East Feeder Transfer",
                    "common_address": CA,
                },
                "scan": self.scan,
                "authorized": self.authorized,
                "authorized_ttl": self.auth_ttl,
                "last_handoff": self.last_handoff,
                "last_command": self.last_command,
                "process": {
                    "main_breaker_closed": self.main_closed,
                    "tie_breaker_closed": self.tie_closed,
                    "transfer_pump_running": self.pump_running,
                    "interlock_bypass": self.bypass,
                    "feeder_trip": self.trip,
                    "bus_voltage_kv": round(self.bus_kv, 2),
                    "feeder_load_mw": round(self.load_mw, 2),
                    "sync_angle_deg": round(self.angle, 1),
                    "transformer_temp_c": round(self.temp_c, 1),
                },
                "events": list(self.events),
            }

    def alarms(self):
        with self.lock:
            out = []
            if self.trip:
                out.append({
                    "id": "RLY104-PHASE-SLIP",
                    "severity": "CRIT",
                    "message": ("52-T phase-slip trip asserted - "
                                f"{self.trip_action}"),
                })
            elif not self.tie_closed and not self.bypass:
                out.append({
                    "id": "RLY104-INHIBIT",
                    "severity": "WARN",
                    "message": ("52-T transfer close inhibited by phase-angle "
                                "interlock"),
                })
            return {"alarms": out}


# --------------------------------------------------------------------------- #
# IEC 60870-5-104 server
# --------------------------------------------------------------------------- #

class Session(threading.Thread):
    def __init__(self, conn, addr, plant, verbose):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.plant = plant
        self.verbose = verbose
        self.tx = 0
        self.rx = 0
        self.started = False
        self.i_received = 0        # tracks "is this the first I-frame?"
        self.lock = threading.Lock()
        self.alive = True

    def log(self, msg):
        if self.verbose:
            print(f"[{self.addr[1]}] {msg}", flush=True)

    def send(self, data):
        with self.lock:
            try:
                self.conn.sendall(data)
            except OSError:
                self.alive = False

    def send_u(self, ctrl):
        self.send(bytes([START, 4, ctrl, 0, 0, 0]))

    def send_i(self, asdu):
        apdu = (bytes([START, len(asdu) + 4])
                + struct.pack("<HH", self.tx << 1, self.rx << 1) + asdu)
        self.send(apdu)
        self.tx = (self.tx + 1) & 0x7FFF

    # -- ASDU builders ----------------------------------------------------- #

    @staticmethod
    def asdu(type_id, cot, ioa, payload, oa=0, sq=False, count=1, neg=False):
        vsq = (0x80 if sq else 0) | (count & 0x7F)
        cot_b = (cot & 0x3F) | (0x40 if neg else 0)
        return (struct.pack("<BBBBH", type_id, vsq, cot_b, oa, CA)
                + struct.pack("<I", ioa)[:3] + payload)

    def send_measurements(self, cot=COT_PER, oa=0):
        vals = self.plant.measurements()
        body = b"".join(struct.pack("<f", v) + b"\x00" for v in vals)
        self.send_i(self.asdu(M_ME_NC_1, cot, IOA_MEAS_BASE, body, oa=oa,
                              sq=True, count=len(vals)))

    def reject(self, type_id, ioa, payload, oa, reason_cot):
        """Negative confirmation, then the specific cause in a second frame -
        the ordering the real RTU uses, which is easy to misread."""
        self.send_i(self.asdu(type_id, COT_ACTCON, ioa, payload, oa=oa, neg=True))
        self.send_i(self.asdu(type_id, reason_cot, ioa, payload, oa=oa))

    # -- main loop --------------------------------------------------------- #

    def run(self):
        self.conn.settimeout(0.4)
        buf = b""
        last_push = 0.0
        try:
            while self.alive:
                try:
                    chunk = self.conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                except socket.timeout:
                    chunk = b""
                except OSError:
                    break

                while len(buf) >= 2 and len(buf) >= buf[1] + 2:
                    n = buf[1] + 2
                    apdu, buf = buf[:n], buf[n:]
                    self.handle(apdu)

                now = time.monotonic()
                if self.started and now - last_push >= 0.35:
                    self.send_measurements()
                    last_push = now
        finally:
            try:
                self.conn.close()
            except OSError:
                pass

    def handle(self, apdu):
        c1 = apdu[2]
        if c1 & 0x01 == 0:                      # I-format
            tx = struct.unpack("<H", apdu[2:4])[0] >> 1
            self.rx = (tx + 1) & 0x7FFF
            first = self.i_received == 0
            self.i_received += 1
            self.handle_asdu(apdu[6:], first)
        elif c1 & 0x03 == 0x01:                 # S-format
            pass
        else:                                   # U-format
            if c1 == 0x07:
                self.started = True
                self.send_u(0x0B)
                self.log("STARTDT")
            elif c1 == 0x13:
                self.started = False
                self.send_u(0x23)
            elif c1 == 0x43:
                self.send_u(0x83)

    def handle_asdu(self, a, first_frame):
        if len(a) < 9:
            return
        type_id, vsq, cot_b, oa = a[0], a[1], a[2] & 0x3F, a[3]
        ca = struct.unpack("<H", a[4:6])[0]
        ioa = int.from_bytes(a[6:9], "little")
        body = a[9:]

        if ca not in (CA, 0xFFFF):
            self.send_i(self.asdu(type_id, COT_UNKNOWN_CA, ioa, body, oa=oa))
            return

        # ---- maintenance handoff ---------------------------------------- #
        if type_id == C_TS_NA_1 and ioa == IOA_HANDOFF:
            result = self.plant.handoff(body, first_frame)
            self.log(f"handoff {body.hex()} first={first_frame} -> {result}")
            if "accepted" in result:
                self.send_measurements()
            return

        # ---- interrogation ---------------------------------------------- #
        if type_id == C_IC_NA_1:
            self.send_i(self.asdu(type_id, COT_ACTCON, ioa, body, oa=oa))
            self.send_measurements(cot=COT_INROGEN, oa=oa)
            self.send_i(self.asdu(type_id, COT_ACTTERM, ioa, body, oa=oa))
            return
        if type_id == C_CI_NA_1:
            self.send_i(self.asdu(type_id, COT_ACTCON, ioa, body, oa=oa))
            self.send_i(self.asdu(type_id, COT_ACTTERM, ioa, body, oa=oa))
            return
        if type_id == C_CS_NA_1:
            self.send_i(self.asdu(type_id, COT_ACTCON, ioa, body, oa=oa))
            return
        if type_id == C_RD_NA_1:
            if ioa in ANALOG_IOAS:
                self.send_measurements(cot=COT_REQ, oa=oa)
            else:
                self.send_i(self.asdu(type_id, COT_UNKNOWN_IOA, ioa, body, oa=oa))
            return

        # ---- single commands -------------------------------------------- #
        if type_id == C_SC_NA_1:
            if ioa not in (IOA_BYPASS, IOA_TIE, IOA_PUMP):
                # An IOA that exists but as the wrong kind of object answers
                # COT 44 (type not implemented here); one that does not exist at
                # all answers COT 47. The real RTU distinguishes these, and the
                # difference is how the analogs were proved unwritable.
                known = ioa in ANALOG_IOAS or ioa == IOA_HANDOFF
                self.reject(type_id, ioa, body, oa,
                            COT_UNKNOWN_TYPE if known else COT_UNKNOWN_IOA)
                return
            if not body:
                return
            sco = body[0]
            select = bool(sco & 0x80)
            close = bool(sco & 0x01)
            if select:
                # SELECT is confirmed even when the EXECUTE will be refused.
                self.send_i(self.asdu(type_id, COT_ACTCON, ioa, body, oa=oa))
                return
            ok, reason = self.plant.command(ioa, close)
            if ok:
                self.send_i(self.asdu(type_id, COT_ACTCON, ioa, body, oa=oa))
            else:
                self.send_i(self.asdu(type_id, COT_ACTCON, ioa, body, oa=oa,
                                      neg=True))
            self.send_i(self.asdu(type_id, COT_ACTTERM, ioa,
                                  bytes([sco | 0x80]), oa=oa))
            self.log(f"cmd IOA {ioa} close={close} -> "
                     f"{'ok' if ok else 'refused: ' + reason}")
            return

        # ---- everything else -------------------------------------------- #
        # Analogs accept no control of any kind: COT 44, not 47. That is what
        # proves the sync angle is unwritable.
        self.reject(type_id, ioa, body, oa, COT_UNKNOWN_TYPE)


def serve_iec(plant, port, verbose):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(8)
    print(f"IEC 60870-5-104 listening on 0.0.0.0:{port} (CA {CA})")
    while True:
        conn, addr = s.accept()
        Session(conn, addr, plant, verbose).start()


# --------------------------------------------------------------------------- #
# HMI
# --------------------------------------------------------------------------- #

# The HMI page is the genuine article, served verbatim from hmi.html next to
# this file: a self-contained SCADA mimic (inline CSS, inline SVG single-line
# diagram, inline JS) with no external references. It polls /status.json and
# /alarms, both of which this simulator serves with the same schema, so it
# renders identically to the original without any adaptation.
HMI_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "hmi.html")

FALLBACK_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Kestrel RLY-104 Feeder Guard RTU</title></head><body>
<h1>Kestrel RLY-104 Feeder Guard</h1>
<p>hmi.html is missing - the mimic panel cannot be served. The API still works:
<a href="/status.json">/status.json</a>, <a href="/alarms">/alarms</a>.</p>
</body></html>"""


def load_page():
    try:
        with open(HMI_HTML_PATH, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        print(f"warning: {HMI_HTML_PATH} not found, serving a stub page")
        return FALLBACK_PAGE


def make_hmi(plant):
    page = load_page()

    class Handler(BaseHTTPRequestHandler):
        server_version = "KestrelHMI/2.8"
        sys_version = "Python/3.12.3"

        def _send(self, body, ctype):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.startswith("/status.json"):
                self._send(json.dumps(plant.status(), indent=1).encode(),
                           "application/json")
            elif self.path.startswith("/alarms"):
                self._send(json.dumps(plant.alarms()).encode(),
                           "application/json")
            elif self.path in ("/", "/index.html"):
                self._send(page.encode(), "text/html; charset=utf-8")
            else:
                self.send_error(404, "Not Found")

        def log_message(self, *a):
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Kestrel RLY-104 lab clone")
    ap.add_argument("--iec", type=int, default=2404, help="IEC-104 port")
    ap.add_argument("--hmi", type=int, default=8080, help="HMI web port")
    ap.add_argument("--trip-action", default=DEFAULT_TRIP_ACTION,
                    help="operator instruction published in the phase-slip alarm")
    ap.add_argument("--seed", type=int, help="fix the per-boot sync angle")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log handoffs and commands")
    a = ap.parse_args()

    if a.seed is not None:
        random.seed(a.seed)
    plant = Plant(a.trip_action)

    def ticker():
        last = time.monotonic()
        while True:
            time.sleep(0.35)
            now = time.monotonic()
            plant.tick(now - last)
            last = now

    threading.Thread(target=ticker, daemon=True).start()
    threading.Thread(target=serve_iec, args=(plant, a.iec, a.verbose),
                     daemon=True).start()

    httpd = HTTPServer(("0.0.0.0", a.hmi), make_hmi(plant))
    print(f"HMI listening on http://0.0.0.0:{a.hmi}/  "
          f"(status.json, alarms)")
    print(f"sync angle this boot: {plant.angle:.1f} deg")
    print("\nsolve it with:\n"
          f"  python3 rtu_shell.py 127.0.0.1 {a.iec} --hmi {a.hmi}\n"
          "  rtu> priv ; sc 1101 close ; sc 1201 close\n"
          "  rtu> alarms")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
