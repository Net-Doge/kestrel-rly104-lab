#!/usr/bin/env python3
"""
Interactive IEC 60870-5-104 command shell for the RTU seen in backup.pcap.

    ./rtu_shell.py 154.57.164.71
    ./rtu_shell.py 127.0.0.1 2404 --ca 17

Type `help` at the prompt. Everything arriving from the RTU is printed
asynchronously as it comes in, so spontaneous data shows up between prompts.
"""

from __future__ import annotations

import argparse
import atexit
import contextlib
import json
import urllib.error
import urllib.request
import datetime as _dt
import os
import re
import readline
import shlex
import shutil
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rtu_tui  # noqa: E402

from iec104_client import (  # noqa: E402
    ASDU, COT_ACT, COT_ACTCON, COT_ACTTERM, COT_DEACT, C_SC_NA_1, IEC104Client,
    QOI_STATION, TYPE_NAMES, U_STARTDT_ACT, U_STOPDT_ACT, U_TESTFR_ACT,
    cp56time2a, _fmt_num,
)

HISTFILE = os.path.expanduser("~/.rtu_shell_history")

# Known points, recovered from backup.pcap.
POINTS = {
    2101: "M_ME_NC_1 float (11.24 in capture)",
    2102: "M_ME_NC_1 float (3.72 in capture)",
    2103: "M_ME_NC_1 float (13.5 in capture)",
    2104: "M_ME_NC_1 float (67.0 in capture)",
    1101: "C_SC_NA_1 output - HMI selected+executed ON",
    1201: "C_SC_NA_1 output - HMI selected+executed ON",
    266500: "private TypeId=104 object, payload bb322456bda87cee",
}

PRIV_TYPE = 104
PRIV_IOA = 266500
PRIV_PAYLOAD = bytes.fromhex("bb322456bda87cee")


def num(s: str) -> int:
    """Parse decimal or 0x-prefixed integer."""
    return int(s, 0)


def hexbytes(s: str) -> bytes:
    cleaned = s.replace(" ", "").replace("0x", "").replace(":", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError(
            f"{s!r} is not hex. Payloads are hex byte strings such as "
            f"bb322456bda87cee or 81. To chain commands use ';' or '&&'."
        ) from None


class Shell:
    def __init__(self, host, port, ca, oa):
        self.host = host
        self.port = port
        self.ca = ca
        self.oa = oa
        self.c: IEC104Client | None = None
        self._ask = None   # set by the TUI so prompts render in its input line
        self.transcript = None   # full log: every frame, unfolded
        self.folded_transcript = None   # optional second log, exactly as shown
        self.style = "human"     # see cmd_view: human | frames | raw
        self.hmi_port = None     # HMI web port, for `hmi` and `alarms`
        self.collapse = True     # see cmd_full: fold repeated identical lines

    def ask(self, prompt):
        """Read one line of user input, through the active UI."""
        if self._ask is not None:
            return self._ask(prompt)
        return input(prompt)

    # -- helpers ----------------------------------------------------------- #

    def need(self) -> bool:
        if self.c is None or not self.c._running:
            print("not connected - run `open`")
            return False
        return True

    def resolve_ca(self, args, flagname="--ca"):
        """Pull an optional --ca/-b override out of an arg list."""
        ca = self.ca
        out = []
        i = 0
        while i < len(args):
            if args[i] in (flagname, "-c") and i + 1 < len(args):
                ca = num(args[i + 1])
                i += 2
            elif args[i] in ("--bcast", "-b"):
                ca = 0xFFFF
                i += 1
            else:
                out.append(args[i])
                i += 1
        return ca, out

    # -- commands ---------------------------------------------------------- #

    def cmd_open(self, args):
        """open [host] [port]   - TCP connect + STARTDT.  NOT a breaker open;
                                 to open a breaker use `operate <ioa> open`."""
        if args and args[0].isdigit():
            print(f"`open` connects a TCP session; it does not open a breaker.\n"
                  f"To open the output at IOA {args[0]}:  operate {args[0]} open")
            return
        if args:
            self.host = args[0]
        if len(args) > 1:
            self.port = num(args[1])
        if self.c is not None:
            self.cmd_close([])
        self.c = IEC104Client(self.host, self.port, ca=self.ca, oa=self.oa,
                              style=self.style, collapse=self.collapse)
        self.c.log_sink = self.transcript
        try:
            self.c.connect()
        except OSError as exc:
            print(f"connect failed: {exc}")
            self.c = None
            return
        if not self.c.start_dt():
            print("warning: no STARTDT con")

    def cmd_close(self, args):
        """close                - close the TCP connection.  NOT a breaker close;
                                 to close a breaker use `operate <ioa> close`."""
        if args and args[0].isdigit():
            print(f"`close` drops the TCP session; it does not close a breaker.\n"
                  f"To close the output at IOA {args[0]}:  operate {args[0]} close")
            return
        if self.c:
            try:
                self.c.stop_dt()
                time.sleep(0.2)
            except Exception:
                pass
            self.c.close()
            self.c = None
            print("closed")

    def cmd_ca(self, args):
        """ca [addr]            - show / set default common ASDU address"""
        if args:
            self.ca = num(args[0])
            if self.c:
                self.c.ca = self.ca
        print(f"ca = {self.ca}")

    def cmd_oa(self, args):
        """oa [addr]            - show / set originator address"""
        if args:
            self.oa = num(args[0])
            if self.c:
                self.c.oa = self.oa
        print(f"oa = {self.oa}")

    def cmd_start(self, args):
        """start                - STARTDT act"""
        if self.need():
            self.c.send_u(U_STARTDT_ACT)

    def cmd_stop(self, args):
        """stop                 - STOPDT act"""
        if self.need():
            self.c.send_u(U_STOPDT_ACT)

    def cmd_test(self, args):
        """test                 - TESTFR act (keepalive)"""
        if self.need():
            self.c.send_u(U_TESTFR_ACT)

    def cmd_ack(self, args):
        """ack                  - send S-format acknowledgement"""
        if self.need():
            self.c.send_s()

    def cmd_ic(self, args):
        """ic [qoi] [--bcast]   - C_IC_NA_1 interrogation (default qoi=20)"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        qoi = num(rest[0]) if rest else QOI_STATION
        self.c.interrogation(qoi, ca=ca, wait=4.0)

    def cmd_ci(self, args):
        """ci [qcc] [--bcast]   - C_CI_NA_1 counter interrogation (default 5)"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        qcc = num(rest[0]) if rest else 5
        self.c.counter_interrogation(qcc, ca=ca, wait=4.0)

    def cmd_clock(self, args):
        """clock [when] [--bcast]
                              - C_CS_NA_1 clock sync. With no argument, sends
                                local time. `when` may be an ISO timestamp
                                (2026-06-06T20:10:22.943) or +/-SECONDS to skew
                                from now - useful if anything on the RTU is
                                time-derived and you want to move its clock"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        when = None
        if rest:
            arg = rest[0]
            try:
                if arg[0] in "+-":
                    when = _dt.datetime.now() + _dt.timedelta(seconds=float(arg))
                else:
                    when = _dt.datetime.fromisoformat(arg)
            except ValueError:
                print("could not read that time. Use an ISO timestamp like "
                      "2026-06-06T20:10:22.943, or +3600 / -86400 to skew.")
                return
            print(f"setting RTU clock to {when.isoformat(timespec='milliseconds')}")
        self.c.clock_sync(when=when, ca=ca)

    def cmd_read(self, args):
        """read <ioa>           - C_RD_NA_1 read request"""
        if not self.need():
            return
        if not args:
            print("usage: read <ioa>")
            return
        ca, rest = self.resolve_ca(args)
        self.c.read(num(rest[0]), ca=ca, wait=3.0)

    # State words accepted everywhere. In power-system usage CLOSE energises
    # (contacts closed, SCS=1) and OPEN de-energises / trips (SCS=0).
    ON_WORDS = ("on", "close", "closed", "1", "true", "energise", "energize")
    OFF_WORDS = ("off", "open", "opened", "trip", "0", "false", "deenergise")

    PULSE = {"none": 0, "short": 1, "long": 2, "persist": 3, "persistent": 3}

    def parse_state(self, word):
        """Return True for close/on, False for open/off, None if unrecognised."""
        w = word.lower()
        if w in self.ON_WORDS:
            return True
        if w in self.OFF_WORDS:
            return False
        return None

    def _control_opts(self, rest):
        """Strip shared control flags. Returns (rest, direct, qu, yes, verify)."""
        direct = False
        yes = False
        verify = False
        qu = 0
        out = []
        i = 0
        while i < len(rest):
            a = rest[i]
            if a in ("--direct", "-d"):
                direct = True
            elif a in ("--yes", "-y"):
                yes = True
            elif a in ("--verify", "-v"):
                verify = True
            elif a == "--qu" and i + 1 < len(rest):
                qu = num(rest[i + 1])
                i += 1
            elif a == "--pulse" and i + 1 < len(rest):
                key = rest[i + 1].lower()
                if key not in self.PULSE:
                    raise ValueError(f"--pulse must be one of {sorted(self.PULSE)}")
                qu = self.PULSE[key]
                i += 1
            else:
                out.append(a)
            i += 1
        return out, direct, qu, yes, verify

    def confirm(self, what, yes):
        """Ask before actuating, unless --yes or not on a terminal."""
        if yes or not sys.stdin.isatty():
            return True
        try:
            ans = self.ask(f"about to {what} on {self.host} - proceed? [y/N] ")
            if ans is None:
                raise EOFError
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if ans.strip().lower() in ("y", "yes"):
            return True
        print("aborted")
        return False

    def cmd_operate(self, args):
        """operate <ioa> open|close [--direct] [--pulse short|long|persist]
                                 [--double] [--verify] [--yes]
                              - operate an output. CLOSE energises (SCS=1),
                                OPEN de-energises / trips (SCS=0). Uses
                                select-before-operate like the captured HMI."""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        double = "--double" in rest or "--dc" in rest
        rest = [a for a in rest if a not in ("--double", "--dc")]
        rest, direct, qu, yes, verify = self._control_opts(rest)
        if len(rest) < 2:
            print("usage: operate <ioa> open|close [--direct] [--pulse P] "
                  "[--double] [--verify] [--yes]")
            return
        ioa = num(rest[0])
        state = self.parse_state(rest[1])
        if state is None:
            print(f"state must be open or close (got {rest[1]!r})")
            return
        word = "CLOSE" if state else "OPEN"
        if self.style == "human":
            mode = "execute only" if direct else "select, then execute"
            kind = "double command" if double else "single command"
            head = f"{word} output {ioa} on station {ca} - {kind}, {mode}"
        else:
            mode = "direct execute" if direct else "select-before-operate"
            kind = "C_DC_NA_1 double" if double else "C_SC_NA_1 single"
            head = f"{word} IOA {ioa} (CA={ca}, {kind} command, {mode})"
        if not self.confirm(head, yes):
            return
        print(f"--- {head} ---")
        if double:
            res = self.c.double_command(ioa, dcs=2 if state else 1, ca=ca,
                                        select=not direct)
            tid = 46
        else:
            res = self.c.single_command(ioa, on=state, ca=ca,
                                        select=not direct, qu=qu)
            tid = 45
        self._report_control(res, ioa, word, tid)
        if verify:
            self.cmd_verify([str(ioa)])
        return res

    def cmd_retry(self, args):
        """retry <ioa> open|close [--for SEC] [--every SEC] [--auth [SEC]] [--direct]
                              - attempt the same operation over and over while
                                logging the analog values at each try, until one
                                is accepted. This tells a CONDITION-based block
                                (some attempt succeeds as the values drift) apart
                                from an AUTHORISATION-based one (every attempt
                                fails identically, values irrelevant).
                                --auth re-sends the handoff every SEC seconds
                                (default 20) so a long wait cannot outlive the
                                ~30s authorisation window."""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        rest, direct, qu, _yes, _v = self._control_opts(rest)
        window, every, auth_every = 120.0, 3.0, None
        if "--auth" in rest:
            i = rest.index("--auth")
            nxt = rest[i + 1] if i + 1 < len(rest) else ""
            try:
                auth_every = float(nxt)
                del rest[i:i + 2]
            except ValueError:
                auth_every = 20.0
                del rest[i:i + 1]
        for flag, attr in (("--for", "window"), ("--every", "every")):
            if flag in rest:
                i = rest.index(flag)
                val = float(rest[i + 1])
                if attr == "window":
                    window = val
                else:
                    every = val
                del rest[i:i + 2]
        if len(rest) < 2:
            print("usage: retry <ioa> open|close [--for SEC] [--every SEC]")
            return
        ioa = num(rest[0])
        state = self.parse_state(rest[1])
        if state is None:
            print("state must be open or close")
            return
        word = "CLOSE" if state else "OPEN"
        print(f"retrying {word} on {ioa} every {every:g}s for up to {window:g}s. "
              f"Ctrl-C to stop.")
        if auth_every:
            print(f"re-sending the maintenance handoff every {auth_every:g}s so "
                  f"the authorisation window never lapses mid-wait")
        verbose, self.c.verbose = self.c.verbose, False
        rows, deadline, n = [], time.monotonic() + window, 0
        last_auth = None
        try:
            while time.monotonic() < deadline:
                n += 1
                if auth_every and (last_auth is None
                                   or time.monotonic() - last_auth >= auth_every):
                    # A handoff only counts as the first frame of a session, so
                    # re-authorising means reconnecting.
                    v = self.c.verbose
                    self.cmd_priv([])
                    if self.c is None:
                        print("lost the link while re-authorising")
                        return
                    self.c.verbose = v
                    last_auth = time.monotonic()
                snapshot = self._latest_values()
                res = self.c.single_command(ioa, on=state, ca=ca,
                                            select=not direct, qu=qu, wait=2.0)
                got = [a for a in (res or []) if a is not None]
                if not got:
                    verdict = "no reply"
                elif any(a.cot in (44, 45, 46, 47) for a in got):
                    verdict = "type/addr error"
                elif any(a.negative for a in got):
                    verdict = "refused"
                else:
                    verdict = "ACCEPTED"
                rows.append((n, snapshot, verdict))
                print(f"  try {n:<3} {snapshot:<44} {verdict}")
                if verdict == "ACCEPTED":
                    print(f"\n[ok] accepted on attempt {n} with {snapshot}")
                    break
                if verdict == "type/addr error":
                    print("\nstopping: this is an addressing/type problem, not a "
                          "condition that will pass with time")
                    break
                time.sleep(every)
        except KeyboardInterrupt:
            print()
        finally:
            self.c.verbose = verbose
        verdicts = {v for _, _, v in rows}
        snapshots = {snap for _, snap, _ in rows}
        print()
        if "ACCEPTED" in verdicts:
            print("CONDITIONAL: the block depends on plant state, not on you.")
        elif verdicts == {"refused"} and len(rows) > 1:
            if len(snapshots) == 1:
                print(f"all {len(rows)} attempts refused, and the measurements "
                      f"never changed once ({snapshots.pop()}). Waiting cannot "
                      f"help: nothing is drifting, so no attempt will ever catch "
                      f"a better moment. The block is a precondition you have to "
                      f"set first, not a value to wait out.")
            else:
                print(f"all {len(rows)} attempts refused across "
                      f"{len(snapshots)} different measurement sets. That points "
                      f"away from a simple threshold on these values.")
        self.c.drain(1.0)

    def _latest_values(self):
        """Most recent measurement line, compactly, for correlating attempts."""
        for a in reversed(self.c.received):
            if a.type_id in (9, 11, 13, 36) and a.objects:
                return "  ".join(f"{ioa}={self._show_value(a, e)}"
                                 for ioa, e in a.objects)
        return "(no measurements seen)"

    def cmd_trip(self, args):
        """trip <ioa> [flags]   - shorthand for `operate <ioa> open`"""
        self.cmd_operate([args[0], "open"] + list(args[1:]) if args else [])

    def _report_control(self, res, ioa, word, tid):
        """Summarise the actcon / actterm outcome of a control sequence."""
        human = self.style == "human"
        target = f"output {ioa}" if human else f"IOA {ioa}"
        got = [a for a in (res or []) if a is not None]
        if not got:
            print(f"[!] {word} {target}: no answer at all - wrong station "
                  f"address, link stopped, or the point cannot be commanded")
            return
        # A specific cause outranks the bare negative confirmation: this RTU
        # sends NEG first and the actual reason (COT 44 etc.) in a later frame.
        for a in got:
            if a.cot in (44, 45, 46, 47):
                from iec104_client import COT_NAMES, _COT_ERROR
                reason = (_COT_ERROR.get(a.cot) if human
                          else COT_NAMES.get(a.cot, a.cot))
                print(f"[!] {word} {target}: {reason}")
                return
        if any(a.negative for a in got):
            print(f"[!] {word} {target}: the RTU REFUSED it - an interlock is "
                  f"active, the point was not selected first, or the qualifier "
                  f"is not accepted")
            return
        cots = {a.cot for a in got}
        if COT_ACTTERM in cots:
            print(f"[ok] {word} {target}: the RTU confirmed it and reported the "
                  f"operation finished")
        elif COT_ACTCON in cots:
            print(f"[~] {word} {target}: the RTU accepted it but never reported "
                  f"completion - it may still be running")

    def cmd_sc(self, args):
        """sc <ioa> on|off|open|close [--direct] [--qu N] [--pulse P]
                              - C_SC_NA_1 single command, low-level form of
                                `operate` (no confirm prompt, no summary)"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        rest, direct, qu, _yes, _v = self._control_opts(rest)
        if len(rest) < 2:
            print("usage: sc <ioa> on|off|open|close [--direct] [--qu N]")
            return
        state = self.parse_state(rest[1])
        if state is None:
            print("state must be on|off|open|close")
            return
        self.c.single_command(num(rest[0]), on=state, ca=ca,
                              select=not direct, qu=qu)

    def cmd_dc(self, args):
        """dc <ioa> on|off|open|close [--direct]
                              - C_DC_NA_1 double command (DCS 2=close, 1=open)"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        rest, direct, _qu, _yes, _v = self._control_opts(rest)
        if len(rest) < 2:
            print("usage: dc <ioa> on|off|open|close [--direct]")
            return
        state = self.parse_state(rest[1])
        if state is None:
            print("state must be on|off|open|close")
            return
        self.c.double_command(num(rest[0]), dcs=2 if state else 1,
                              ca=ca, select=not direct)

    def cmd_verify(self, args):
        """verify [ioa ...]     - re-interrogate and print current values, so you
                                 can confirm an operation actually took effect"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        wanted = {num(a) for a in rest} if rest else None
        data = self.c.interrogation(QOI_STATION, ca=0xFFFF, wait=4.0)
        rows = []
        for a in data:
            if a.type_id not in self.MONITOR_TYPES:
                continue          # skip the interrogation's own confirmations
            for ioa, elem in a.objects:
                if wanted is None or ioa in wanted:
                    rows.append((ioa, self._kind(a.type_id),
                                 self._show_value(a, elem)))
        if not rows:
            print("no matching objects came back. The capture only ever showed "
                  "M_ME_NC_1 floats at 2101-2104; this RTU may not report a "
                  "status point for 1101/1201 in a station interrogation.")
            return
        print(f"{'POINT':<8} {'KIND':<10} VALUE")
        for ioa, tname, val in sorted(rows):
            print(f"{ioa:<8} {tname:<10} {val}")

    MONITOR_TYPES = (1, 3, 9, 11, 13, 30, 31, 34, 35, 36)

    FLAG_RE = re.compile(r"(?:HTB|flag)\{[^}]{4,120}\}")

    def _hmi_get(self, path):
        """Fetch a JSON document from the HMI. Returns (data, raw_text)."""
        url = f"http://{self.host}:{self.hmi_port}{path}"
        with urllib.request.urlopen(url, timeout=8) as r:
            raw = r.read().decode("utf-8", "replace")
        return json.loads(raw), raw

    def _hmi_probe(self, port, timeout=1.5):
        """Is there a Kestrel HMI on this port? Returns its status dict."""
        try:
            url = f"http://{self.host}:{port}/status.json"
            with urllib.request.urlopen(url, timeout=timeout) as r:
                st = json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            return None
        return st if "Kestrel" in str(st.get("plc", {})) else None

    def _hmi_candidates(self, first, last, workers=48):
        """All Kestrel HMIs in a port range, found in parallel.

        The lab proxy completes a TCP handshake on every port, so a plain scan is
        useless and a serial scan is far too slow - hence threads with a short
        timeout.
        """
        import concurrent.futures
        ports = [p for p in range(first, last + 1) if p != self.port]
        found = []
        print(f"scanning {first}-{last} for Kestrel HMIs ...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(self._hmi_probe, p): p for p in ports}
            for fut in concurrent.futures.as_completed(futures):
                st = fut.result()
                if st is not None:
                    port = futures[fut]
                    found.append(port)
                    print(f"  port {port}: Kestrel HMI "
                          f"(scan={st.get('scan')}, "
                          f"auth={st.get('authorized')})")
        return sorted(found)

    def _hmi_find(self, first=None, last=None):
        """Locate the HMI paired with THIS RTU.

        Several players' instances answer on nearby ports and a fresh one looks
        much like any other, so values cannot identify it. Instead act: send the
        maintenance handoff over this IEC-104 connection, then see whose
        authorisation state changed. That is causal, so it cannot pick wrong.
        """
        if self.c is None:
            print("connect first - the match is made by acting on this link")
            return None
        if first is None:
            first, last = 30000, 32800
        cands = self._hmi_candidates(first, last)
        if not cands:
            print(f"no Kestrel HMI answered in {first}-{last}. Try a wider "
                  f"range: hmi scan <first> <last>")
            return None
        if len(cands) == 1:
            self.hmi_port = cands[0]
            print(f"only one candidate - paired HMI is {self.hmi_port}")
            return self.hmi_port

        print(f"\n{len(cands)} Kestrel HMIs answered - other players' "
              f"instances are in there too.")
        print("sending a maintenance handoff on this link to see which one "
              "reacts ...")
        before = {}
        for port in cands:
            st = self._hmi_probe(port, timeout=3)
            if st:
                before[port] = (st.get("authorized"), st.get("last_handoff"),
                                st.get("authorized_ttl"))
        self.c.send_i(ASDU.build(PRIV_TYPE, COT_ACT, self.ca, PRIV_IOA,
                                 PRIV_PAYLOAD, oa=self.oa))
        self.c.drain(1.5)
        hits = []
        for port in cands:
            st = self._hmi_probe(port, timeout=3)
            if not st:
                continue
            now = (st.get("authorized"), st.get("last_handoff"),
                   st.get("authorized_ttl"))
            was = before.get(port)
            if st.get("authorized") and (was is None or not was[0]
                                         or now[1] != was[1]):
                hits.append(port)
            elif was and now[:2] != was[:2]:
                hits.append(port)
        if len(hits) == 1:
            self.hmi_port = hits[0]
            print(f"paired HMI is {self.hmi_port} - it is the one whose "
                  f"authorisation flipped")
            return self.hmi_port
        if hits:
            print(f"more than one reacted ({hits}). Someone else authorised at "
                  f"the same moment - run `hmi` again, or set it directly with "
                  f"`hmi <port>`.")
        else:
            print(f"none reacted. Candidates were {cands}. If the handoff is "
                  f"being refused none will flip - check `hmi <port>` manually.")
        return None

    def cmd_hmi(self, args):
        """hmi [port | scan <first> <last>]
                              - read the HMI's status.json: plant state, auth
                                window and the RTU's own reason for the last
                                command. With no argument, finds the HMI paired
                                with this RTU by sending a handoff and seeing
                                which one reacts. `hmi scan 30000 31000` limits
                                the port range"""
        if args and args[0].lower() == "verify":
            return self._hmi_verify()
        if args and args[0].lower() == "scan":
            first = num(args[1]) if len(args) > 1 else 30000
            last = num(args[2]) if len(args) > 2 else 32800
            if self._hmi_find(first, last) is None:
                return
        elif args:
            self.hmi_port = num(args[0])
        if self.hmi_port is None and self._hmi_find() is None:
            return
        try:
            st, raw = self._hmi_get("/status.json")
        except Exception as exc:
            print(f"cannot read the HMI on port {self.hmi_port}: {exc}")
            return
        p = st.get("process", {})
        print(f"HMI {self.host}:{self.hmi_port}   scan={st.get('scan')}")
        print(f"  authorised    {st.get('authorized')}  "
              f"ttl={round(st.get('authorized_ttl') or 0, 1)}s")
        print(f"  last handoff  {st.get('last_handoff')!r}")
        print(f"  last command  {st.get('last_command')!r}")
        print("  plant:")
        for k, v in p.items():
            print(f"    {k:<26} {v}")
        ev = st.get("events") or []
        if ev:
            print("  recent events:")
            for e in ev[-5:]:
                print(f"    {e}")
        flag = self.FLAG_RE.search(raw)
        if flag:
            print(f"\n  *** {flag.group(0)} ***")

    def _hmi_verify(self):
        """Prove the configured HMI really belongs to THIS RTU.

        Several instances share the host, so a wrong port shows someone else's
        plant and quietly misleads you. Send a handoff on this link and check the
        HMI reacts - if it does not, the port is not yours.
        """
        if self.hmi_port is None:
            print("no HMI port set - `hmi <port>` first")
            return None
        if not self.need():
            return None
        try:
            before, _ = self._hmi_get("/status.json")
        except Exception as exc:
            print(f"cannot read the HMI on {self.hmi_port}: {exc}")
            return None
        scan_before = before.get("scan")
        # Causal test: send the handoff (cmd_priv reconnects, so it is accepted
        # every time) and see whose authorisation opens. Only our own instance
        # can react to traffic on our own link.
        print(f"sending a handoff and watching port {self.hmi_port} ...")
        self.cmd_priv([])
        if self.c is None:
            return None
        try:
            after, _ = self._hmi_get("/status.json")
        except Exception as exc:
            print(f"cannot re-read the HMI: {exc}")
            return None
        if after.get("authorized"):
            print(f"PAIRED: port {self.hmi_port} authorised in response to our "
                  f"handoff (ttl={round(after.get('authorized_ttl') or 0, 1)}s)")
            print("  the window is open - send commands NOW")
            return self.hmi_port
        if after.get("last_handoff") != before.get("last_handoff"):
            print(f"PAIRED: port {self.hmi_port} reacted "
                  f"({after.get('last_handoff')!r}) but did not authorise")
            return self.hmi_port
        print(f"NOT PAIRED: port {self.hmi_port} did not react "
              f"(scan {scan_before} -> {after.get('scan')}, still "
              f"{after.get('last_handoff')!r}). That is a different instance - "
              f"take the web port from the HTB panel.")
        return None

    def cmd_alarms(self, args):
        """alarms               - read the HMI's alarm table. The phase-slip trip
                                 alarm is where the token appears - status.json
                                 never carries it"""
        if args:
            self.hmi_port = num(args[0])
        if self.hmi_port is None and self._hmi_find() is None:
            return
        try:
            data, raw = self._hmi_get("/alarms")
        except Exception as exc:
            print(f"cannot read the HMI on port {self.hmi_port}: {exc}")
            return
        alarms = data.get("alarms", [])
        if not alarms:
            print("no alarms active")
        for a in alarms:
            print(f"  {a.get('severity','?'):<5} {a.get('id','?'):<20} "
                  f"{a.get('message','')}")
        flag = self.FLAG_RE.search(raw)
        if flag:
            print(f"\n*** {flag.group(0)} ***")

    def cmd_trend(self, args):
        """trend [seconds]      - watch the analog/status points for a while and
                                 table first/last/min/max/delta per IOA. Use it
                                 to work out which IOA is which quantity, and
                                 which ones move on their own"""
        if not self.need():
            return
        secs = float(args[0]) if args else 20.0
        start = len(self.c.received)
        print(f"observing {secs:.0f}s ... (Ctrl-C to stop early)")
        try:
            self.c.drain(secs)
        except KeyboardInterrupt:
            print()
        seen = {}
        order = []
        for a in self.c.received[start:]:
            if a.type_id not in self.MONITOR_TYPES:
                continue
            for ioa, elem in a.objects:
                val = self._numeric(a, elem)
                if val is None:
                    continue
                if ioa not in seen:
                    seen[ioa] = {"type": a.type_id, "vals": []}
                    order.append(ioa)
                seen[ioa]["vals"].append(val)
        if not seen:
            print("nothing arrived. The RTU may not push data unprompted - try "
                  "`ic --bcast` first, or `priv` to send the capture's TypeId=104 "
                  "ASDU, which is what made it start reporting in backup.pcap.")
            return
        print(f"{'IOA':<8}{'TYPE':<12}{'N':>4}{'FIRST':>11}{'LAST':>11}"
              f"{'MIN':>11}{'MAX':>11}{'DELTA':>11}  MOVING")
        for ioa in sorted(order):
            d = seen[ioa]
            v = d["vals"]
            delta = v[-1] - v[0]
            moving = "yes" if (max(v) - min(v)) > 1e-9 else "-"
            print(f"{ioa:<8}{TYPE_NAMES.get(d['type'], d['type']):<12}"
                  f"{len(v):>4}{v[0]:>11.4g}{v[-1]:>11.4g}"
                  f"{min(v):>11.4g}{max(v):>11.4g}{delta:>+11.4g}  {moving}")
        print("\nA value that climbs on its own is a process variable. A value "
              "that only changes after you write it is a setpoint.\n"
              "Try `setpoint <ioa> <value>` on a candidate: a positive actcon "
              "means it is writable, COT=44/45/47 or a NEG actcon means it is not.")

    @staticmethod
    def _numeric(asdu, elem):
        """Best-effort float for trending, or None."""
        try:
            t = asdu.type_id
            if t in (13, 36):
                return struct.unpack("<f", elem[0:4])[0]
            if t in (9, 11, 34, 35):
                return float(struct.unpack("<h", elem[0:2])[0])
            if t in (1, 30):
                return float(elem[0] & 1)
            if t in (3, 31):
                return float(elem[0] & 3)
        except Exception:
            return None
        return None

    # (TypeId, label, payload) using SELECT-only encodings where the type has an
    # S/E bit, so a probe reserves a point and reports whether it is permitted
    # without ever executing. COT 44 = type not implemented, 47 = no such
    # object, 45 = cause rejected, actcon = the type IS available.
    PROBE_TYPES = [
        (45, "C_SC_NA_1 single cmd", b"\x81"),
        (46, "C_DC_NA_1 double cmd", b"\x82"),
        (47, "C_RC_NA_1 reg step", b"\x81"),
        (48, "C_SE_NA_1 setpt norm", b"\x00\x00\x80"),
        (49, "C_SE_NB_1 setpt scal", b"\x00\x00\x80"),
        (50, "C_SE_NC_1 setpt float", b"\x00\x00\x00\x00\x80"),
        (58, "C_SC_TA_1 sc + time", b"\x81"),
        (59, "C_DC_TA_1 dc + time", b"\x82"),
        (63, "C_SE_TC_1 setpt + time", b"\x00\x00\x00\x00\x80"),
    ]
    PROBE_PARAMS = [
        (110, "P_ME_NA_1 param norm", b"\x00\x00\x01"),
        (111, "P_ME_NB_1 param scal", b"\x00\x00\x01"),
        (112, "P_ME_NC_1 param float", b"\x00\x00\x00\x00\x01"),
        (113, "P_AC_NA_1 param act", b"\x01"),
    ]

    def cmd_probe(self, args):
        """probe <ioa> [--params] [--all]
                              - find out which control TypeIds this RTU accepts
                                at an IOA. Uses SELECT-only encodings, so nothing
                                is executed. --params also probes parameter
                                loading (110-113), which has no select and does
                                write, so it is off by default"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        params = "--params" in rest or "--all" in rest
        rest = [a for a in rest if a not in ("--params", "--all")]
        if not rest:
            print("usage: probe <ioa> [--params]")
            return
        ioa = num(rest[0])
        table = list(self.PROBE_TYPES) + (list(self.PROBE_PARAMS) if params else [])
        print(f"probing IOA {ioa} on CA {ca} with select-only commands"
              + (" plus parameter writes" if params else "") + "\n")
        verbose, self.c.verbose = self.c.verbose, False
        results = []
        try:
            for tid, label, payload in table:
                self.c.send_i(ASDU.build(tid, COT_ACT, ca, ioa, payload,
                                         oa=self.oa))
                # This RTU answers a rejected command with a NEG actcon AND a
                # second frame carrying the real reason (COT 44). Collect every
                # reply, then let the specific COT outrank the bare NEG.
                replies = []
                first = self.c.wait_for(tid, ioa=ioa, timeout=2.0)
                while first is not None:
                    replies.append(first)
                    first = self.c.wait_for(tid, ioa=ioa, timeout=0.4)
                cots = {r.cot for r in replies}
                if not replies:
                    verdict, note = "no reply", "type ignored, or no permission"
                elif 44 in cots:
                    verdict, note = "COT 44", "TypeId not implemented here"
                elif 47 in cots:
                    verdict, note = "COT 47", "no such object at this IOA"
                elif 46 in cots:
                    verdict, note = "COT 46", "wrong CA"
                elif 45 in cots:
                    verdict, note = "COT 45", "cause of transmission rejected"
                elif any(r.negative for r in replies):
                    verdict, note = "NEG actcon", "supported but refused/interlocked"
                else:
                    verdict, note = "ACCEPTED", "type is available - usable"
                results.append((tid, label, verdict, note))
        finally:
            self.c.verbose = verbose
        print(f"{'TYPE':<6}{'ASDU':<24}{'RESULT':<12}NOTE")
        for tid, label, verdict, note in results:
            print(f"{tid:<6}{label:<24}{verdict:<12}{note}")
        usable = [t for t, _, v, _ in results if v in ("ACCEPTED", "NEG actcon")]
        print()
        if usable:
            print(f"usable TypeIds here: {usable}")
        else:
            print("nothing accepted. If every control type returns COT 44, this "
                  "RTU exposes no standard control at this IOA - the private "
                  "TypeId 104 object (IOA 266500) is then the only write path "
                  "the capture shows. Try `priv` first on this same connection, "
                  "then re-probe.")
        self.c.drain(1.0)

    KINDS = {1: "on/off", 3: "on/off/bad", 9: "number", 11: "number",
             13: "number", 15: "counter", 21: "number", 30: "on/off",
             31: "on/off/bad", 34: "number", 35: "number", 36: "number",
             37: "counter", 45: "output", 46: "output"}

    def _kind(self, type_id):
        """Plain word for a TypeId, or the acronym in frames/raw view."""
        if self.style != "human":
            return TYPE_NAMES.get(type_id, str(type_id))
        return self.KINDS.get(type_id, TYPE_NAMES.get(type_id, str(type_id)))

    def _show_value(self, asdu, elem):
        """Value for a table cell: bare number in human view, with the quality
        flags appended only when they are actually set."""
        if self.style != "human":
            return asdu.value_str(elem)
        v = self._numeric(asdu, elem)
        if v is None:
            return asdu.value_str(elem)
        if asdu.type_id in (1, 30):
            text = "ON" if v else "OFF"
        elif asdu.type_id in (3, 31):
            text = {0: "indeterminate", 1: "OFF", 2: "ON", 3: "faulty"}[int(v)]
        else:
            text = _fmt_num(v)
        flags = []
        try:
            q = elem[4] if asdu.type_id in (13, 36) else (
                elem[2] if asdu.type_id in (9, 11) else elem[0])
            for bit, label in ((0x01, "OVERFLOW"), (0x10, "BLOCKED"),
                               (0x20, "SUBSTITUTED"), (0x40, "STALE"),
                               (0x80, "INVALID")):
                if q & bit:
                    flags.append(label)
        except Exception:
            pass
        return text + (("   [" + ", ".join(flags) + "]") if flags else "")

    def cmd_csweep(self, args):
        """csweep <first> <last> [--step N]
                              - find COMMANDABLE points fast: one select-only
                                C_SC_NA_1 per IOA (S/E=1, never executed), so
                                nothing actuates. A positive confirmation means
                                the point exists and takes commands; COT 47 means
                                there is no such output"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        step = 1
        if "--step" in rest:
            i = rest.index("--step")
            step = num(rest[i + 1])
            del rest[i:i + 2]
        if len(rest) < 2:
            print("usage: csweep <first> <last> [--step N]")
            return
        first, last = num(rest[0]), num(rest[1])
        if last < first or (last - first) // max(step, 1) > 2000:
            print("refusing: bad or oversized range")
            return
        verbose, self.c.verbose = self.c.verbose, False
        found = []
        try:
            for ioa in range(first, last + 1, step):
                self.c.send_i(ASDU.build(45, COT_ACT, ca, ioa, b"\x80",
                                         oa=self.oa))
                reply = self.c.wait_for(45, ioa=ioa, timeout=1.0)
                extra = []
                while reply is not None:
                    extra.append(reply)
                    reply = self.c.wait_for(45, ioa=ioa, timeout=0.25)
                if not extra:
                    continue
                cots = {r.cot for r in extra}
                if 47 in cots or 44 in cots:
                    continue
                verdict = ("refused" if any(r.negative for r in extra)
                           else "COMMANDABLE")
                found.append((ioa, verdict))
                print(f"  {ioa:<8} {verdict}")
        except KeyboardInterrupt:
            print()
        finally:
            self.c.verbose = verbose
        print(f"\n{len(found)} commandable point(s) in {first}..{last}")
        if not found:
            print("none. Note this needs an active authorisation - run `priv` "
                  "first, and remember the window is only ~30s.")
        self.c.drain(0.5)

    def cmd_sweep(self, args):
        """sweep <first> <last> [--step N]
                              - C_RD_NA_1 across an IOA range to find live points
                                (read-only; does not operate anything)"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        rest, _d, _q, _y, _v = self._control_opts(rest)
        step = 1
        if "--step" in rest:
            i = rest.index("--step")
            step = num(rest[i + 1])
            del rest[i:i + 2]
        if len(rest) < 2:
            print("usage: sweep <first> <last> [--step N]")
            return
        first, last = num(rest[0]), num(rest[1])
        if last < first or (last - first) // max(step, 1) > 4096:
            print("refusing: bad or oversized range")
            return
        before = len(self.c.received)
        for ioa in range(first, last + 1, step):
            self.c.send_i(ASDU.build(102, 5, ca, ioa, b"", oa=self.oa))
            time.sleep(0.02)
        self.c.drain(3.0)
        print(f"sweep {first}..{last} step {step}: "
              f"{len(self.c.received) - before} ASDUs came back "
              f"(see `log` for detail)")

    def cmd_sp(self, args):
        """sp <ioa> <float>     - C_SE_NC_1 short-float setpoint"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        if len(rest) < 2:
            print("usage: sp <ioa> <value>")
            return
        self.c.setpoint_float(num(rest[0]), float(rest[1]), ca=ca)

    QPM = {"threshold": 1, "smoothing": 2, "low": 3, "lowlimit": 3,
           "high": 4, "highlimit": 4}

    def cmd_param(self, args):
        """param <ioa> <value> [--kind threshold|smoothing|low|high]
                              - P_ME_NC_1 (112): write a PARAMETER of a measured
                                value, i.e. a protection threshold or limit,
                                rather than the value itself. Use this when a
                                measurement will not accept a setpoint but the
                                limit it is compared against might"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        kind = "threshold"
        if "--kind" in rest:
            i = rest.index("--kind")
            kind = rest[i + 1].lower()
            del rest[i:i + 2]
        if kind not in self.QPM:
            print(f"--kind must be one of {sorted(set(self.QPM))}")
            return
        if len(rest) < 2:
            print("usage: param <ioa> <value> [--kind threshold|low|high]")
            return
        ioa, value = num(rest[0]), float(rest[1])
        payload = struct.pack("<f", value) + bytes([self.QPM[kind]])
        self.c.send_i(ASDU.build(112, COT_ACT, ca, ioa, payload, oa=self.oa))
        con = self.c.wait_for(112, COT_ACTCON, ioa=ioa, timeout=3.0)
        if con is None:
            print(f"[!] no actcon for parameter write at IOA {ioa} "
                  f"- RTU may not implement P_ME_NC_1 (112)")
        elif con.negative:
            print(f"[!] parameter write REFUSED at IOA {ioa}")
        else:
            print(f"[ok] parameter {kind} = {value:g} accepted at IOA {ioa}")
        self.c.drain(1.0)

    def cmd_raw(self, args):
        """raw <typeid> <ioa> [hexpayload] [--cot N] [--sq N]
                              - send an arbitrary ASDU"""
        if not self.need():
            return
        ca, rest = self.resolve_ca(args)
        cot = COT_ACT
        if "--cot" in rest:
            i = rest.index("--cot")
            cot = num(rest[i + 1])
            del rest[i:i + 2]
        count = None
        sq = False
        if "--sq" in rest:
            i = rest.index("--sq")
            count = num(rest[i + 1])
            sq = True
            del rest[i:i + 2]
        if len(rest) < 2:
            print("usage: raw <typeid> <ioa> [hexpayload] [--cot N] [--sq N]")
            return
        payload = hexbytes(rest[2]) if len(rest) > 2 else b""
        self.c.send_i(ASDU.build(num(rest[0]), cot, ca, num(rest[1]), payload,
                                 sq=sq, count=count, oa=self.oa))
        self.c.drain(3.0)

    def cmd_apdu(self, args):
        """apdu <hex>           - send fully hand-built APDU bytes (68 ...)"""
        if not self.need():
            return
        if not args:
            print("usage: apdu 680407000000")
            return
        b = hexbytes(args[0])
        print(f"[->] raw apdu {b.hex()}")
        self.c._send(b)
        self.c.drain(2.0)

    def cmd_priv(self, args):
        """priv [hexpayload] [--stay]
                              - send the maintenance handoff from backup.pcap
                                (TypeId 104, IOA 266500, bb322456bda87cee).

                                The RTU only accepts it as the FIRST I-frame of a
                                fresh connection - sent later in a session it is
                                always answered 'bad proof rejected'. So this
                                reconnects first whenever anything has already
                                been sent. --stay suppresses that."""
        if not self.need():
            return
        stay = "--stay" in args
        args = [a for a in args if a != "--stay"]
        payload = hexbytes(args[0]) if args else PRIV_PAYLOAD
        if self.c.i_sent and not stay:
            print("reconnecting - the handoff is only accepted as the first "
                  "frame of a session")
            host, port = self.host, self.port
            self.c.close()
            self.c = IEC104Client(host, port, ca=self.ca, oa=self.oa,
                                  style=self.style, collapse=self.collapse)
            self.c.log_sink = self.transcript
            try:
                self.c.connect()
            except OSError as exc:
                print(f"reconnect failed: {exc}")
                self.c = None
                return
            if not self.c.start_dt():
                print("warning: no STARTDT con after reconnect")
        self.c.send_i(ASDU.build(PRIV_TYPE, COT_ACT, self.ca, PRIV_IOA,
                                 payload, oa=self.oa))
        self.c.drain(1.5)
        if self.hmi_port:
            try:
                st, _ = self._hmi_get("/status.json")
                ok = st.get("authorized")
                print(f"  handoff: {st.get('last_handoff')!r}  "
                      f"authorised={ok} ttl={round(st.get('authorized_ttl') or 0, 1)}s")
                if ok:
                    print("  window is open - send commands NOW")
            except Exception:
                pass

    def cmd_mon(self, args):
        """mon [seconds]        - listen for spontaneous data (default 15)"""
        if not self.need():
            return
        secs = float(args[0]) if args else 15.0
        print(f"listening {secs}s (Ctrl-C to stop early)")
        try:
            self.c.drain(secs)
        except KeyboardInterrupt:
            print()

    def cmd_replay(self, args):
        """replay               - full captured HMI sequence: ic, clock, 1101, 1201 ON"""
        if not self.need():
            return
        self.c.interrogation(QOI_STATION, ca=0xFFFF, wait=4.0)
        self.c.clock_sync(ca=0xFFFF)
        for ioa in (1101, 1201):
            self.c.single_command(ioa, on=True, ca=self.ca, select=True)
        self.c.drain(1.0)

    def cmd_points(self, args):
        """points               - list IOAs recovered from backup.pcap"""
        for ioa, desc in sorted(POINTS.items()):
            print(f"  {ioa:<8} {desc}")

    def cmd_scroll(self, args):
        """scroll up|down|top|end [lines]
                              - scroll the output pane from the keyboard, for
                                when PgUp/PgDn or the wheel are unavailable"""
        if getattr(self, "_tui", None) is None:
            print("scrolling only applies to the split-screen UI "
                  "(use your terminal's own scrollback in --plain mode)")
            return
        what = (args[0].lower() if args else "up")
        if what not in ("up", "down", "top", "end", "live", "bottom"):
            print("usage: scroll up|down|top|end [lines]")
            return
        n = num(args[1]) if len(args) > 1 else None
        self._tui.scroll_by(what, n)

    def cmd_pause(self, args):
        """pause [on|off]       - freeze the output pane so a mouse selection
                                 survives incoming frames. F2 or Ctrl-O toggles
                                 it; running any command resumes"""
        if getattr(self, "_tui", None) is None:
            print("pausing only applies to the split-screen UI")
            return
        on = True if not args else args[0].lower() in ("on", "1", "true", "yes")
        self._tui.set_freeze(on)

    def cmd_mouse(self, args):
        """mouse on|off         - wheel scrolling. Turn it off to use the
                                 terminal's own text selection for copying"""
        if getattr(self, "_tui", None) is None:
            print("no split-screen UI active")
            return
        if not args:
            print(f"mouse capture {'on' if self._tui.mouse_on else 'off'}")
            return
        self._tui.set_mouse(args[0].lower() in ("on", "1", "true", "yes"))

    def _transcript(self, n=None):
        """Session text, newest last. Falls back to decoded ASDUs in plain mode."""
        tui = getattr(self, "_tui", None)
        if tui is not None:
            lines = list(tui.lines)
        elif self.c is not None:
            lines = [str(a) for a in self.c.received]
        else:
            lines = []
        return lines[-n:] if n else lines

    def cmd_logfile(self, args):
        """logfile [path|off]   - start, show or stop logging every line to a
                                 file mid-session (same thing as --log at
                                 launch). Appends if the file exists"""
        if not args:
            print(f"logging to {self.transcript.path}" if self.transcript
                  else "not logging - `logfile <path>` to start")
            return
        if args[0].lower() in ("off", "stop", "none"):
            if self.transcript is None:
                print("not logging")
                return
            path = self.transcript.path
            self.transcript.close()
            self.transcript = None
            if self.c is not None:
                self.c.log_sink = None
            if getattr(self, "_tui", None) is not None:
                self._tui.log = None
            print(f"stopped logging to {path}")
            return
        if self.transcript is not None:
            self.transcript.close()
        try:
            self.transcript = Transcript(args[0], append=True,
                                         timestamps="--time" in args)
        except OSError as exc:
            self.transcript = None
            print(f"could not open {args[0]}: {exc}")
            return
        if self.c is not None:
            self.c.log_sink = self.transcript
        if getattr(self, "_tui", None) is not None:
            self._tui.log = self.transcript
        print(f"logging to {self.transcript.path} (every frame, unfolded)")

    def cmd_save(self, args):
        """save [file] [n]      - write the session transcript to a file, the
                                 reliable way to get text out of the UI
                                 (default ./rtu_session.log)"""
        path = args[0] if args else "rtu_session.log"
        n = num(args[1]) if len(args) > 1 else None
        lines = self._transcript(n)
        if not lines:
            print("nothing to save yet")
            return
        try:
            with open(path, "w") as fh:
                fh.write("\n".join(lines) + "\n")
        except OSError as exc:
            print(f"could not write {path}: {exc}")
            return
        print(f"wrote {len(lines)} lines to {os.path.abspath(path)}")

    def cmd_copy(self, args):
        """copy [n]             - copy the last n lines (default 40) to the
                                 system clipboard via xclip/wl-copy/pbcopy"""
        n = num(args[0]) if args else 40
        lines = self._transcript(n)
        if not lines:
            print("nothing to copy yet")
            return
        text = "\n".join(lines) + "\n"
        for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"],
                    ["xsel", "--clipboard", "--input"], ["pbcopy"]):
            if shutil.which(cmd[0]) is None:
                continue
            try:
                p = subprocess.run(cmd, input=text.encode(), timeout=5)
            except (OSError, subprocess.SubprocessError) as exc:
                print(f"{cmd[0]} failed: {exc}")
                continue
            if p.returncode == 0:
                print(f"copied {len(lines)} lines to the clipboard via {cmd[0]}")
                return
        print("no clipboard tool found (tried wl-copy, xclip, xsel, pbcopy).\n"
              "Use `save <file>` instead, or run with --plain to select text "
              "in the terminal.")

    def cmd_log(self, args):
        """log [n]              - reprint the last n ASDUs received (default 20)"""
        if not self.need():
            return
        n = num(args[0]) if args else 20
        for a in self.c.received[-n:]:
            print(f"  {a}")

    def cmd_state(self, args):
        """state                - show link state"""
        if self.c is None:
            print("not connected")
            return
        print(f"  {self.host}:{self.port}  ca={self.ca} oa={self.oa}")
        print(f"  V(S)={self.c.tx} V(R)={self.c.rx} peer-acked={self.c.acked} "
              f"unacked-rx={self.c.unacked_rx}")
        print(f"  asdus received={len(self.c.received)}")

    def cmd_types(self, args):
        """types [filter]       - list known TypeId numbers"""
        f = args[0].lower() if args else ""
        for tid, name in sorted(TYPE_NAMES.items()):
            if not f or f in name.lower() or f == str(tid):
                print(f"  {tid:<4} {name}")

    def cmd_view(self, args):
        """view [human|frames|raw]
                              - how traffic is shown. human (default) is plain
                                language with link housekeeping hidden and
                                repeated frames collapsed; frames is one line
                                per APDU with sequence numbers; raw adds hex"""
        if not args:
            print(f"view = {self.style}")
            return
        style = args[0].lower()
        if style not in ("human", "frames", "raw"):
            print("usage: view human|frames|raw")
            return
        self.style = style
        if self.c is not None:
            self.c.flush_repeats()
            self.c.style = style
        print(f"view = {style}")

    def cmd_full(self, args):
        """full [on|off]        - on: print every frame, including the identical
                                 repeats of periodic data. off (default): fold
                                 runs of identical lines into "... same N more
                                 times". Independent of `view`"""
        if not args:
            print(f"full = {'off' if self.collapse else 'on'}"
                  f"  (repeat folding is {'on' if self.collapse else 'off'})")
            return
        on = args[0].lower() in ("on", "1", "true", "yes", "full")
        self.collapse = not on
        if self.c is not None:
            self.c.flush_repeats()
            self.c.collapse = self.collapse
        print(f"full = {'on - every frame printed' if on else 'off - repeats folded'}")

    def cmd_quiet(self, args):
        """quiet on|off         - toggle frame logging"""
        if self.need():
            self.c.verbose = not (args and args[0].lower() in ("on", "1", "true"))
            print(f"verbose = {self.c.verbose}")

    HELP_GROUPS = [
        ("control", "OPERATE OUTPUTS - these actuate real plant equipment",
         ["operate", "trip", "retry", "verify", "sc", "dc", "sp", "param"]),
        ("read", "ask the RTU for data - safe, changes nothing",
         ["ic", "ci", "read", "sweep", "csweep", "trend", "probe", "mon",
          "log", "points", "types", "hmi", "alarms"]),
        ("link", "TCP session and protocol control",
         ["open", "close", "start", "stop", "test", "ack", "ca", "oa",
          "quiet", "state", "clock"]),
        ("raw", "hand-crafted frames",
         ["raw", "apdu", "priv", "replay"]),
        ("shell", "",
         ["help", "view", "full", "scroll", "pause", "mouse", "save", "copy",
          "logfile", "quit"]),
    ]

    HELP_TOPICS = {
        "control": """
OPENING AND CLOSING OUTPUTS
===========================

Vocabulary. In power-system usage the words are the opposite of what a
programmer expects, so the shell accepts both and means the same thing:

    CLOSE = contacts closed = circuit energised = current flows = SCS 1 = "on"
    OPEN  = contacts open   = circuit dead      = no current    = SCS 0 = "off"
    TRIP  = an open, usually protective                          = SCS 0

Accepted state words:
    close, closed, on, 1, true, energise      -> SCS/DCS = closed
    open, opened, off, trip, 0, false         -> SCS/DCS = open

Careful: the shell's own `open` and `close` commands manage the TCP session,
not breakers. Guarded - `close 1101` refuses and points you at `operate`.
Use `operate <ioa> close` / `operate <ioa> open` for plant.

The command sequence
--------------------

Select-before-operate (SBO) is what the captured HMI used, and it is the
default here. Two ASDUs per operation:

    1. SELECT   SCO bit7 (S/E) = 1   "reserve this point, tell me if allowed"
       <- actcon, positive = point reserved for you, interlocks clear
       <- actcon, NEGATIVE = refused. Nothing was operated. Stop here.

    2. EXECUTE  SCO bit7 (S/E) = 0   "now actually do it"
       <- actcon  = accepted
       <- actterm = the RTU says the operation finished

    operate 1101 close            # select then execute, the safe default
    operate 1101 close --direct   # execute only, one ASDU, no reservation

`--direct` skips step 1. Some RTUs only accept direct execute, others only
accept SBO and will silently drop a bare execute. If nothing comes back, try
the other mode before assuming the point is wrong.

The SCO / DCO qualifier byte
----------------------------

Single command C_SC_NA_1 (TypeId 45), one octet:

    bit  7    S/E   1 = select, 0 = execute
    bits 6..2 QU    qualifier: 0 none, 1 short pulse, 2 long pulse,
                    3 persistent output
    bit  1    -     must be 0
    bit  0    SCS   1 = close, 0 = open

    0x81 = select + close      0x01 = execute + close
    0x80 = select + open       0x00 = execute + open

Double command C_DC_NA_1 (TypeId 46) uses two state bits instead:

    DCS 0 = not permitted   1 = OPEN   2 = CLOSE   3 = not permitted

Double commands are the safer real-world choice for breakers because 0 and 3
are invalid, so a single corrupted bit cannot be read as a valid operation.
Reach for it with `--double` if single commands are refused:

    operate 1101 close --double

Pulse output. QU tells the RTU how long to hold the coil:

    operate 1101 close --pulse short     # QU=1, momentary
    operate 1101 close --pulse long      # QU=2
    operate 1101 close --pulse persist   # QU=3, latched until commanded back
    operate 1101 close --qu 0            # QU=0, RTU's configured default

The capture used QU=0 on both points, so QU=0 is the known-good value here.

Confirming it worked
--------------------

actterm means the RTU finished its command handling. It does NOT prove the
breaker physically moved. Real confirmation is a status point changing:

    operate 1101 close --verify      # operate, then re-interrogate
    verify                           # interrogate and table everything
    verify 1101 2101                 # only these IOAs
    mon 30                           # watch for a spontaneous (COT=3) change

Note honestly: backup.pcap only ever showed M_ME_NC_1 floats at 2101-2104. No
status point for 1101/1201 appears in it, so this RTU may not report their
position in a station interrogation. Watch the 2101-2104 floats instead - if
those are line measurements, closing a breaker should move them.

When it does not work
---------------------

    no reply at all        wrong CA, or STOPDT, or point not commandable.
                           Check `state`, re-`start`, try `--ca`.
    NEGATIVE actcon        RTU refused: interlock active, not selected first,
                           invalid QU/DCS, or you lack authority.
                           Try `--double`, or SBO instead of `--direct`.
    COT 47 unknown object  IOA does not exist on that CA.
    COT 46 unknown asdu    CA is wrong. `ic --bcast` to discover the real one.
    COT 45 unknown cause   RTU rejects COT=6 on this type.
    COT 44 unknown type    RTU does not implement TypeId 45/46 at all.

All of these are decoded by name in the frame log, so read the `[<-]` lines.

Safety
------

`operate` and `trip` prompt for confirmation on a terminal. `--yes` skips it,
and it is skipped automatically when input is piped or run via `-x`.
IOA 1101 and 1201 are outputs the captured HMI energised - they are real plant
actuations, not readings.
""",
        "addressing": """
ADDRESSING
==========

    TCP host:2404   ->   CA   ->   IOA
    which device         which     which point inside
                         station   that station

CA, Common Address of ASDU (2 octets in -104). Which logical station/RTU. The
capture's RTU answers on CA=17. 0 means unused. 0xFFFF is the global
broadcast address, legal only for interrogation, counter interrogation, clock
sync, reset process and test - NEVER for commands, which must name a real CA.

OA, Originator Address (1 octet, inside the 2-octet COT field). Which master
station sent the command, so that with several masters on one RTU each can
recognise its own actcon/actterm. The capture's HMI used OA=0.

IOA, Information Object Address (3 octets). The individual point.

Header layout, real frame from backup.pcap:

    2d   01   06   00   1100   4d0400   81
    |    |    |    |    |      |        SCO: select + close
    |    |    |    |    |      IOA = 1101
    |    |    |    |    CA = 17
    |    |    |    OA = 0
    |    |    COT = 6 (act)
    |    VSQ: 1 object, SQ=0
    TypeId 45 = C_SC_NA_1

Set them:  `ca 17`, `oa 0` for the session; `--ca N` or `--bcast` per command.
Discover CA: `ic --bcast` and read the CA in the reply.
""",
        "points": """
POINTS RECOVERED FROM backup.pcap
=================================

    IOA      TYPE          NOTES
    2101     M_ME_NC_1     float, 11.24 per/cyc, 11.23 interrogated
    2102     M_ME_NC_1     float, 3.72 / 3.78
    2103     M_ME_NC_1     float, 13.5 / 13.8
    2104     M_ME_NC_1     float, 67.0 / 68.1
             All four arrive as one SQ=1 block based at 2101.
    1101     C_SC_NA_1     OUTPUT. HMI sent select 0x81 then execute 0x01,
                           i.e. it CLOSED this point.
    1201     C_SC_NA_1     OUTPUT. Same select-then-execute close.
    266500   TypeId 104    private, 0x041104, payload bb322456bda87cee.
                           Sending it alone made the RTU push measurements
                           with no interrogation - probably an unlock token.

Nothing in the capture reveals status/position points for 1101 or 1201, nor
any point outside these. Use `sweep` to look for more:

    sweep 1000 1300        # read-only probe of a range
    sweep 2000 2200 --step 1
""",
        "recon": """
SUGGESTED ORDER OF WORK
=======================

    1  open 154.57.164.71        connect, STARTDT
    2  ic --bcast                discover the real CA and dump all points
    3  priv                      replay the private TypeId=104 token
    4  mon 30                    watch what arrives unprompted
    5  sweep 1000 1300           hunt for undiscovered IOAs (read-only)
    6  verify                    snapshot values BEFORE touching anything
    7  operate 1101 close        the actuation the captured HMI performed
    8  verify 1101 2101 2102     compare against the step-6 snapshot

Steps 1-6 change nothing. Step 7 does.
""",
    }

    def cmd_help(self, args):
        """help [command|topic] - command list, or a long topic page.
                                 Topics: control, addressing, points, recon."""
        if args:
            key = args[0].lower()
            if key in self.HELP_TOPICS:
                print(self.HELP_TOPICS[key].strip())
                return
            name = self.ALIASES.get(key, key)
            fn = getattr(self, f"cmd_{name}", None)
            if fn is None:
                print(f"unknown command or topic: {args[0]}\n"
                      f"topics: {', '.join(sorted(self.HELP_TOPICS))}")
                return
            doc = (fn.__doc__ or "no help").strip()
            for i, ln in enumerate(doc.splitlines()):
                print(" " * 23 + ln.strip() if i else ln)
            for k, v in self.ALIASES.items():
                if v == name:
                    print(f"  alias: {k}")
            return

        print("IEC 60870-5-104 command shell")
        print(f"target {self.host}:{self.port}   ca={self.ca}  oa={self.oa}\n")
        for title, blurb, names in self.HELP_GROUPS:
            print(f"{title.upper()}{'  - ' + blurb if blurb else ''}")
            for n in names:
                fn = getattr(self, f"cmd_{n}", None)
                doc = (fn.__doc__ or n).strip() if fn else n
                for i, ln in enumerate(doc.splitlines()):
                    print(" " * 25 + ln.strip() if i else "  " + ln)
            print()
        print("OPENING AND CLOSING - the short version")
        print("  CLOSE = energise, contacts closed, SCS=1, also spelled `on`")
        print("  OPEN  = de-energise / trip, contacts apart, SCS=0, also `off`")
        print("  operate 1101 close        select-before-operate, as the HMI did")
        print("  operate 1101 open         de-energise the same point")
        print("  trip 1101                 same as `operate 1101 open`")
        print("  operate 1101 close --double     use C_DC_NA_1 instead of C_SC_NA_1")
        print("  operate 1101 close --direct     skip select, execute only")
        print("  operate 1101 close --verify     operate, then re-interrogate")
        print("  NOTE the shell's own `open`/`close` manage the TCP session,")
        print("       not breakers. Use `operate` for plant. See `help control`.\n")
        print("MODIFIERS")
        print("  --ca N          override common ASDU address for this command")
        print("  --bcast         CA=0xFFFF (what the HMI used for ic and clock)")
        print("  --direct, -d    control: skip select, execute immediately")
        print("  --double        operate: use a double command (DCS 2=close, 1=open)")
        print("  --pulse P       control: QU short|long|persist|none")
        print("  --qu N          control: raw qualifier value")
        print("  --verify, -v    operate: re-interrogate afterwards")
        print("  --yes, -y       operate: skip the confirmation prompt")
        print("  --cot N         raw only: cause of transmission (default 6 = act)")
        print("  --sq N          raw only: sequence-of-objects with N elements\n")
        print("POINTS FROM backup.pcap")
        print("  2101-2104   M_ME_NC_1 floats: 11.24, 3.72, 13.5, 67.0")
        print("  1101, 1201  C_SC_NA_1 OUTPUTS - the HMI closed both")
        print("  266500      private TypeId=104, payload bb322456bda87cee\n")
        print("HOW MUCH DETAIL IS SHOWN")
        print("  view human       plain language, link housekeeping hidden (default)")
        print("  view frames      one line per APDU with TypeIds and sequence numbers")
        print("  view raw         frames plus the hex of every APDU")
        print("  full on          print EVERY frame, repeats included")
        print("  full off         fold identical repeats into '... same N more")
        print("                   times' (default). Works in all three views.")
        print("  --view / --full  the same, set at launch\n")
        print("READING LONG OUTPUT (split-screen UI)")
        print("  after a long command the view parks at its START and the status")
        print("  bar shows -- MORE --. To move through it:")
        print("    PgUp / PgDn        scroll a screen, works at any time")
        print("    up / down arrows   scroll a line while -- MORE -- is showing")
        print("    space              page down while -- MORE -- is showing")
        print("    Home / End         oldest output / back to live")
        print("    scroll up|down|top|end [n]   same thing as a command")
        print("    mouse on           wheel scrolling (off by default - it would")
        print("                       block selecting text with the mouse)\n")
        print("COPYING TEXT OUT")
        print("  A selection disappears when an arriving frame repaints the cells")
        print("  under it. Freeze the pane first and it will hold:")
        print("    F2 or Ctrl-O       pause/resume the pane (`pause` also works)")
        print("                       frames keep arriving and are shown on resume")
        print("  Then select with the mouse as normal - capture is off by default;")
        print("  if you enabled it with `mouse on`, hold Shift to select.")
        print("  Or skip selecting entirely:")
        print("    save [file] [n]    write the transcript to a file")
        print("    copy [n]           last n lines to the clipboard")
        print("    --plain            normal prompt, native terminal scrollback\n")
        print("TOPIC PAGES  (long form)")
        print("  help control      opening/closing in depth: SBO, SCO bits,")
        print("                    pulse output, confirming, every failure mode")
        print("  help addressing   CA, OA, IOA and the header layout")
        print("  help points       full point list from the capture")
        print("  help recon        suggested order of work, safe steps first\n")
        print("`help <command>` for one command.  quit / exit / Ctrl-D to leave.")

    def cmd_quit(self, args):
        """quit                 - close and exit"""
        self.cmd_close([])
        raise SystemExit(0)

    cmd_exit = cmd_quit

    # -- dispatch ---------------------------------------------------------- #

    ALIASES = {
        "cmd": "sc", "connect": "open", "interrogate": "ic", "clocksync": "clock",
        "setpoint": "sp", "monitor": "mon", "q": "quit", "?": "help",
        "op": "operate", "select": "operate", "execute": "operate",
        "disconnect": "close", "status": "verify",
    }

    def names(self):
        return sorted({n[4:] for n in dir(self) if n.startswith("cmd_")}
                      | set(self.ALIASES))

    def run_line(self, line):
        """Run one line. Several commands may be chained with ';' or '&&', which
        matters because the RTU's authorisation window is only ~30 seconds:
            priv ; sc 1301 open ; sc 1201 close
        With '&&' the rest is abandoned if a command reports a failure."""
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            print(f"parse error: {exc}")
            return
        if not parts:
            return
        groups, current, joiners = [], [], []
        for tok in parts:
            if tok in (";", "&&"):
                groups.append(current)
                joiners.append(tok)
                current = []
            else:
                current.append(tok)
        groups.append(current)
        for i, group in enumerate(groups):
            if not group:
                continue
            ok = self._dispatch(group)
            if not ok and i < len(joiners) and joiners[i] == "&&":
                print("stopping: previous command reported a problem")
                return

    def _dispatch(self, parts):
        """Run one already-tokenised command. Returns False on a reported error."""
        name = self.ALIASES.get(parts[0].lower(), parts[0].lower())
        fn = getattr(self, f"cmd_{name}", None)
        if fn is None:
            print(f"unknown command: {parts[0]} (try `help`)")
            return False
        try:
            fn(parts[1:])
        except SystemExit:
            raise
        except KeyboardInterrupt:
            print()
            return False
        except (ValueError, IndexError) as exc:
            print(f"bad arguments: {exc}")
            return False
        except OSError as exc:
            print(f"link error: {exc}")
            return False
        return True

    def completer(self, text, state):
        opts = [n for n in self.names() if n.startswith(text)]
        return opts[state] if state < len(opts) else None

    def repl(self):
        """Plain readline REPL. Async output from the reader thread is written
        through a proxy that erases the input line first and redraws the prompt
        plus whatever you had typed, so incoming frames never garble it."""
        guard = _PromptGuard(sys.stdout)
        sys.stdout = guard
        try:
            self._repl(guard)
        finally:
            sys.stdout = guard.real

    def _repl(self, guard=None):
        readline.set_completer(self.completer)
        readline.parse_and_bind("tab: complete")
        try:
            readline.read_history_file(HISTFILE)
        except OSError:
            pass
        atexit.register(lambda: readline.write_history_file(HISTFILE))

        print(f"IEC-104 shell  ->  {self.host}:{self.port}  (ca={self.ca})")
        print("`help` for commands, `points` for known IOAs from the pcap")
        while True:
            up = "" if (self.c and self.c._running) else " [down]"
            prompt = f"rtu{up}> "
            if guard is not None:
                guard.set_prompt(prompt)
            try:
                line = input(prompt)
            except EOFError:
                print()
                self.cmd_close([])
                return
            except KeyboardInterrupt:
                print()
                continue
            if guard is not None:
                guard.set_prompt(None)
            # An interactive line is echoed by the terminal, not printed, so it
            # never reaches the tee. Record it explicitly. (Under -e/-x the
            # prompt echo IS printed, so logging there would duplicate it.)
            if self.transcript is not None and line.strip():
                self.transcript.write_line(f"rtu> {line}", raw=True)
            self.run_line(line)


_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\r")


class Transcript:
    """Line-oriented session log. Strips ANSI so the file stays greppable, and
    flushes every line so a killed session still leaves a usable log."""

    def __init__(self, path, append=False, timestamps=False):
        self.path = os.path.abspath(path)
        self.timestamps = timestamps
        self.lock = threading.Lock()
        self.fh = open(path, "a" if append else "w", buffering=1)
        self.partial = ""
        self.muted_depth = 0

    # input() writes the prompt to stdout with no newline, so in plain mode it
    # ends up glued to the front of the next logged line. Strip it; commands are
    # recorded separately via write_line(raw=True).
    _PROMPT = re.compile(r"^(rtu(?: \[down\])?> )+")

    def write_line(self, line, raw=False):
        line = _ANSI.sub("", line).rstrip()
        if not raw:
            line = self._PROMPT.sub("", line)
            if not line:
                return
        with self.lock:
            if self.fh.closed:
                return
            if self.timestamps:
                stamp = _dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                self.fh.write(f"{stamp} {line}\n")
            else:
                self.fh.write(line + "\n")

    @contextlib.contextmanager
    def muted(self):
        """Ignore writes for the duration - used while the client prints a folded
        screen line whose unfolded twin has already been written."""
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

    def write(self, s):
        """Accept partial writes (print() emits text and "\\n" separately)."""
        with self.lock:
            if self.muted_depth:
                return
            self.partial += s
        while "\n" in self.partial:
            line, self.partial = self.partial.split("\n", 1)
            self.write_line(line)

    def close(self):
        with self.lock:
            if self.partial:
                rest, self.partial = self.partial, ""
            else:
                rest = ""
        if rest:
            self.write_line(rest)
        with self.lock:
            if not self.fh.closed:
                self.fh.close()


class _Tee:
    """Writes to the real stream and mirrors into one or more Transcripts."""

    def __init__(self, real, *transcripts):
        self.real = real
        self.transcripts = [t for t in transcripts if t is not None]

    def write(self, s):
        self.real.write(s)
        for t in self.transcripts:
            t.write(s)
        return len(s)

    def flush(self):
        self.real.flush()

    def isatty(self):
        try:
            return self.real.isatty()
        except Exception:
            return False

    def fileno(self):
        return self.real.fileno()


class _PromptGuard:
    """stdout proxy for plain readline mode.

    While the shell is blocked in input(), any write from the reader thread
    would land on top of the line being typed. This erases the input line,
    writes the message, then redraws the prompt and readline's current buffer.
    """

    def __init__(self, real):
        self.real = real
        self.prompt = None
        self.partial = ""
        self.lock = threading.Lock()
        try:
            self.tty = real.isatty()
        except Exception:
            self.tty = False

    def set_prompt(self, prompt):
        with self.lock:
            self.prompt = prompt

    def write(self, s):
        with self.lock:
            # Only rewrite the input line on a real terminal, and only once a
            # whole line is available - otherwise print()'s separate text and
            # "\n" writes would each trigger a redraw.
            if not self.tty or self.prompt is None:
                self.real.write(s)
                self.real.flush()
                return
            self.partial += s
            if "\n" not in self.partial:
                return
            done, self.partial = self.partial.rsplit("\n", 1)
            self.real.write("\r\x1b[2K" + done + "\n"
                            + self.prompt + readline.get_line_buffer())
            self.real.flush()

    def flush(self):
        with self.lock:
            if self.partial and (not self.tty or self.prompt is None):
                self.real.write(self.partial)
                self.partial = ""
            self.real.flush()

    def isatty(self):
        return self.real.isatty()

    def fileno(self):
        return self.real.fileno()


def main(argv=None):
    p = argparse.ArgumentParser(description="Interactive IEC-104 command shell")
    p.add_argument("host")
    p.add_argument("port", nargs="?", type=num, default=2404)
    p.add_argument("--ca", type=num, default=17, help="common ASDU address (pcap: 17)")
    p.add_argument("--oa", type=num, default=0)
    p.add_argument("--no-open", action="store_true", help="do not connect at startup")
    p.add_argument("-e", "--exec", action="append", default=[],
                   metavar="CMD", help="run a command then continue (repeatable)")
    p.add_argument("-x", "--script", metavar="FILE",
                   help="run commands from a file, then exit")
    p.add_argument("--plain", action="store_true",
                   help="plain readline prompt instead of the split-screen UI")
    p.add_argument("--tui", action="store_true",
                   help="force the split-screen UI")
    p.add_argument("--view", choices=("human", "frames", "raw"), default="human",
                   help="output style: human (default), frames, or raw hex")
    p.add_argument("--hmi", type=num, metavar="PORT",
                   help="HMI web port, for the `hmi` and `alarms` commands")
    p.add_argument("--full", action="store_true",
                   help="print every frame instead of folding identical repeats")
    p.add_argument("--log", metavar="FILE",
                   help="log every frame to FILE, unfolded, whatever the screen "
                        "shows (ANSI stripped)")
    p.add_argument("--log-folded", metavar="FILE",
                   help="second log written exactly as shown on screen, with "
                        "repeats folded")
    p.add_argument("--log-append", action="store_true",
                   help="append to --log instead of truncating it")
    p.add_argument("--log-time", action="store_true",
                   help="prefix each logged line with a HH:MM:SS.mmm stamp")
    a = p.parse_args(argv)

    sh = Shell(a.host, a.port, a.ca, a.oa)
    sh.style = a.view
    sh.collapse = not a.full
    sh.hmi_port = a.hmi

    if a.log:
        try:
            sh.transcript = Transcript(a.log, append=a.log_append,
                                       timestamps=a.log_time)
        except OSError as exc:
            print(f"cannot open log {a.log}: {exc}", file=sys.stderr)
            return 1
        sh.transcript.write_line(
            f"=== rtu_shell {a.host}:{a.port} ca={a.ca} oa={a.oa} "
            f"started {_dt.datetime.now().isoformat(timespec='seconds')} "
            f"(full, unfolded) ===")
        print(f"logging every frame to {sh.transcript.path}")
    if a.log_folded:
        try:
            sh.folded_transcript = Transcript(a.log_folded, append=a.log_append,
                                              timestamps=a.log_time)
        except OSError as exc:
            print(f"cannot open log {a.log_folded}: {exc}", file=sys.stderr)
            return 1
        print(f"logging the screen view to {sh.folded_transcript.path}")

    # Split-screen by default on a real terminal: the output pane scrolls above
    # a pinned prompt, so async frames cannot overwrite what is being typed.
    if not a.script and (a.tui or (not a.plain and rtu_tui.available())):
        try:
            rtu_tui.TUI(sh, log=sh.transcript,
                        folded_log=sh.folded_transcript).run(
                            startup_cmds=a.exec, auto_open=not a.no_open)
        finally:
            for t in (sh.transcript, sh.folded_transcript):
                if t:
                    t.close()
        return 0

    # Plain and script modes: mirror stdout into the log.
    if sh.transcript is not None or sh.folded_transcript is not None:
        sys.stdout = _Tee(sys.stdout, sh.transcript, sh.folded_transcript)
    try:
        if not a.no_open:
            sh.cmd_open([])
        for c in a.exec:
            print(f"rtu> {c}")
            sh.run_line(c)
        if a.script:
            with open(a.script) as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        print(f"rtu> {line}")
                        sh.run_line(line)
            sh.cmd_close([])
            return 0
        sh.repl()
    finally:
        if isinstance(sys.stdout, _Tee):
            sys.stdout = sys.stdout.real
        for t in (sh.transcript, sh.folded_transcript):
            if t:
                t.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.exit(130)
