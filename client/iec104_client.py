#!/usr/bin/env python3
"""
IEC 60870-5-104 client (HMI / master station).

Reconstructed from backup.pcap: HMI 172.17.0.1 -> RTU 172.17.0.5:2404.

Observed link parameters (all defaults below):
    Common ASDU address (CA) : 17
    Originator address (OA)  : 0
    COT field size           : 2 octets (COT + OA)
    CA field size            : 2 octets
    IOA field size           : 3 octets

Observed session flows:
    A) STARTDT act -> con
       I: TypeId=104 (private), COT=Act, CA=17, IOA=266500, payload bb322456bda87cee
       <- I: M_ME_NC_1 (13) SQ=1 n=4, COT=Per/Cyc, IOA 2101..2104 floats

    B) STARTDT act -> con
       C_IC_NA_1  (100) COT=Act, CA=0xFFFF, IOA=0, QOI=20   -> actcon, data, actterm
       C_CS_NA_1  (103) COT=Act, CA=0xFFFF, IOA=0, CP56Time2a -> actcon
       C_SC_NA_1  (45)  COT=Act, CA=17, IOA=1101, SCO=0x81 (select ON) -> actcon
       C_SC_NA_1  (45)  COT=Act, CA=17, IOA=1101, SCO=0x01 (execute ON) -> actcon, actterm
       C_SC_NA_1  (45)  CA=17, IOA=1201, same select/execute pair
       S-format ack

No third-party dependencies.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import queue
import socket
import struct
import sys
import threading
import time

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

START = 0x68

# U-format control field 1 values
U_STARTDT_ACT = 0x07
U_STARTDT_CON = 0x0B
U_STOPDT_ACT = 0x13
U_STOPDT_CON = 0x23
U_TESTFR_ACT = 0x43
U_TESTFR_CON = 0x83

U_NAMES = {
    U_STARTDT_ACT: "STARTDT act",
    U_STARTDT_CON: "STARTDT con",
    U_STOPDT_ACT: "STOPDT act",
    U_STOPDT_CON: "STOPDT con",
    U_TESTFR_ACT: "TESTFR act",
    U_TESTFR_CON: "TESTFR con",
}

# Type identifiers seen / commonly useful
M_SP_NA_1 = 1     # single point
M_DP_NA_1 = 3     # double point
M_ME_NA_1 = 9     # measured, normalized
M_ME_NB_1 = 11    # measured, scaled
M_ME_NC_1 = 13    # measured, short float
M_SP_TB_1 = 30    # single point with CP56Time2a
M_ME_TF_1 = 36    # short float with CP56Time2a
C_SC_NA_1 = 45    # single command
C_DC_NA_1 = 46    # double command
C_SE_NC_1 = 50    # setpoint, short float
C_IC_NA_1 = 100   # interrogation command
C_CI_NA_1 = 101   # counter interrogation
C_RD_NA_1 = 102   # read command
C_CS_NA_1 = 103   # clock synchronisation
C_TS_NA_1 = 104   # test command
C_RP_NA_1 = 105   # reset process

TYPE_NAMES = {
    1: "M_SP_NA_1", 3: "M_DP_NA_1", 5: "M_ST_NA_1", 7: "M_BO_NA_1",
    9: "M_ME_NA_1", 11: "M_ME_NB_1", 13: "M_ME_NC_1", 15: "M_IT_NA_1",
    20: "M_PS_NA_1", 21: "M_ME_ND_1",
    30: "M_SP_TB_1", 31: "M_DP_TB_1", 32: "M_ST_TB_1", 33: "M_BO_TB_1",
    34: "M_ME_TD_1", 35: "M_ME_TE_1", 36: "M_ME_TF_1", 37: "M_IT_TB_1",
    45: "C_SC_NA_1", 46: "C_DC_NA_1", 47: "C_RC_NA_1", 48: "C_SE_NA_1",
    49: "C_SE_NB_1", 50: "C_SE_NC_1", 51: "C_BO_NA_1",
    58: "C_SC_TA_1", 59: "C_DC_TA_1", 60: "C_RC_TA_1", 61: "C_SE_TA_1",
    62: "C_SE_TB_1", 63: "C_SE_TC_1", 64: "C_BO_TA_1",
    70: "M_EI_NA_1",
    100: "C_IC_NA_1", 101: "C_CI_NA_1", 102: "C_RD_NA_1", 103: "C_CS_NA_1",
    104: "C_TS_NA_1", 105: "C_RP_NA_1", 107: "C_TS_TA_1",
    110: "P_ME_NA_1", 111: "P_ME_NB_1", 112: "P_ME_NC_1", 113: "P_AC_NA_1",
    120: "F_FR_NA_1", 121: "F_SR_NA_1", 122: "F_SC_NA_1", 123: "F_LS_NA_1",
    124: "F_AF_NA_1", 125: "F_SG_NA_1", 126: "F_DR_TA_1",
}

COT_NAMES = {
    1: "per/cyc", 2: "back", 3: "spont", 4: "init", 5: "req", 6: "act",
    7: "actcon", 8: "deact", 9: "deactcon", 10: "actterm", 11: "retrem",
    12: "retloc", 13: "file", 20: "inrogen",
    44: "unknown type", 45: "unknown cause",
    46: "unknown asdu address", 47: "unknown object address",
}
for _i in range(21, 37):
    COT_NAMES.setdefault(_i, f"inro{_i - 20}")

COT_ACT = 6
COT_ACTCON = 7
COT_DEACT = 8
COT_ACTTERM = 10

QOI_STATION = 20  # station interrogation (global)

# Type identifiers whose information objects are (IOA, value, quality)
_FIXED_ELEM_LEN = {
    1: 1,      # SIQ
    3: 1,      # DIQ
    9: 3,      # NVA + QDS
    11: 3,     # SVA + QDS
    13: 5,     # IEEE754 + QDS
    45: 1,     # SCO
    46: 1,     # DCO
    100: 1,    # QOI
    101: 1,    # QCC
    103: 7,    # CP56Time2a
    30: 8,     # SIQ + CP56Time2a
    36: 12,    # IEEE754 + QDS + CP56Time2a
    50: 5,     # IEEE754 + QOS
}


# --------------------------------------------------------------------------- #
# CP56Time2a
# --------------------------------------------------------------------------- #

def cp56time2a(when: _dt.datetime | None = None) -> bytes:
    """Encode a datetime as the 7-octet CP56Time2a used by C_CS_NA_1."""
    if when is None:
        when = _dt.datetime.now()
    ms = when.second * 1000 + when.microsecond // 1000
    dow = when.isoweekday()  # 1=Mon .. 7=Sun
    return struct.pack(
        "<HBBBBB",
        ms,
        when.minute & 0x3F,
        when.hour & 0x1F,
        (dow << 5) | (when.day & 0x1F),
        when.month & 0x0F,
        when.year % 100 & 0x7F,
    )


def parse_cp56time2a(raw: bytes) -> str:
    if len(raw) < 7:
        return "<short time>"
    ms, minute, hour, dom, month, year = struct.unpack("<HBBBBB", raw[:7])
    return (
        f"{2000 + (year & 0x7F):04d}-{month & 0x0F:02d}-{dom & 0x1F:02d} "
        f"{hour & 0x1F:02d}:{minute & 0x3F:02d}:{ms // 1000:02d}.{ms % 1000:03d}"
    )


# --------------------------------------------------------------------------- #
# ASDU
# --------------------------------------------------------------------------- #

def _fmt_num(v):
    """Short, human-friendly number: 11.24 not 11.239999771118164."""
    if v == int(v) and abs(v) < 1e9:
        return str(int(v))
    return f"{v:.4g}"


# Plain-language names for the causes of transmission a human cares about.
_COT_HUMAN = {
    1: "periodic", 2: "background", 3: "spontaneous", 4: "after startup",
    5: "requested", 20: "from interrogation",
}
_COT_ERROR = {
    44: "this RTU does not implement that message type",
    45: "the RTU rejected the cause of transmission",
    46: "wrong station address (CA)",
    47: "no such point at that address (IOA)",
}
_CMD_TYPES = {45: "single", 46: "double", 47: "step", 58: "single",
              59: "double", 60: "step"}
_SETPOINT_TYPES = {48: "normalised", 49: "scaled", 50: "float",
                   61: "normalised", 62: "scaled", 63: "float"}


class ASDU:
    """A parsed / buildable application service data unit."""

    def __init__(self, type_id, cot, ca, objects=None, sq=False, oa=0,
                 negative=False, test=False, raw=b""):
        self.type_id = type_id
        self.cot = cot
        self.ca = ca
        self.oa = oa
        self.sq = sq
        self.negative = negative
        self.test = test
        self.objects = objects or []      # list of (ioa, bytes) or (ioa, value)
        self.raw = raw                    # undecoded object body

    # -- build ------------------------------------------------------------- #

    @classmethod
    def build(cls, type_id, cot, ca, ioa, payload=b"", sq=False, count=None,
              oa=0, negative=False, test=False) -> bytes:
        """Build ASDU bytes for a single (or SQ) information object block."""
        n = count if count is not None else 1
        vsq = (0x80 if sq else 0x00) | (n & 0x7F)
        cot_b = (cot & 0x3F) | (0x40 if negative else 0) | (0x80 if test else 0)
        return (
            struct.pack("<BBBBH", type_id, vsq, cot_b, oa & 0xFF, ca & 0xFFFF)
            + struct.pack("<I", ioa & 0xFFFFFF)[:3]
            + payload
        )

    # -- parse ------------------------------------------------------------- #

    @classmethod
    def parse(cls, data: bytes) -> "ASDU":
        type_id, vsq, cot_b, oa = struct.unpack("<BBBB", data[:4])
        ca = struct.unpack("<H", data[4:6])[0]
        sq = bool(vsq & 0x80)
        n = vsq & 0x7F
        a = cls(
            type_id=type_id,
            cot=cot_b & 0x3F,
            ca=ca,
            sq=sq,
            oa=oa,
            negative=bool(cot_b & 0x40),
            test=bool(cot_b & 0x80),
            raw=data[6:],
        )
        a._decode(data[6:], n)
        return a

    def _decode(self, body: bytes, n: int) -> None:
        elen = _FIXED_ELEM_LEN.get(self.type_id)
        if elen is None:
            # Unknown / private type: keep whole body after the first IOA.
            if len(body) >= 3:
                ioa = int.from_bytes(body[0:3], "little")
                self.objects = [(ioa, body[3:])]
            return
        try:
            if self.sq:
                base = int.from_bytes(body[0:3], "little")
                off = 3
                for i in range(n):
                    self.objects.append((base + i, body[off:off + elen]))
                    off += elen
            else:
                off = 0
                for _ in range(n):
                    ioa = int.from_bytes(body[off:off + 3], "little")
                    off += 3
                    self.objects.append((ioa, body[off:off + elen]))
                    off += elen
        except Exception:
            pass

    # -- pretty print ------------------------------------------------------ #

    def value_str(self, elem: bytes) -> str:
        t = self.type_id
        try:
            if t == 1:
                siq = elem[0]
                return f"SPI={siq & 1} q=0x{siq & 0xF0:02x}"
            if t == 3:
                diq = elem[0]
                return f"DPI={diq & 3} q=0x{diq & 0xF0:02x}"
            if t in (9, 11):
                v = struct.unpack("<h", elem[0:2])[0]
                return f"{v} QDS=0x{elem[2]:02x}"
            if t == 13:
                v = struct.unpack("<f", elem[0:4])[0]
                return f"{v:g} QDS=0x{elem[4]:02x}"
            if t == 30:
                return f"SPI={elem[0] & 1} @{parse_cp56time2a(elem[1:8])}"
            if t == 36:
                v = struct.unpack("<f", elem[0:4])[0]
                return f"{v:g} QDS=0x{elem[4]:02x} @{parse_cp56time2a(elem[5:12])}"
            if t == 45:
                sco = elem[0]
                return (f"SCO=0x{sco:02x} SCS={sco & 1} "
                        f"QU={(sco >> 2) & 0x1F} S/E={(sco >> 7) & 1}")
            if t == 46:
                dco = elem[0]
                return (f"DCO=0x{dco:02x} DCS={dco & 3} "
                        f"QU={(dco >> 2) & 0x1F} S/E={(dco >> 7) & 1}")
            if t == 50:
                v = struct.unpack("<f", elem[0:4])[0]
                return f"{v:g} QOS=0x{elem[4]:02x}"
            if t == 100:
                return f"QOI={elem[0]}"
            if t == 103:
                return parse_cp56time2a(elem)
        except Exception:
            pass
        return elem.hex()

    # -- plain language ---------------------------------------------------- #

    def describe(self) -> str:
        """One line of plain English. No sequence numbers, no hex, no acronyms
        unless they carry information a reader needs."""
        t = self.type_id

        if self.cot in _COT_ERROR:
            what = TYPE_NAMES.get(t, f"type {t}")
            return f"ERROR: {_COT_ERROR[self.cot]} ({what})"

        # Measurements and counters.
        if t in (9, 11, 13, 21, 34, 35, 36, 15, 37):
            vals = []
            for ioa, elem in self.objects:
                v = None
                try:
                    if t in (13, 36):
                        v = struct.unpack("<f", elem[0:4])[0]
                    elif t in (9, 11, 21, 34, 35):
                        v = float(struct.unpack("<h", elem[0:2])[0])
                    elif t in (15, 37):
                        v = float(struct.unpack("<i", elem[0:4])[0])
                except Exception:
                    pass
                vals.append(f"{ioa}={_fmt_num(v) if v is not None else '?'}")
            src = _COT_HUMAN.get(self.cot)
            head = f"values ({src})" if src else "values"
            return f"{head}:  " + "   ".join(vals)

        # Binary status points.
        if t in (1, 3, 30, 31):
            out = []
            for ioa, elem in self.objects:
                if t in (1, 30):
                    state = "ON" if elem[0] & 1 else "OFF"
                else:
                    state = {0: "indeterminate", 1: "OFF", 2: "ON",
                             3: "faulty"}[elem[0] & 3]
                out.append(f"{ioa}={state}")
            src = _COT_HUMAN.get(self.cot)
            head = f"status ({src})" if src else "status"
            return f"{head}:  " + "   ".join(out)

        # Commands: say SELECT vs EXECUTE, and open vs close.
        if t in _CMD_TYPES:
            bits = self.objects[0][1][0] if self.objects else 0
            ioa = self.objects[0][0] if self.objects else "?"
            if t in (46, 59):
                state = {0: "invalid", 1: "OPEN", 2: "CLOSE", 3: "invalid"}[bits & 3]
            else:
                state = "CLOSE" if bits & 1 else "OPEN"
            stage = "SELECT" if bits & 0x80 else "EXECUTE"
            qu = (bits >> 2) & 0x1F
            pulse = {1: " short pulse", 2: " long pulse", 3: " latched"}.get(qu, "")
            body = f"{stage} {state} output {ioa}{pulse}"
            if self.negative:
                return f"REFUSED: {body}  (RTU said no)"
            if self.cot == COT_ACTCON:
                return f"confirmed {body}"
            if self.cot == COT_ACTTERM:
                return f"operation finished: output {ioa}"
            return body

        # Setpoints and parameters.
        if t in _SETPOINT_TYPES:
            ioa, elem = self.objects[0] if self.objects else ("?", b"")
            try:
                v = (struct.unpack("<f", elem[0:4])[0] if t in (50, 63)
                     else float(struct.unpack("<h", elem[0:2])[0]))
                val = _fmt_num(v)
            except Exception:
                val = "?"
            body = f"set point {ioa} = {val}"
            if self.negative:
                return f"REFUSED: {body}  (RTU said no)"
            if self.cot == COT_ACTCON:
                return f"confirmed {body}"
            return body
        if t in (110, 111, 112):
            ioa, elem = self.objects[0] if self.objects else ("?", b"")
            kinds = {1: "threshold", 2: "smoothing", 3: "low limit",
                     4: "high limit"}
            try:
                v = (struct.unpack("<f", elem[0:4])[0] if t == 112
                     else float(struct.unpack("<h", elem[0:2])[0]))
                kind = kinds.get(elem[-1] & 0x3F, "parameter")
                body = f"set {kind} of point {ioa} = {_fmt_num(v)}"
            except Exception:
                body = f"set parameter of point {ioa}"
            if self.negative:
                return f"REFUSED: {body}  (RTU said no)"
            if self.cot == COT_ACTCON:
                return f"confirmed {body}"
            return body

        # System messages.
        if t == C_IC_NA_1:
            qoi = self.objects[0][1][0] if self.objects else 0
            what = ("read all points (general interrogation)" if qoi == 20
                    else f"read point group {qoi - 20}")
            if self.negative:
                return f"REFUSED: {what}"
            if self.cot == COT_ACTCON:
                return f"acknowledged: {what}"
            if self.cot == COT_ACTTERM:
                return f"finished: {what}"
            return what
        if t == C_CI_NA_1:
            return {COT_ACTCON: "acknowledged: read counters",
                    COT_ACTTERM: "finished: read counters"}.get(
                        self.cot, "read counters")
        if t == C_RD_NA_1:
            ioa = self.objects[0][0] if self.objects else "?"
            return f"read point {ioa}"
        if t == C_CS_NA_1:
            when = (parse_cp56time2a(self.objects[0][1])
                    if self.objects else "?")
            return ("confirmed clock set" if self.cot == COT_ACTCON
                    else f"set clock to {when}")
        if t == C_TS_NA_1:
            ioa, elem = self.objects[0] if self.objects else (0, b"")
            return (f"private request at point {ioa}"
                    f" [{elem.hex()}]" if elem else f"private request at {ioa}")
        if t == C_RP_NA_1:
            return "reset process"
        if t == 70:
            return "RTU reports it has just initialised"

        name = TYPE_NAMES.get(t, f"private type {t}")
        return f"{name}: {self.raw.hex()}"

    def __str__(self) -> str:
        name = TYPE_NAMES.get(self.type_id, "PRIVATE")
        cot = COT_NAMES.get(self.cot, str(self.cot))
        head = (f"{name}({self.type_id}) CA={self.ca} COT={cot}"
                f"{' NEG' if self.negative else ''}{' TEST' if self.test else ''}")
        if not self.objects:
            return f"{head} raw={self.raw.hex()}"
        parts = [f"IOA={ioa} {self.value_str(e)}" for ioa, e in self.objects]
        return head + " | " + "; ".join(parts)


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

class IEC104Client:
    """Master station (HMI) speaking IEC 60870-5-104 to an RTU."""

    def __init__(self, host, port=2404, ca=17, oa=0, k=12, w=8,
                 timeout=10.0, verbose=True, style="human", collapse=True):
        # style: "human"  plain language, link housekeeping hidden, identical
        #                 repeated frames collapsed into one counted line
        #        "frames" one line per APDU with sequence numbers and acronyms
        #        "raw"    frames plus the hex of every APDU
        # collapse: fold runs of identical lines into a counted summary. Turn it
        #           off (--full / `full on`) to see every frame as it arrives.
        self.style = style
        self.collapse = collapse
        # Transcript that must receive every frame unfolded, whatever the screen
        # is doing. Set by the shell when --log is active.
        self.log_sink = None
        self._last_line = None
        self._repeats = 0
        self.host = host
        self.port = port
        self.ca = ca
        self.oa = oa
        self.k = k                 # max unacked outbound I-frames
        self.w = w                 # send S-ack after w received I-frames
        self.timeout = timeout
        self.verbose = verbose

        self.sock = None
        self.i_sent = 0            # I-frames sent on this connection
        self.tx = 0                # V(S) - our send sequence number
        self.rx = 0                # V(R) - expected receive sequence number
        self.acked = 0             # last sequence number the RTU acked
        self.unacked_rx = 0        # received I-frames not yet S-acked

        self._events = queue.Queue()
        self._rx_thread = None
        self._running = False
        self._lock = threading.Lock()
        self.received = []         # every ASDU received, in order

    # -- logging ----------------------------------------------------------- #

    REPEAT_FLUSH = 20     # announce a long identical run rather than stay silent

    def _screen(self, text):
        """Print to the screen. While doing so the full log is muted, because it
        is fed separately with the unfolded line - otherwise a folded screen line
        and its unfolded twin would both land in the file."""
        if self.log_sink is not None:
            with self.log_sink.muted():
                print(text, flush=True)
        else:
            print(text, flush=True)

    def log(self, direction, msg):
        if self.verbose:
            self.flush_repeats()
            line = f"[{direction}] {msg}"
            if self.log_sink is not None:
                self.log_sink.write_line(line)
            self._screen(line)

    def flush_repeats(self):
        """Emit the pending 'same thing N more times' summary, if any."""
        if self._repeats and self.verbose:
            n = self._repeats
            self._screen(f"           ... same {n} more time"
                         f"{'s' if n > 1 else ''}")
        self._repeats = 0

    def show(self, outbound, asdu, tx=None, rx=None, apdu=None):
        """Display one ASDU in the active style."""
        if not self.verbose:
            return
        if self.style == "human":
            who = "you -> RTU" if outbound else "RTU -> you"
            line = f"{who}   {asdu.describe()}"
            extra = None
        else:
            arrow = "->" if outbound else "<-"
            seq = f"I(tx={tx},rx={rx}) " if tx is not None else ""
            line = f"[{arrow}] {seq}{asdu}"
            extra = f"       hex {apdu.hex()}" if (self.style == "raw" and apdu) else None

        # Periodic data repeats forever; printing it 280 times buries everything
        # else. Collapsing folds identical consecutive lines into a count. With
        # collapse off, every frame is printed exactly as it arrives.
        # The log gets every frame, unfolded, regardless of screen folding.
        if self.log_sink is not None:
            self.log_sink.write_line(line)
            if extra:
                self.log_sink.write_line(extra)

        if self.collapse:
            key = line if self.style == "human" else self._dedupe_key(asdu, outbound)
            if key == self._last_line:
                self._repeats += 1
                if self._repeats % self.REPEAT_FLUSH == 0:
                    self._screen(f"           ... same {self._repeats} more "
                                 f"times (still arriving)")
                return
            self.flush_repeats()
            self._last_line = key
        self._screen(line)
        if extra:
            self._screen(extra)

    @staticmethod
    def _dedupe_key(asdu, outbound):
        """Frame lines carry sequence numbers, which differ every time. Compare
        the payload instead so identical frames still collapse in frames view."""
        return (outbound, asdu.type_id, asdu.cot, asdu.ca, asdu.negative,
                asdu.raw)

    def note(self, text):
        """Link-level housekeeping. Hidden in human style unless important."""
        if self.verbose and self.style != "human":
            print(f"[*] {text}", flush=True)

    # -- connection -------------------------------------------------------- #

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port),
                                             timeout=self.timeout)
        self.sock.settimeout(0.5)
        self._running = True
        self._rx_thread = threading.Thread(target=self._reader, daemon=True)
        self._rx_thread.start()
        if self.style == "human":
            print(f"connected to {self.host}:{self.port}", flush=True)
        else:
            self.log("*", f"connected to {self.host}:{self.port}")
        return self

    def close(self):
        self._running = False
        if self._rx_thread:
            self._rx_thread.join(timeout=2.0)
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    # -- raw frame I/O ----------------------------------------------------- #

    def _send(self, apdu: bytes):
        with self._lock:
            self.sock.sendall(apdu)

    # Link housekeeping worth surfacing even in human style.
    _U_HUMAN = {
        U_STARTDT_ACT: None, U_STARTDT_CON: "link ready (data transfer started)",
        U_STOPDT_ACT: None, U_STOPDT_CON: "link stopped",
        U_TESTFR_ACT: None, U_TESTFR_CON: None,
    }

    def send_u(self, ctrl1: int):
        if self.style == "human":
            text = self._U_HUMAN.get(ctrl1)
            if text:
                self.flush_repeats()
                if self.log_sink is not None:
                    self.log_sink.write_line(f"you -> RTU   {text}")
                self._screen(f"you -> RTU   {text}")
        else:
            self.log("->", U_NAMES.get(ctrl1, f"U 0x{ctrl1:02x}"))
        self._send(bytes([START, 4, ctrl1, 0, 0, 0]))

    def send_s(self):
        """Acknowledge received I-frames. Pure housekeeping - hidden in human
        style, where it only ever added noise."""
        if self.style != "human":
            self.log("->", f"S (rx={self.rx})")
        self._send(bytes([START, 4, 0x01, 0x00]) + struct.pack("<H", self.rx << 1))
        self.unacked_rx = 0

    def send_i(self, asdu: bytes):
        """Send an I-format APDU carrying `asdu`."""
        ctrl = struct.pack("<HH", self.tx << 1, self.rx << 1)
        apdu = bytes([START, len(asdu) + 4]) + ctrl + asdu
        try:
            self.show(True, ASDU.parse(asdu), self.tx, self.rx, apdu)
        except Exception:
            self.log("->", f"I(tx={self.tx},rx={self.rx}) {asdu.hex()}")
        self._send(apdu)
        self.i_sent += 1
        self.tx = (self.tx + 1) & 0x7FFF

    # -- receive pump ------------------------------------------------------ #

    def _reader(self):
        buf = b""
        while self._running:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                self.log("*", "connection closed by peer")
                break
            buf += chunk
            while len(buf) >= 2:
                if buf[0] != START:
                    buf = buf[1:]
                    continue
                length = buf[1]
                if len(buf) < length + 2:
                    break
                apdu, buf = buf[:length + 2], buf[length + 2:]
                try:
                    self._handle(apdu)
                except Exception as exc:                  # noqa: BLE001
                    self.log("!", f"parse error: {exc!r} on {apdu.hex()}")
        self._running = False

    def _handle(self, apdu: bytes):
        c1 = apdu[2]
        if c1 & 0x01 == 0:                                  # I-format
            tx, rxf = struct.unpack("<HH", apdu[2:6])
            tx >>= 1
            self.acked = rxf >> 1
            asdu = ASDU.parse(apdu[6:])
            self.rx = (tx + 1) & 0x7FFF
            self.unacked_rx += 1
            self.received.append(asdu)
            self.show(False, asdu, tx, self.acked, apdu)
            self._events.put(asdu)
            if self.unacked_rx >= self.w:
                self.send_s()
        elif c1 & 0x03 == 0x01:                             # S-format
            self.acked = struct.unpack("<H", apdu[4:6])[0] >> 1
            if self.style != "human":
                self.log("<-", f"S (rx={self.acked})")
        else:                                               # U-format
            if self.style == "human":
                text = self._U_HUMAN.get(c1)
                if text:
                    self.flush_repeats()
                    if self.log_sink is not None:
                        self.log_sink.write_line(f"RTU -> you   {text}")
                    self._screen(f"RTU -> you   {text}")
            else:
                self.log("<-", U_NAMES.get(c1, f"U 0x{c1:02x}"))
            if c1 == U_TESTFR_ACT:
                self.send_u(U_TESTFR_CON)
            self._events.put(("U", c1))

    # -- waiting ----------------------------------------------------------- #

    def wait_for(self, type_id=None, cot=None, ioa=None, timeout=5.0):
        """Block until a matching ASDU arrives; return it or None on timeout."""
        deadline = time.monotonic() + timeout
        pending = []
        result = None
        while time.monotonic() < deadline:
            try:
                item = self._events.get(timeout=max(0.05, deadline - time.monotonic()))
            except queue.Empty:
                break
            if not isinstance(item, ASDU):
                continue
            if type_id is not None and item.type_id != type_id:
                pending.append(item)
                continue
            if cot is not None and item.cot != cot:
                pending.append(item)
                continue
            if ioa is not None and not any(o[0] == ioa for o in item.objects):
                pending.append(item)
                continue
            result = item
            break
        for p in pending:
            self._events.put(p)
        self.flush_repeats()
        return result

    def drain(self, seconds=1.0):
        """Collect everything that arrives for `seconds`."""
        out = []
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                item = self._events.get(timeout=deadline - time.monotonic())
            except queue.Empty:
                break
            if isinstance(item, ASDU):
                out.append(item)
        if self.unacked_rx:
            self.send_s()
        self.flush_repeats()
        return out

    # -- session control --------------------------------------------------- #

    def start_dt(self, timeout=5.0) -> bool:
        self.send_u(U_STARTDT_ACT)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                item = self._events.get(timeout=deadline - time.monotonic())
            except queue.Empty:
                break
            if isinstance(item, tuple) and item[1] == U_STARTDT_CON:
                return True
        return False

    def stop_dt(self):
        self.send_u(U_STOPDT_ACT)

    def test_fr(self):
        self.send_u(U_TESTFR_ACT)

    # -- application services ---------------------------------------------- #

    def interrogation(self, qoi=QOI_STATION, ca=0xFFFF, wait=3.0):
        """C_IC_NA_1 station interrogation. Returns collected ASDUs."""
        self.send_i(ASDU.build(C_IC_NA_1, COT_ACT, ca, 0, bytes([qoi]), oa=self.oa))
        self.wait_for(C_IC_NA_1, COT_ACTCON, timeout=wait)
        data = self.drain(wait)
        return data

    def counter_interrogation(self, qcc=5, ca=0xFFFF, wait=3.0):
        self.send_i(ASDU.build(C_CI_NA_1, COT_ACT, ca, 0, bytes([qcc]), oa=self.oa))
        self.wait_for(C_CI_NA_1, COT_ACTCON, timeout=wait)
        return self.drain(wait)

    def read(self, ioa, ca=None, wait=3.0):
        """C_RD_NA_1 read a single information object."""
        ca = self.ca if ca is None else ca
        self.send_i(ASDU.build(C_RD_NA_1, 5, ca, ioa, b"", oa=self.oa))
        return self.drain(wait)

    def clock_sync(self, when=None, ca=0xFFFF, wait=3.0):
        """C_CS_NA_1 clock synchronisation."""
        self.send_i(ASDU.build(C_CS_NA_1, COT_ACT, ca, 0,
                               cp56time2a(when), oa=self.oa))
        return self.wait_for(C_CS_NA_1, COT_ACTCON, timeout=wait)

    def single_command(self, ioa, on=True, ca=None, select=True, qu=0, wait=3.0):
        """C_SC_NA_1. select=True performs the observed select-before-operate
        pair; select=False sends a direct execute only."""
        ca = self.ca if ca is None else ca
        scs = 1 if on else 0
        qu_bits = (qu & 0x1F) << 2
        results = []
        if select:
            sco = 0x80 | qu_bits | scs
            self.send_i(ASDU.build(C_SC_NA_1, COT_ACT, ca, ioa,
                                   bytes([sco]), oa=self.oa))
            con = self.wait_for(C_SC_NA_1, COT_ACTCON, ioa=ioa, timeout=wait)
            results.append(con)
            if con is None:
                self.log("!", f"no select actcon for IOA {ioa}")
                return results
            if con.negative:
                # This RTU sends a bare negative confirmation first and the real
                # reason (e.g. COT 44 "type not implemented") in a second frame.
                # Collect it so the caller can report why, not just that.
                extra = self.wait_for(C_SC_NA_1, ioa=ioa, timeout=0.6)
                while extra is not None:
                    results.append(extra)
                    extra = self.wait_for(C_SC_NA_1, ioa=ioa, timeout=0.4)
                return results
        sco = qu_bits | scs
        self.send_i(ASDU.build(C_SC_NA_1, COT_ACT, ca, ioa,
                               bytes([sco]), oa=self.oa))
        results.append(self.wait_for(C_SC_NA_1, COT_ACTCON, ioa=ioa, timeout=wait))
        results.append(self.wait_for(C_SC_NA_1, COT_ACTTERM, ioa=ioa, timeout=wait))
        return results

    def double_command(self, ioa, dcs=2, ca=None, select=True, qu=0, wait=3.0):
        """C_DC_NA_1. dcs: 1=OFF, 2=ON."""
        ca = self.ca if ca is None else ca
        qu_bits = (qu & 0x1F) << 2
        out = []
        if select:
            self.send_i(ASDU.build(C_DC_NA_1, COT_ACT, ca, ioa,
                                   bytes([0x80 | qu_bits | (dcs & 3)]), oa=self.oa))
            out.append(self.wait_for(C_DC_NA_1, COT_ACTCON, ioa=ioa, timeout=wait))
        self.send_i(ASDU.build(C_DC_NA_1, COT_ACT, ca, ioa,
                               bytes([qu_bits | (dcs & 3)]), oa=self.oa))
        out.append(self.wait_for(C_DC_NA_1, COT_ACTCON, ioa=ioa, timeout=wait))
        out.append(self.wait_for(C_DC_NA_1, COT_ACTTERM, ioa=ioa, timeout=wait))
        return out

    def setpoint_float(self, ioa, value, ca=None, qos=0, wait=3.0):
        """C_SE_NC_1 short-float setpoint."""
        ca = self.ca if ca is None else ca
        payload = struct.pack("<f", float(value)) + bytes([qos & 0xFF])
        self.send_i(ASDU.build(C_SE_NC_1, COT_ACT, ca, ioa, payload, oa=self.oa))
        return self.wait_for(C_SE_NC_1, COT_ACTCON, ioa=ioa, timeout=wait)

    def raw_asdu(self, type_id, cot, ca, ioa, payload=b"", sq=False, count=None,
                 wait=3.0):
        """Send an arbitrary ASDU - used for the private TypeId=104 exchange."""
        self.send_i(ASDU.build(type_id, cot, ca, ioa, payload, sq=sq,
                               count=count, oa=self.oa))
        return self.drain(wait)


# --------------------------------------------------------------------------- #
# Replays of the captured sessions
# --------------------------------------------------------------------------- #

# Session A: private TypeId 104, IOA 266500, 8-byte payload.
PCAP_PRIV_TYPE = 104
PCAP_PRIV_IOA = 266500                       # 0x041104
PCAP_PRIV_PAYLOAD = bytes.fromhex("bb322456bda87cee")

# Session B: the two commanded outputs.
PCAP_CMD_IOAS = (1101, 1201)
PCAP_CA = 17


def replay_session_a(host, port, ca=PCAP_CA, payload=PCAP_PRIV_PAYLOAD,
                     ioa=PCAP_PRIV_IOA, verbose=True):
    """STARTDT + private TypeId=104 ASDU, exactly as HMI port 47504 did."""
    with IEC104Client(host, port, ca=ca, verbose=verbose) as c:
        if not c.start_dt():
            print("[!] no STARTDT con", file=sys.stderr)
            return c
        c.raw_asdu(PCAP_PRIV_TYPE, COT_ACT, ca, ioa, payload, wait=3.0)
        c.drain(1.0)
        return c


def replay_session_b(host, port, ca=PCAP_CA, ioas=PCAP_CMD_IOAS, on=True,
                     verbose=True):
    """Full HMI sequence from port 47510: interrogation, clock sync,
    select-before-operate on each IOA."""
    with IEC104Client(host, port, ca=ca, verbose=verbose) as c:
        if not c.start_dt():
            print("[!] no STARTDT con", file=sys.stderr)
            return c
        print("--- general interrogation ---")
        c.interrogation(QOI_STATION, ca=0xFFFF)
        print("--- clock sync ---")
        c.clock_sync(ca=0xFFFF)
        for ioa in ioas:
            print(f"--- single command IOA {ioa} -> {'ON' if on else 'OFF'} ---")
            c.single_command(ioa, on=on, ca=ca, select=True)
        c.drain(1.0)
        if c.unacked_rx:
            c.send_s()
        return c


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _hexarg(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", "").replace("0x", ""))


def main(argv=None):
    p = argparse.ArgumentParser(
        description="IEC 60870-5-104 HMI client (reconstructed from backup.pcap)")
    p.add_argument("host")
    p.add_argument("port", nargs="?", type=int, default=2404)
    p.add_argument("--ca", type=lambda x: int(x, 0), default=PCAP_CA,
                   help="common ASDU address (default 17, as in pcap)")
    p.add_argument("--oa", type=lambda x: int(x, 0), default=0)
    p.add_argument("-q", "--quiet", action="store_true")

    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("replay", help="run both captured sessions in order")
    sub.add_parser("session-a", help="STARTDT + private TypeId=104 ASDU")
    sb = sub.add_parser("session-b", help="interrogation + clocksync + commands")
    sb.add_argument("--off", action="store_true", help="command OFF instead of ON")

    si = sub.add_parser("interrogate", help="C_IC_NA_1 station interrogation")
    si.add_argument("--qoi", type=lambda x: int(x, 0), default=QOI_STATION)
    si.add_argument("--bcast", action="store_true",
                    help="use CA=0xFFFF (as the pcap did)")
    si.add_argument("--wait", type=float, default=5.0)

    sc = sub.add_parser("clocksync", help="C_CS_NA_1")
    sc.add_argument("--bcast", action="store_true")

    ss = sub.add_parser("cmd", help="C_SC_NA_1 single command")
    ss.add_argument("ioa", type=lambda x: int(x, 0))
    ss.add_argument("state", choices=["on", "off"])
    ss.add_argument("--direct", action="store_true",
                    help="direct execute (skip select)")
    ss.add_argument("--qu", type=int, default=0)

    sd = sub.add_parser("dcmd", help="C_DC_NA_1 double command")
    sd.add_argument("ioa", type=lambda x: int(x, 0))
    sd.add_argument("state", choices=["on", "off"])
    sd.add_argument("--direct", action="store_true")

    sp = sub.add_parser("setpoint", help="C_SE_NC_1 short-float setpoint")
    sp.add_argument("ioa", type=lambda x: int(x, 0))
    sp.add_argument("value", type=float)

    sr = sub.add_parser("read", help="C_RD_NA_1 read one IOA")
    sr.add_argument("ioa", type=lambda x: int(x, 0))

    sw = sub.add_parser("monitor", help="STARTDT then listen for spontaneous data")
    sw.add_argument("--seconds", type=float, default=30.0)
    sw.add_argument("--interrogate", action="store_true")

    sx = sub.add_parser("raw", help="send an arbitrary ASDU")
    sx.add_argument("type_id", type=lambda x: int(x, 0))
    sx.add_argument("ioa", type=lambda x: int(x, 0))
    sx.add_argument("payload", nargs="?", default="", type=_hexarg)
    sx.add_argument("--cot", type=lambda x: int(x, 0), default=COT_ACT)
    sx.add_argument("--wait", type=float, default=3.0)

    a = p.parse_args(argv)
    verbose = not a.quiet

    if a.cmd == "replay":
        print("=== session A (private TypeId 104) ===")
        replay_session_a(a.host, a.port, ca=a.ca, verbose=verbose)
        print("\n=== session B (interrogation / clocksync / commands) ===")
        replay_session_b(a.host, a.port, ca=a.ca, verbose=verbose)
        return 0
    if a.cmd == "session-a":
        replay_session_a(a.host, a.port, ca=a.ca, verbose=verbose)
        return 0
    if a.cmd == "session-b":
        replay_session_b(a.host, a.port, ca=a.ca, on=not a.off, verbose=verbose)
        return 0

    with IEC104Client(a.host, a.port, ca=a.ca, oa=a.oa, verbose=verbose) as c:
        if not c.start_dt():
            print("[!] no STARTDT con", file=sys.stderr)
            return 1
        if a.cmd == "interrogate":
            c.interrogation(a.qoi, ca=0xFFFF if a.bcast else a.ca, wait=a.wait)
        elif a.cmd == "clocksync":
            c.clock_sync(ca=0xFFFF if a.bcast else a.ca)
        elif a.cmd == "cmd":
            c.single_command(a.ioa, on=(a.state == "on"),
                             select=not a.direct, qu=a.qu)
        elif a.cmd == "dcmd":
            c.double_command(a.ioa, dcs=2 if a.state == "on" else 1,
                             select=not a.direct)
        elif a.cmd == "setpoint":
            c.setpoint_float(a.ioa, a.value)
        elif a.cmd == "read":
            c.read(a.ioa)
        elif a.cmd == "monitor":
            if a.interrogate:
                c.interrogation(QOI_STATION, ca=0xFFFF)
            c.drain(a.seconds)
        elif a.cmd == "raw":
            c.raw_asdu(a.type_id, a.cot, a.ca, a.ioa, a.payload, wait=a.wait)
        c.drain(1.0)
        if c.unacked_rx:
            c.send_s()
    return 0


if __name__ == "__main__":
    sys.exit(main())
