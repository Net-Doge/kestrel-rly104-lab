# IEC 60870-5-104 toolkit — help

Two files, no third-party dependencies (Python 3.10+):

| File | Purpose |
|---|---|
| `iec104_client.py` | Protocol library + one-shot CLI. Import it or run it. |
| `rtu_shell.py` | Interactive shell built on the library. Use this for exploration. |
| `rtu_tui.py` | Split-screen UI for the shell. Loaded automatically. |

Everything here was reconstructed from `backup.pcap` (HMI `172.17.0.1` → RTU `172.17.0.5:2404`).

---

## 1. What was in the capture

Link parameters (the defaults in both tools):

```
Common ASDU address (CA) : 17
Originator address (OA)  : 0
COT field                : 2 octets (COT + OA)
CA field                 : 2 octets
IOA field                : 3 octets
TCP port                 : 2404
```

Two HMI sessions:

**Session A** — source port 47504

```
-> STARTDT act
<- STARTDT con
-> I  TypeId=104  COT=act  CA=17  IOA=266500  payload bb322456bda87cee
<- I  M_ME_NC_1(13) SQ=1 n=4  COT=per/cyc  IOA 2101..2104
```

No interrogation. That single private ASDU alone made the RTU push measurements.

**Session B** — source port 47510

```
-> STARTDT act                                         <- STARTDT con
-> C_IC_NA_1 (100) COT=act CA=0xFFFF IOA=0 QOI=20      <- actcon, data (COT=inrogen), actterm
-> C_CS_NA_1 (103) COT=act CA=0xFFFF IOA=0 CP56Time2a  <- actcon
-> C_SC_NA_1 (45)  CA=17 IOA=1101 SCO=0x81  (select ON) <- actcon
-> C_SC_NA_1 (45)  CA=17 IOA=1101 SCO=0x01  (exec ON)   <- actcon, actterm
-> C_SC_NA_1 (45)  CA=17 IOA=1201 SCO=0x81 / 0x01       <- actcon, actcon, actterm
-> S-format ack (rx=10)
```

### Point list

| IOA | Type | Notes |
|---|---|---|
| 2101 | M_ME_NC_1 float | 11.24 (per/cyc), 11.23 (inrogen) |
| 2102 | M_ME_NC_1 float | 3.72 / 3.78 |
| 2103 | M_ME_NC_1 float | 13.5 / 13.8 |
| 2104 | M_ME_NC_1 float | 67.0 / 68.1 |
| 1101 | C_SC_NA_1 output | HMI selected then closed (ON) |
| 1201 | C_SC_NA_1 output | HMI selected then closed (ON) |
| 266500 | TypeId 104, private | `0x041104`, payload `bb322456bda87cee` |

**On TypeId 104.** Standard C_TS_NA_1 (test command) carries a 2-octet fixed test
pattern and the RTU is meant to mirror it back. Here it carries **8 octets** and the
RTU answers with measurement data instead. Non-standard — most likely this RTU's
auth token or unlock handshake. If it is a token it may be replay-checked, so treat a
failure as informative, not as a bug in the client.

**Command safety.** `1101` and `1201` are outputs, not readings. `sc 1101 on` performs
a real actuation on the target. Recon first: `priv`, `ic --bcast`, `mon`.

---

## 2. `rtu_shell.py` — interactive

```
./rtu_shell.py 154.57.164.71                  # connect + STARTDT on startup
./rtu_shell.py 154.57.164.71 2404 --ca 17
./rtu_shell.py <host> --no-open               # start disconnected
./rtu_shell.py <host> --plain                 # plain prompt, no split screen
```

### How traffic is displayed

Default is **human** view: plain language, link housekeeping hidden, and runs of
identical frames collapsed. Periodic data repeats forever, and 280 identical
lines bury everything that matters.

```
connected to 154.57.164.71:2404
RTU -> you   link ready (data transfer started)
you -> RTU   read all points (general interrogation)
RTU -> you   acknowledged: read all points (general interrogation)
RTU -> you   values (from interrogation):  2101=11.24   2102=3.72   2103=13.5   2104=67
           ... same 34 more times
you -> RTU   SELECT CLOSE output 1101
RTU -> you   confirmed SELECT CLOSE output 1101
you -> RTU   EXECUTE CLOSE output 1101
RTU -> you   operation finished: output 1101
[ok] CLOSE output 1101: the RTU confirmed it and reported the operation finished
```

Errors read as sentences, and the RTU's *specific* reason outranks its generic
refusal (this RTU sends a bare negative first, the real cause in a later frame):

```
RTU -> you   REFUSED: SELECT CLOSE output 2103  (RTU said no)
RTU -> you   ERROR: this RTU does not implement that message type (C_SC_NA_1)
[!] CLOSE output 2103: this RTU does not implement that message type
```

Switch views any time — nothing is lost, it is only formatting:

| | Shows |
|---|---|
| `view human` | the above. Default |
| `view frames` | one line per APDU with TypeIds, COTs, sequence numbers, SCO bits |
| `view raw` | frames plus the hex of every APDU |

`--view frames` / `--view raw` at launch does the same. Use `frames` when you
need the wire detail — `probe`, sequence-number problems, byte-level work.

#### Full output vs folded

Repeat folding is a separate switch from the view, and applies to all three:

| | Effect |
|---|---|
| `full off` | *(default)* runs of identical lines collapse to `... same N more times` |
| `full on` | every frame is printed as it arrives, repeats included |
| `--full` | same, set at launch |
| `full` | show the current setting |

In `frames`/`raw` view the folding compares the ASDU payload rather than the
whole line, since sequence numbers differ on every frame and would otherwise
defeat it. A long identical run still reports progress every 20 frames
(`... same 20 more times (still arriving)`), so a frozen stream never looks like
a hung session. Turn folding off when you need exact frame counts or timing —
counting how many periodic updates arrive between two events, for instance.

### The screen

On a real terminal you get a split screen, so the RTU's asynchronous frames can never
overwrite what you are typing:

```
+----------------------------------------------------------------+
| scrolling output pane - frames, replies, help                  |
| ...                                                            |
+----------------------------------------------------------------+
| 154.57.164.71:2404  ca=17 oa=0  up V(S)=3 V(R)=6 rx=6      ... |   <- status
| rtu> operate 1101 clo                                          |   <- pinned prompt
+----------------------------------------------------------------+
```

The status bar shows the target, CA/OA, link state and live sequence counters, and
switches to `-- MORE --` while you are scrolled back.

**Long output pages instead of scrolling past.** When a command prints more than one
screenful — `help`, a large interrogation — the view parks at the **start** of that
output and the status bar shows `-- MORE --`. Press space or PgDn to advance; `End`
jumps back to live.

#### Scrolling

A curses screen replaces the terminal's own scrollback, so scrolling happens
inside the app:

| Key / command | Action |
|---|---|
| PgUp / PgDn | scroll a screen — works at any time |
| Up / Down | scroll a line **while `-- MORE --` is showing**; otherwise they walk command history |
| Space | page down while `-- MORE --` is showing |
| Shift-Up / Shift-Down | scroll a single line |
| Home / End (empty input line) | oldest output / back to live |
| `scroll up\|down\|top\|end [n]` | the same as a command, if a key is unavailable |
| `mouse on` | enable wheel scrolling (**off by default**) |

Both modern SGR and legacy X10 mouse reporting are decoded, and cursor keys are
accepted in both CSI (`\e[A`) and SS3 (`\eOA`) form, so unrecognised sequences
never get typed into the input line as literal `[A`.

#### Copying text out

**Mouse capture is off by default precisely so that selecting and copying with the
mouse keeps working.** If you turn it on with `mouse on`, the app grabs click-drag —
hold **Shift** to select anyway, or run `mouse off`.

| Command | Does |
|---|---|
| `save [file] [n]` | write the transcript to a file (default `./rtu_session.log`) |
| `copy [n]` | last n lines (default 40) to the clipboard via wl-copy / xclip / xsel / pbcopy |
| `--plain` at launch | normal prompt with native terminal scrollback and selection |

#### Editing keys

| Key | Action |
|---|---|
| Enter | run the command |
| Tab | complete a command name |
| Up / Down | command history, when not scrolled back (persisted in `~/.rtu_shell_history`) |
| Left / Right, Ctrl-A / Ctrl-E | move the cursor |
| Backspace / Del, Ctrl-W, Ctrl-U, Ctrl-K | edit |
| Ctrl-L | force redraw |
| Ctrl-C | interrupt a running command |
| Ctrl-D | quit on an empty line |

Frames are colour-coded: outbound `[->]` cyan, inbound `[<-]` green, problems `[!]`
red, `[ok]` green bold. Scrollback holds 5000 lines.

`--plain` falls back to a readline prompt; async output there erases the input line,
prints, then redraws your prompt and buffer, so it stays readable too. Script modes
(`-x`) always run plain.

Sequence numbers, S-acks (every 8 received I-frames) and TESTFR-act auto-reply are
handled automatically in both modes.

### Link control

| Command | Effect |
|---|---|
| `open [host] [port]` | TCP connect, then STARTDT act |
| `close` | STOPDT act, then close socket |
| `start` / `stop` | STARTDT act / STOPDT act |
| `test` | TESTFR act (keepalive) |
| `ack` | send an S-format acknowledgement now |
| `ca [addr]` / `oa [addr]` | show or set the session default CA / OA |
| `quiet on\|off` | toggle per-frame logging |
| `state` | V(S), V(R), peer-acked, ASDU count |

### Reading

| Command | ASDU |
|---|---|
| `ic [qoi]` | C_IC_NA_1 interrogation, default QOI=20 (station) |
| `ci [qcc]` | C_CI_NA_1 counter interrogation, default QCC=5 |
| `read <ioa>` | C_RD_NA_1 read request |
| `mon [seconds]` | listen only, default 15s, Ctrl-C to cut short |
| `log [n]` | reprint last n received ASDUs, default 20 |
| `points` | the IOA table above |
| `types [filter]` | known TypeId numbers, optionally filtered |

### Opening and closing outputs

This is the part you actuate plant with. Also available in the shell as
`help control`.

#### Vocabulary — the words are backwards from programmer intuition

| Power-system word | Means | SCS/DCS | Also spelled |
|---|---|---|---|
| **CLOSE** | contacts closed, circuit energised, current flows | SCS=1, DCS=2 | `on`, `1`, `true`, `energise` |
| **OPEN** | contacts apart, circuit dead, no current | SCS=0, DCS=1 | `off`, `0`, `false`, `trip` |
| **TRIP** | an open, usually protective | SCS=0 | — |

> **Name collision.** The shell's own `open` and `close` commands manage the
> **TCP session**, not breakers. Both are guarded: `close 1101` refuses and
> points you at `operate`. Use `operate <ioa> close` for plant.

#### Commands

| Command | Does |
|---|---|
| `operate <ioa> open\|close` | the main verb. Select-before-operate, confirmation prompt, decoded outcome summary |
| `trip <ioa>` | shorthand for `operate <ioa> open` |
| `verify [ioa ...]` | re-interrogate and table current values, to confirm an operation landed |
| `sc <ioa> on\|off\|open\|close` | low-level C_SC_NA_1 — no prompt, no summary |
| `dc <ioa> on\|off\|open\|close` | low-level C_DC_NA_1 |
| `sp <ioa> <float>` | C_SE_NC_1 short-float setpoint |

Flags on `operate` / `trip`:

```
--direct, -d      execute only, skip the select step
--double, --dc    use C_DC_NA_1 instead of C_SC_NA_1
--pulse P         QU: short | long | persist | none
--qu N            QU as a raw number
--verify, -v      re-interrogate right after operating
--yes, -y         skip the confirmation prompt
--ca N / --bcast  address override (never broadcast a command)
```

#### Select-before-operate

Two ASDUs per operation. This is what the captured HMI did, and the default here.

```
1. SELECT   SCO bit7 (S/E) = 1     "reserve this point, is it allowed?"
   <- actcon positive   point reserved, interlocks clear
   <- actcon NEGATIVE   refused. Nothing operated. Stop.

2. EXECUTE  SCO bit7 (S/E) = 0     "now do it"
   <- actcon            accepted
   <- actterm           RTU says the operation finished
```

```
operate 1101 close             # select, then execute  (the captured behaviour)
operate 1101 close --direct    # execute only, single ASDU
```

Some RTUs accept only SBO, others only direct execute. If nothing comes back,
**try the other mode** before concluding the point is wrong.

#### The SCO / DCO qualifier byte

C_SC_NA_1 (TypeId 45), one octet:

```
bit  7     S/E   1 = select, 0 = execute
bits 6..2  QU    0 none, 1 short pulse, 2 long pulse, 3 persistent output
bit  1      -    must be 0
bit  0     SCS   1 = close, 0 = open

0x81 = select + close       0x01 = execute + close      <- both in backup.pcap
0x80 = select + open        0x00 = execute + open
```

C_DC_NA_1 (TypeId 46) replaces SCS with two bits:

```
DCS 0 = not permitted    1 = OPEN    2 = CLOSE    3 = not permitted
```

Double commands are the safer real-world form for breakers — `0` and `3` are
invalid, so one flipped bit cannot read as a valid operation. Try
`operate 1101 close --double` if single commands get refused.

Pulse duration via QU tells the RTU how long to hold the coil:

```
operate 1101 close --pulse short     # QU=1 momentary
operate 1101 close --pulse long      # QU=2
operate 1101 close --pulse persist   # QU=3 latched until commanded back
operate 1101 close --qu 0            # QU=0, the RTU's configured default
```

The capture used QU=0 on both points, so **QU=0 is the known-good value here**.

#### Confirming it actually happened

`actterm` means the RTU finished its command handling. It does **not** prove the
breaker physically moved. Real confirmation is a status point changing:

```
operate 1101 close --verify     # operate, then re-interrogate
verify                          # interrogate and table everything
verify 1101 2101                # only these IOAs
mon 30                          # watch for a spontaneous (COT=3) change
```

Honest limitation: `backup.pcap` contains **no status point for 1101 or 1201**,
only the M_ME_NC_1 floats at 2101-2104. This RTU may not report their position
in a station interrogation. Watch the floats instead — if they are line
measurements, closing a breaker should move them. Snapshot with `verify` before
operating so you have something to compare.

#### Failure modes

| Symptom | Meaning |
|---|---|
| no reply at all | wrong CA, or STOPDT, or point not commandable. Check `state`, re-`start`, try `--ca` |
| NEGATIVE actcon | RTU refused: interlock, not selected first, invalid QU/DCS, insufficient authority. Try `--double` or SBO instead of `--direct` |
| COT 47 `unknown object address` | IOA does not exist on that CA |
| COT 46 `unknown asdu address` | CA is wrong — `ic --bcast` to discover the real one |
| COT 45 `unknown cause` | RTU rejects COT=6 on this type |
| COT 44 `unknown type` | RTU does not implement TypeId 45/46 at all |

All decoded by name in the `[<-]` frame log.

`operate` and `trip` prompt for confirmation on a terminal; `--yes` skips it,
and it is skipped automatically under `-x` or a pipe.

### Raw / capture replay

| Command | Effect |
|---|---|
| `raw <typeid> <ioa> [hex] [--cot N] [--sq N]` | arbitrary ASDU, framing handled |
| `apdu <hex>` | fully hand-built APDU bytes, e.g. `apdu 680407000000` |
| `priv [hex]` | the capture's TypeId=104 / IOA 266500 ASDU; default payload `bb322456bda87cee` |
| `replay` | whole session-B sequence: ic, clock, then 1101 and 1201 ON |

### Modifiers

Accepted by any command that carries an ASDU:

```
--ca N       override common ASDU address for this command only
--bcast      CA=0xFFFF   (what the captured HMI used for ic and clock)
--direct     sc/dc only: skip select, execute immediately
--qu N       sc only: qualifier of command (0 = no additional definition)
--cot N      raw only: cause of transmission, default 6 (act)
--sq N       raw only: sequence-of-objects addressing with N elements
```

### Aliases

`cmd`→`sc`, `connect`→`open`, `interrogate`→`ic`, `clocksync`→`clock`,
`setpoint`→`sp`, `monitor`→`mon`, `q`→`quit`, `?`→`help`.

`help` prints the same page inside the shell; `help <command>` details one.

---

## 3. `iec104_client.py` — one-shot CLI

For scripted single actions, no prompt.

```bash
python3 iec104_client.py <host> [port] <subcommand> [...]
```

| Subcommand | Does |
|---|---|
| `replay` | both captured sessions, A then B, each on its own connection |
| `session-a` | STARTDT + the private TypeId=104 ASDU |
| `session-b [--off]` | interrogation, clock sync, then commands on 1101 and 1201 |
| `interrogate [--qoi N] [--bcast] [--wait S]` | C_IC_NA_1 |
| `clocksync [--bcast]` | C_CS_NA_1 |
| `cmd <ioa> on\|off [--direct] [--qu N]` | C_SC_NA_1 |
| `dcmd <ioa> on\|off [--direct]` | C_DC_NA_1 |
| `setpoint <ioa> <value>` | C_SE_NC_1 |
| `read <ioa>` | C_RD_NA_1 |
| `monitor [--seconds S] [--interrogate]` | listen |
| `raw <typeid> <ioa> [hex] [--cot N]` | arbitrary ASDU |

Global flags: `--ca` (default 17), `--oa` (default 0), `-q/--quiet`.

```bash
python3 iec104_client.py 154.57.164.71 replay
python3 iec104_client.py 154.57.164.71 raw 104 266500 bb322456bda87cee
python3 iec104_client.py 154.57.164.71 monitor --seconds 60 --interrogate
```

---

## 4. Library use

```python
from iec104_client import IEC104Client, ASDU, COT_ACT, cp56time2a

with IEC104Client("154.57.164.71", 2404, ca=17) as c:
    c.start_dt()

    # the private unlock ASDU, then whatever the RTU pushes
    c.raw_asdu(104, COT_ACT, 17, 266500, bytes.fromhex("bb322456bda87cee"))

    for asdu in c.interrogation(qoi=20, ca=0xFFFF):
        for ioa, elem in asdu.objects:
            print(ioa, asdu.value_str(elem))

    c.single_command(1101, on=True)          # select then execute
    c.single_command(1201, on=True, select=False)   # direct execute
```

Useful members:

- `send_i(asdu_bytes)`, `send_u(ctrl1)`, `send_s()` — frame-level sends.
- `ASDU.build(type_id, cot, ca, ioa, payload, sq=, count=, oa=)` — bytes out.
- `ASDU.parse(data)` → object with `.type_id .cot .ca .oa .sq .negative .test
  .objects .raw`; `str()` on it gives the decoded one-liner, `value_str(elem)`
  decodes one element.
- `wait_for(type_id=, cot=, ioa=, timeout=)` → matching ASDU or `None`.
- `drain(seconds)` → list of everything received in that window.
- `c.received` — every ASDU seen, in order.
- `cp56time2a(datetime)` / `parse_cp56time2a(bytes)`.

Decoders exist for TypeIds 1, 3, 9, 11, 13, 30, 36, 45, 46, 50, 100, 103. Unknown
and private types keep their first IOA and expose the remaining body as raw bytes —
which is how TypeId 104's 8-byte payload survives intact.

---

## 5. Verification

- `ASDU.parse` re-decodes all 23 APDUs of `backup.pcap` identically to `tshark -V`.
- Full `replay` was run against a mock RTU built from the capture's server-side
  bytes; tx/rx sequencing and S-ack timing matched the capture.

Re-check the decoder against the capture at any time:

```bash
tshark -r backup.pcap -Y "tcp.len>0" -T fields -e tcp.payload |
while read h; do python3 -c "
import sys,struct; sys.path.insert(0,'.')
from iec104_client import ASDU
b=bytes.fromhex('$h')
print(ASDU.parse(b[6:]) if b[2]&1==0 else 'supervisory')"; done
```
