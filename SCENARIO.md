# Exercise: EAST FEEDER TRANSFER

A red-vs-blue exercise on an IEC 60870-5-104 substation RTU. Runs in about two
hours with three roles: **white cell**, **red**, **blue**.

## Situation

Kestrel Energy's east feeder is fed through 52-M. A second supply is available
through the tie breaker 52-T, normally open. P-43, a 3.7 MW transfer pump, is the
load. A sync-check interlock holds 52-T open because the two supplies sit about
15° apart — closing a tie between out-of-phase sources slams them together and
torques every rotating machine on the bus.

Maintenance access to the RTU is authorised by a proof carried in a private
protocol message. An engineer's packet capture from a maintenance visit weeks ago
has leaked.

**Red wins** by tripping the feeder. **Blue wins** by detecting it and proving
what happened.

---

## Roles at a glance

| | Objective | Wins by |
|---|---|---|
| White cell | Keep it running, judge it | Both teams get a clean, resettable environment |
| Red | Trip the east feeder | `feeder_trip: true` on the HMI |
| Blue | Detect, characterise, contain | A timeline naming the credential, the IOAs and the operator action |

---

# White cell / network team

## Build

Two VMs on a routed network with a firewall between them.

| VM | Runs | Listens |
|---|---|---|
| **VM1** — substation | RTU + HMI | `2404/tcp`, `8080/tcp` |
| **VM2** — jump box | engineering console | `8081/tcp` |

```bash
# VM1
docker compose -f deploy/docker-compose.rtu.yml up -d --build

# VM2
docker compose -f deploy/docker-compose.jumpbox.yml up -d --build
```

Full steps and troubleshooting: [deploy/SETUP.md](deploy/SETUP.md).
Air-gapped range: `./package-offline.sh`, then copy one archive to each VM.

## Firewall

| Source | Destination | Port | Notes |
|---|---|---|---|
| VM2 | VM1 | `2404/tcp` | mandatory — the control channel |
| VM2 | VM1 | `8080/tcp` | optional; omit it to force red onto the protocol instead of the web page |
| red team | VM2 | `8081/tcp` | the console |
| blue team | VM1 | ssh / span | for packet capture |

Nothing else reaches VM1. That single rule is what makes the jump box worth
compromising.

## What each team starts with

**Red** gets: the console URL, and `artifacts/backup.pcap`. Nothing else — not
the RTU's address, not the point list. Hand over `docs/client-reference.md` only
if they stall past the first 30 minutes.

**Blue** gets: shell on VM1, ability to capture traffic, the HMI URL. Do **not**
give them the pcap or the point list; identifying the addressing is part of the
job.

## Verify before you start

```bash
curl -s http://<VM1>:8080/status.json | grep -E 'feeder_trip|tie_breaker|interlock'
```

Baseline is `main_breaker_closed: true`, `tie_breaker_closed: false`,
`transfer_pump_running: true`, `interlock_bypass: false`, `feeder_trip: false`.

## Reset between rounds

```bash
docker compose -f deploy/docker-compose.rtu.yml restart   # on VM1
```

Takes about five seconds. The sync angle is randomised per boot, so each round
differs slightly.

## Answer key

The intended chain, for judging:

1. Pull the proof `bb322456bda87cee` from the pcap — a private TypeId 104 ASDU
   at IOA 266500.
2. Replay it as the **first message of a fresh TCP connection**. Later in a
   session it is always rejected; this is the step teams get stuck on.
3. Within ~28 s, close **1101** (interlock bypass).
4. Close **1201** (52-T) while the pump is still loaded.

```
priv ; sc 1101 close ; sc 1201 close
```

Result: `TRIP: 52-T closed out of phase while transfer pump was loaded`, 52-M
opens, bus to 0 kV, and a CRIT alarm instructing the shift to inspect P-43.

The near-miss worth discussing in the hotwash: shedding the pump first
(`sc 1301 open`) makes the same close complete **cleanly**, with no trip and the
transformer cooling. Same commands, different order, no incident.

## Injects, if a team stalls

| Time | To | Inject |
|---|---|---|
| T+20 | red | "Maintenance says the console needs the relay's address — it's on the substation VLAN." |
| T+40 | red | "That proof only ever works at the start of a session." |
| T+30 | blue | "Operations report an interlock bypass alarm they didn't action." |
| T+60 | blue | "Management wants the source address in ten minutes." |

---

# Red team

## Objective

Trip the east feeder. Success is `feeder_trip: true` on the HMI.

## Rules of engagement

- Targets: the RTU and the jump box only.
- The console at `http://<VM2>:8081/` is authorised infrastructure — use it.
- No attacking blue's tooling, no host destruction, no changes outside the lab.
- Announce the moment you believe you have tripped it. Do not repeat it; one trip
  is the objective, and blue needs a clean timeline.

## What you have

`backup.pcap` — a capture of a legitimate maintenance session, and the console.
The relay's address is not given to you.

## Suggested progression

1. **Find the RTU.** It answers a STARTDT with a STARTDT con on `2404`.
   `client/otscan.py <cidr>` identifies stations by that behaviour.
2. **Read the capture.** Wireshark decodes `2404` natively; on another port use
   *Decode As → IEC 60870-5-104*. Look at what the engineer sent that you cannot
   yet send yourself.
3. **Get authorised.** Something in that capture is a credential. Note *where in
   the session* it appears — that detail matters.
4. **Learn what you can command.** A SELECT with the S/E bit set reserves a point
   without operating it, so it is safe to probe with.
5. **Read the refusals.** The RTU distinguishes "no such point", "wrong message
   type here", and "refused right now". Those three answers map the device.
6. **Trip the feeder.** Watch the HMI while you do it.

## Scoring

| | |
|---|---|
| RTU located and identified | 10 |
| Credential recovered from the capture | 20 |
| Authorised session established | 20 |
| Point list mapped (all four writable IOAs) | 20 |
| Feeder tripped | 30 |
| **Penalty** — noisy brute force, or trips repeated after the first | −10 each |

---

# Blue team

## Objective

Detect the intrusion, characterise it precisely, and contain it. You are not
expected to prevent the first attempt — you are expected to prove what happened.

## What you have

Shell on VM1, the HMI, and the ability to capture traffic. No point list; work it
out.

## Deliverables

1. **Alert** — raised before or within a minute of the trip.
2. **Timeline** — first contact, authorisation, each command, the trip, with
   timestamps and the source address.
3. **Characterisation** — which IOAs were operated, what each does, and which
   single message made the rest possible.
4. **Containment** — a firewall change that stops a repeat, and a statement of
   what it costs operationally.
5. **Recommendation** — one protocol-level fix and one plant-level fix.

## Where to look

Capture the control channel:

```bash
sudo tcpdump -i any -s0 -w /tmp/iec104.pcap 'tcp port 2404'
```

The RTU's own state and event log:

```bash
watch -n1 'curl -s http://localhost:8080/status.json | python3 -m json.tool | tail -25'
curl -s http://localhost:8080/alarms
```

`last_handoff` and `last_command` give the RTU's own words for what it accepted
and refused. The event log is the closest thing to an audit trail here — note in
your report how little there is, and what you would want instead.

## Detection notes

Three signatures, in order of value:

- **A short TCP session whose first I-frame is TypeId 104 to IOA 266500.**
  Legitimate maintenance looks like this too, so the discriminator is *who* and
  *when*, not the message itself.
- **A command to IOA 1101** — the interlock bypass. On this plant there is no
  routine reason to write it. This is the highest-value single alert available.
- **Any C_SC_NA_1 EXECUTE inside the ~28 s window after an accepted handoff.**

If you have Zeek or Suricata, note that both ship IEC-104 support; if not, the
capture plus `tshark -Y iec60870_asdu` is enough.

## Scoring

| | |
|---|---|
| Alert raised before the trip | 25 |
| Alert raised within a minute of it | 15 |
| Source address identified | 15 |
| All operated IOAs identified with function | 20 |
| Bypass named as the enabling step | 15 |
| Containment applied and justified | 15 |
| Fix recommendations, protocol and plant | 10 |
| **Penalty** — containment that also breaks legitimate operation, unnoticed | −10 |

---

## Hotwash

Twenty minutes, both teams, four questions:

1. The interlock bypass is reachable over the same protocol it protects. Where
   else does that pattern exist in your estate?
2. The credential was replayable and weeks old. What in your environment would
   accept an old one today?
3. Blue: could you have distinguished this from genuine maintenance? What
   would you have needed?
4. The RTU had the sync angle in front of it and closed anyway because a flag
   said to. Should a device be able to be told to ignore its own instrument?

Worth raising: this class of attack is not theoretical. The Aurora Generator
Test (INL, 2007) destroyed a diesel generator by out-of-phase breaker closing
over a control channel, and the Industroyer malware used in the 2016 Ukraine
grid attack carried a dedicated IEC-101/104 module for exactly this kind of
breaker manipulation. IEC-104 as standardised has no authentication at all —
the handoff in this lab is *more* than the real protocol offers, and it still
fails to a replay.
