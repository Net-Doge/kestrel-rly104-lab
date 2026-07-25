#!/usr/bin/env python3
"""
OT segment discovery — find IEC-104 RTUs, HMIs and engineering consoles.

    ./otscan.py 10.104.0.0/24
    ./otscan.py 10.104.0.0/24 --iec-ports 2404,12404 --web-ports 8080,8081,80

Identification is by behaviour, not by port number:

  * an IEC 60870-5-104 station answers STARTDT (U-format 0x07) with STARTDT con
    (0x0B), which no other protocol does by accident
  * an RTU also volunteers its common address and its points once started, so
    the scan reports both without sending a single command
  * an HMI or console is identified from its HTTP server banner and payload

Nothing here writes to a device: it starts the data flow, listens, and leaves.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import struct
import sys
import urllib.error
import urllib.request

START = 0x68


def probe_iec(host, port, timeout=2.0):
    """STARTDT and listen. Returns a dict if this speaks IEC-104."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    info = {"host": host, "port": port, "proto": "iec-60870-5-104"}
    try:
        s.settimeout(timeout)
        s.sendall(bytes([START, 4, 0x07, 0, 0, 0]))
        first = s.recv(6)
        if len(first) < 6 or first[0] != START or first[2] != 0x0B:
            return None
        # Anything volunteered next tells us the station address and points.
        s.settimeout(1.5)
        buf = b""
        try:
            for _ in range(6):
                chunk = s.recv(512)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        while len(buf) >= 2 and len(buf) >= buf[1] + 2:
            n = buf[1] + 2
            apdu, buf = buf[:n], buf[n:]
            if len(apdu) < 12 or apdu[2] & 0x01:
                continue
            a = apdu[6:]
            info["common_address"] = struct.unpack("<H", a[4:6])[0]
            info.setdefault("type_ids", set()).add(a[0])
            base = int.from_bytes(a[6:9], "little")
            info.setdefault("ioas", set()).add(base)
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    for k in ("type_ids", "ioas"):
        if k in info:
            info[k] = sorted(info[k])
    return info


def probe_http(host, port, timeout=2.0):
    url = f"http://{host}:{port}/"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            server = r.headers.get("Server", "")
            body = r.read(4096).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return None
    kind = "http"
    if "KestrelHMI" in server or "Feeder Guard" in body:
        kind = "rtu-hmi"
    elif "Console" in server or "Engineering Console" in body:
        kind = "engineering-console"
    out = {"host": host, "port": port, "proto": kind, "server": server.strip()}
    if kind == "rtu-hmi":
        try:
            with urllib.request.urlopen(f"http://{host}:{port}/status.json",
                                        timeout=timeout) as r:
                st = json.load(r)
            plc = st.get("plc", {})
            out["model"] = plc.get("model")
            out["common_address"] = plc.get("common_address")
            out["application"] = plc.get("application")
        except Exception:                                   # noqa: BLE001
            pass
    return out


def main():
    ap = argparse.ArgumentParser(description="discover OT hosts on a segment")
    ap.add_argument("cidr", help="e.g. 10.104.0.0/24 or a single address")
    ap.add_argument("--iec-ports", default="2404",
                    help="comma separated (default 2404)")
    ap.add_argument("--web-ports", default="8080,8081,80,443",
                    help="comma separated")
    ap.add_argument("--workers", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=2.0)
    a = ap.parse_args()

    try:
        net = ipaddress.ip_network(a.cidr, strict=False)
    except ValueError as exc:
        sys.exit(f"bad target: {exc}")
    hosts = [str(h) for h in (net.hosts() if net.num_addresses > 1 else [net.network_address])]
    iec_ports = [int(p) for p in a.iec_ports.split(",") if p.strip()]
    web_ports = [int(p) for p in a.web_ports.split(",") if p.strip()]

    print(f"scanning {len(hosts)} address(es), IEC {iec_ports}, web {web_ports}\n")
    jobs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for h in hosts:
            for p in iec_ports:
                jobs.append(ex.submit(probe_iec, h, p, a.timeout))
            for p in web_ports:
                jobs.append(ex.submit(probe_http, h, p, a.timeout))
        found = [f.result() for f in concurrent.futures.as_completed(jobs)]

    found = sorted([f for f in found if f],
                   key=lambda d: (d["host"], d["port"]))
    if not found:
        print("nothing found")
        return 1
    for d in found:
        head = f"{d['host']}:{d['port']:<6} {d['proto']}"
        extra = []
        if d.get("common_address") is not None:
            extra.append(f"CA={d['common_address']}")
        if d.get("model"):
            extra.append(d["model"])
        if d.get("application"):
            extra.append(d["application"])
        if d.get("server"):
            extra.append(d["server"])
        if d.get("ioas"):
            extra.append(f"points from IOA {d['ioas'][0]}")
        print(f"  {head}" + ("   " + " | ".join(extra) if extra else ""))

    rtus = [d for d in found if d["proto"] == "iec-60870-5-104"]
    if rtus:
        r = rtus[0]
        print(f"\nan RTU is listening on {r['host']}:{r['port']}"
              + (f", common address {r['common_address']}"
                 if r.get("common_address") is not None else ""))
        print("point a client at it:")
        print(f"  python3 rtu_shell.py {r['host']} {r['port']}")
        consoles = [d for d in found if d["proto"] == "engineering-console"]
        if consoles:
            c = consoles[0]
            print(f"or drive it from the console in a browser: "
                  f"http://{c['host']}:{c['port']}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
