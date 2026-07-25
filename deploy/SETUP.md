# Setup — two VMs

**VM1** runs the RTU and its HMI. **VM2** runs the client.
Each builds its own Docker image from this repo. Nothing else is needed.

Requirements on both: Docker with the Compose plugin, and a copy of this repo.

---

## VM1 — the RTU / HMI

```bash
git clone <repo-url> kestrel-lab
cd kestrel-lab
docker compose -f deploy/docker-compose.rtu.yml up -d --build
```

Check it started:

```bash
docker compose -f deploy/docker-compose.rtu.yml ps
curl -s http://localhost:8080/status.json | head -20
```

Note VM1's IP address — VM2 needs it:

```bash
hostname -I | awk '{print $1}'
```

VM1 now listens on:

| Port | What |
|---|---|
| `2404` | IEC 60870-5-104 |
| `8080` | HMI web page |

Open `http://<VM1-IP>:8080/` in a browser to see the plant mimic.

---

## VM2 — the client

```bash
git clone <repo-url> kestrel-lab
cd kestrel-lab
docker compose -f deploy/docker-compose.jumpbox.yml up -d --build
```

Check it started:

```bash
docker compose -f deploy/docker-compose.jumpbox.yml ps
curl -s http://localhost:8081/api/banner
```

VM2 now listens on `8081`.

---

## Use it

Open `http://<VM2-IP>:8081/` in a browser. Fill in the form:

| Field | Value |
|---|---|
| Host or IP | `<VM1-IP>` |
| IEC-104 port | `2404` |
| CA | `17` |
| HMI port | `8080` |

Click **Connect**, then run these three commands in the page, in order:

```
priv
sc 1101 close
sc 1201 close
```

Then:

```
alarms
```

You should see:

```
CRIT  RLY104-PHASE-SLIP   52-T phase-slip trip asserted - ACTION REQUIRED:
inspect P-43 transfer pump immediately - shaft and coupling may be damaged,
do not restart before check
```

Watch `http://<VM1-IP>:8080/` while you do it — the breaker lamps go red and the
bus drops to 0 kV.

**Time limit:** `priv` authorises the session for about 28 seconds. If a command
comes back REFUSED, send `priv` again and retry. To avoid the race, paste all
three as one line:

```
priv ; sc 1101 close ; sc 1201 close
```

---

## Reset between runs

On VM1:

```bash
docker compose -f deploy/docker-compose.rtu.yml restart
```

---

## Prefer a terminal to the browser?

On VM2:

```bash
docker compose -f deploy/docker-compose.jumpbox.yml exec jumpbox \
  python3 /opt/kestrel/client/rtu_shell.py <VM1-IP> 2404 --hmi 8080
```

Same commands at the `rtu>` prompt.

---

## Stop everything

VM1:

```bash
docker compose -f deploy/docker-compose.rtu.yml down
```

VM2:

```bash
docker compose -f deploy/docker-compose.jumpbox.yml down
```

---

## If it does not work

**Browser cannot load VM2's page.** Check the container is up
(`docker compose -f deploy/docker-compose.jumpbox.yml ps`) and that VM2 allows
inbound `8081`.

**"connect failed" in the console.** VM2 cannot reach VM1 on 2404. Test from VM2:

```bash
python3 - <<'PY'
import socket
s = socket.create_connection(("<VM1-IP>", 2404), timeout=5)
s.sendall(bytes([0x68,4,0x07,0,0,0])); print(s.recv(16).hex()); s.close()
PY
```

`68040b000000` means VM1 answered. Anything else is the network or firewall
between them — VM1 must allow inbound `2404` (and `8080` for the `alarms` and
`hmi` commands) from VM2.

**Commands come back REFUSED.** The 28-second window lapsed. Send `priv` again,
or use the single chained line above.

**`hmi` or `alarms` fails but control works.** VM1 is allowing `2404` but not
`8080`. Those two commands read the HMI directly.

---

## Optional: prefill the target

If you would rather trainees not type the address, start VM2 with it baked into
the form:

```bash
CONSOLE_SUGGEST_HOST=<VM1-IP> CONSOLE_SUGGEST_HMI=8080 \
  docker compose -f deploy/docker-compose.jumpbox.yml up -d --build
```

Leave it out and they have to find VM1 themselves, e.g. from VM2:

```bash
docker compose -f deploy/docker-compose.jumpbox.yml exec jumpbox \
  python3 /opt/kestrel/client/otscan.py <your-subnet>/24
```
