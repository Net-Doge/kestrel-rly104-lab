#!/usr/bin/env bash
# Build a self-contained bundle for machines with no internet.
#
#   ./package-offline.sh                 # -> dist/kestrel-lab-offline.tar.gz
#   ./package-offline.sh --tag v1        # name the build
#
# The bundle carries the prebuilt Docker image, so the target VMs never pull
# python:3.12-slim, never build, and never touch a package index. Copy the one
# archive to each VM and run its install script.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="kestrel-rly104:latest"
TAG="${2:-$(date +%Y%m%d)}"
[ "${1:-}" = "--tag" ] && TAG="${2:-manual}"
OUT="dist"
STAGE="$OUT/kestrel-lab-offline"
ARCHIVE="$OUT/kestrel-lab-offline-$TAG.tar.gz"

echo "== building $IMAGE =="
docker build -t "$IMAGE" .

echo
echo "== staging =="
rm -rf "$STAGE"; mkdir -p "$STAGE"

# The image, which is the whole point of the bundle.
echo "   saving image (this is the slow part) ..."
docker save "$IMAGE" | gzip -9 > "$STAGE/kestrel-rly104.tar.gz"

# Compose files WITHOUT a build section: the target must never try to build.
cat > "$STAGE/docker-compose.rtu.yml" <<'YAML'
# VM1 - RTU and HMI. Offline: uses the preloaded image, never builds.
services:
  rtu:
    image: kestrel-rly104:latest
    container_name: kestrel-rtu
    hostname: rly104
    restart: unless-stopped
    ports:
      - "${RTU_BIND:-0.0.0.0}:${IEC_PORT:-2404}:2404"
      - "${RTU_BIND:-0.0.0.0}:${HMI_PORT:-8080}:8080"
    environment:
      KESTREL_TRIP_ACTION: "${KESTREL_TRIP_ACTION:-ACTION REQUIRED: inspect P-43 transfer pump immediately - shaft and coupling may be damaged, do not restart before check}"
      KESTREL_EXTRA_ARGS: "${KESTREL_EXTRA_ARGS:--v}"
    cap_add: [NET_RAW]
    healthcheck:
      test: ["CMD", "python3", "-c",
             "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/status.json', timeout=3)"]
      interval: 15s
      timeout: 4s
      retries: 3
YAML

cat > "$STAGE/docker-compose.client.yml" <<'YAML'
# VM2 - the client. Offline: uses the preloaded image, never builds.
services:
  jumpbox:
    image: kestrel-rly104:latest
    container_name: kestrel-jumpbox
    hostname: jumpbox
    restart: unless-stopped
    entrypoint: ["python3", "/opt/kestrel/console/console.py",
                 "--listen", "0.0.0.0", "--port", "8081"]
    ports:
      - "${CONSOLE_BIND:-0.0.0.0}:${CONSOLE_PORT:-8081}:8081"
    environment:
      CONSOLE_SUGGEST_HOST: "${CONSOLE_SUGGEST_HOST:-}"
      CONSOLE_SUGGEST_PORT: "${CONSOLE_SUGGEST_PORT:-2404}"
      CONSOLE_SUGGEST_HMI: "${CONSOLE_SUGGEST_HMI:-}"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    cap_add: [NET_RAW]
    healthcheck:
      test: ["CMD", "python3", "-c",
             "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/api/banner', timeout=3)"]
      interval: 15s
      timeout: 4s
      retries: 3
YAML

cat > "$STAGE/install.sh" <<'SH'
#!/usr/bin/env bash
# Offline installer. Run on each VM:
#
#   ./install.sh rtu       on VM1 - the RTU and HMI
#   ./install.sh client    on VM2 - the client
#   ./install.sh stop      stop whatever this VM is running
set -euo pipefail
cd "$(dirname "$0")"
IMAGE="kestrel-rly104:latest"

load_image () {
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "image already present, skipping load"
  else
    echo "loading image (no network needed) ..."
    gunzip -c kestrel-rly104.tar.gz | docker load
  fi
}

case "${1:-}" in
  rtu)
    load_image
    docker compose -f docker-compose.rtu.yml up -d --no-build
    echo
    echo "RTU up. This VM's address:"
    hostname -I | awk '{print "   " $1}'
    echo "   IEC-104 on 2404, HMI on http://<this-ip>:8080/"
    ;;
  client)
    load_image
    docker compose -f docker-compose.client.yml up -d --no-build
    echo
    echo "Client up. Open the console at:"
    hostname -I | awk '{print "   http://" $1 ":8081/"}'
    echo "   Enter VM1's IP, port 2404, CA 17, HMI port 8080."
    ;;
  stop)
    docker compose -f docker-compose.rtu.yml    down 2>/dev/null || true
    docker compose -f docker-compose.client.yml down 2>/dev/null || true
    echo "stopped"
    ;;
  *)
    echo "usage: ./install.sh rtu|client|stop"; exit 1 ;;
esac
SH
chmod +x "$STAGE/install.sh"

# Docs and the client source, so the terminal client can be run from the VM
# directly as well as inside the container.
cp deploy/SETUP.md "$STAGE/SETUP.md" 2>/dev/null || true
mkdir -p "$STAGE/client"
cp client/*.py "$STAGE/client/" 2>/dev/null || true
cp docs/client-reference.md "$STAGE/client/" 2>/dev/null || true
cp artifacts/backup.pcap "$STAGE/" 2>/dev/null || true
cp requirements.txt "$STAGE/" 2>/dev/null || true

cat > "$STAGE/README-OFFLINE.md" <<'MD'
# Offline install

Everything needed is in this directory. No internet, no package index, no build.

## VM1 — the RTU and HMI

```bash
./install.sh rtu
```

Note the IP it prints. HMI at `http://<VM1-IP>:8080/`, IEC-104 on `2404`.

## VM2 — the client

```bash
./install.sh client
```

Open the URL it prints. In the page enter VM1's IP, port `2404`, CA `17`,
HMI port `8080`, then Connect and run:

```
priv ; sc 1101 close ; sc 1201 close
alarms
```

## Stop

```bash
./install.sh stop
```

## What is in here

| File | |
|---|---|
| `kestrel-rly104.tar.gz` | the prebuilt Docker image |
| `docker-compose.rtu.yml` | VM1 service, no build section |
| `docker-compose.client.yml` | VM2 service, no build section |
| `install.sh` | loads the image and starts the right one |
| `client/` | the Python client, runnable straight on the VM |
| `SETUP.md` | the fuller walkthrough and troubleshooting |
| `SHA256SUMS` | integrity check: `sha256sum -c SHA256SUMS` |

## Requirements

Docker with the Compose plugin. Nothing else — the lab is standard-library
Python only, so `requirements.txt` is empty by design.

Running the client straight on a VM instead of in the container needs Python
3.10+:

```bash
python3 client/rtu_shell.py <VM1-IP> 2404 --hmi 8080
```
MD

( cd "$STAGE" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )

echo
echo "== archiving =="
tar -C "$OUT" -czf "$ARCHIVE" kestrel-lab-offline
rm -rf "$STAGE"
echo
echo "bundle:  $ARCHIVE  ($(du -h "$ARCHIVE" | cut -f1))"
echo
echo "copy it to each VM, then:"
echo "  tar xzf $(basename "$ARCHIVE") && cd kestrel-lab-offline"
echo "  ./install.sh rtu        # on VM1"
echo "  ./install.sh client     # on VM2"
