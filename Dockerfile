# Kestrel RLY-104 Feeder Guard - lab clone
#
# Stdlib only, so no pip install and no wheels to cache. The image carries both
# the RTU/HMI simulator and the IEC-104 client tooling, so a single container is
# enough to attack itself if you want.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Kestrel RLY-104 Feeder Guard (lab clone)" \
      org.opencontainers.image.description="IEC 60870-5-104 RTU + HMI simulation of the Kestrel East Feeder Transfer scenario" \
      org.opencontainers.image.licenses="MIT"

# procps for pgrep/ps when poking around inside, tcpdump for capturing the
# protocol on the container's own interface.
RUN apt-get update \
 && apt-get install -y --no-install-recommends procps tcpdump iproute2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/kestrel
# rtu/ carries the simulator and hmi.html, the genuine mimic page
COPY rtu/    /opt/kestrel/rtu/
COPY client/ /opt/kestrel/client/
COPY console/ /opt/kestrel/console/
COPY artifacts/ /opt/kestrel/artifacts/

# IEC 60870-5-104 and the HMI. 2404 is the protocol's registered port, so
# Wireshark decodes it with no configuration at all.
ENV KESTREL_IEC_PORT=2404 \
    KESTREL_HMI_PORT=8080 \
    KESTREL_TRIP_ACTION="ACTION REQUIRED: inspect P-43 transfer pump immediately - shaft and coupling may be damaged, do not restart before check" \
    PYTHONUNBUFFERED=1

EXPOSE 2404 8080 8081

# Listening on 0.0.0.0 so the container is reachable from anywhere on the
# attached Docker network, not just localhost.
HEALTHCHECK --interval=15s --timeout=4s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request,os,sys; \
      urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"KESTREL_HMI_PORT\"]}/status.json', timeout=3)" \
      || exit 1

ENTRYPOINT ["/bin/sh", "-c", "exec python3 /opt/kestrel/rtu/kestrel_sim.py \
  --iec \"$KESTREL_IEC_PORT\" --hmi \"$KESTREL_HMI_PORT\" \
  --trip-action \"$KESTREL_TRIP_ACTION\" $KESTREL_EXTRA_ARGS"]
