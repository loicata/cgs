# ══════════════════════════════════════════════════
# CGS — Optimized production Dockerfile
# Multi-stage build · Non-root · Minimal attack surface
# ══════════════════════════════════════════════════

# ── Stage 1: Build dependencies ──
FROM python:3.13-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Production image ──
FROM python:3.13-slim

LABEL maintainer="CGS <cipango56@pm.me>"
LABEL org.opencontainers.image.description="CGS — Autonomous Cybersecurity Server for SMBs"

# Runtime system dependencies only (no gcc, no dev headers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 iptables nftables traceroute whois nmap net-tools \
    openssl tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get purge -y --auto-remove

# Copy Python packages from builder
COPY --from=builder /install /usr/local

# Create non-root service user
RUN useradd -r -s /usr/sbin/nologin -d /opt/cgs cgs

# Application directory
WORKDIR /opt/cgs

# Copy only application code (tests, dev files excluded via .dockerignore)
COPY core/ core/
COPY analyzers/ analyzers/
COPY web/ web/
COPY debian/ debian/
COPY daemon.py cli.py cgs-agent.py config.yaml requirements.txt ./
COPY Dockerfile docker-compose.yml ./

# Create data directories with correct ownership
RUN mkdir -p /var/lib/cgs/data /var/log/cgs /etc/cgs/tls \
             /opt/cgs/data/evidence /var/log/cgs/snapshots \
             /var/log/cgs/forensics /var/log/cgs/backups \
    && chown -R cgs:cgs /var/lib/cgs /var/log/cgs /opt/cgs/data /etc/cgs

# Generate TLS certificate at first run (entrypoint), not at build time
# This ensures each instance gets a unique certificate
COPY <<'ENTRYPOINT' /opt/cgs/entrypoint.sh
#!/bin/sh
set -e

# Generate TLS cert if not mounted externally
if [ ! -f /etc/cgs/tls/sentinel.crt ]; then
    HOSTNAME=$(hostname 2>/dev/null || echo "cgs")
    openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/cgs/tls/sentinel.key \
        -out /etc/cgs/tls/sentinel.crt \
        -days 3650 -nodes \
        -subj "/CN=${HOSTNAME}/O=CGS/OU=Auto-Generated" 2>/dev/null
    chmod 600 /etc/cgs/tls/sentinel.key
    chmod 644 /etc/cgs/tls/sentinel.crt
    chown cgs:cgs /etc/cgs/tls/sentinel.key /etc/cgs/tls/sentinel.crt
    echo "TLS certificate generated for ${HOSTNAME}"
fi

exec "$@"
ENTRYPOINT
RUN chmod +x /opt/cgs/entrypoint.sh

# Expose HTTPS dashboard
EXPOSE 8443

# Health check: verify the web dashboard responds
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "import urllib.request,ssl; ctx=ssl._create_unverified_context(); urllib.request.urlopen('https://localhost:8443/api/setup/detect-network',context=ctx,timeout=5)" || exit 1

# Entrypoint generates TLS cert if needed, then runs CMD
ENTRYPOINT ["/opt/cgs/entrypoint.sh"]

# Drop to non-root user for the daemon
# Note: daemon.py drops privileges internally after binding raw sockets,
# but we start as root for NET_RAW capability, then daemon handles the drop
CMD ["python3", "daemon.py"]
