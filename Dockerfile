FROM python:3.13-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev iptables nftables traceroute whois nmap net-tools \
    openssl tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create service user
RUN useradd -r -s /bin/false cgs

# App directory
WORKDIR /opt/cgs
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Data directories
RUN mkdir -p /var/lib/cgs/data /var/log/cgs /etc/cgs/tls /opt/cgs/data/evidence \
    && chown -R cgs:cgs /var/lib/cgs /var/log/cgs /opt/cgs/data

# TLS certificate
RUN openssl req -x509 -newkey rsa:2048 -keyout /etc/cgs/tls/sentinel.key \
    -out /etc/cgs/tls/sentinel.crt -days 3650 -nodes \
    -subj "/CN=cgs/O=CGS" 2>/dev/null; \
    chmod 600 /etc/cgs/tls/sentinel.key

EXPOSE 8443

# Start daemon (needs NET_RAW capability for packet capture)
CMD ["python3", "daemon.py"]
