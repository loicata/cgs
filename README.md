# CGS — Autonomous Cybersecurity Server for SMBs

CGS (Cyber Guardian Sentinel) is a fully autonomous micro-SIEM written in Python. It provides real-time network monitoring, threat detection, active defense, and incident response — designed for small and medium businesses that cannot afford a dedicated SOC team.

## Features

**Detection & Analysis**
- Real-time packet capture and analysis (scapy)
- Port scan, brute-force, DNS tunnel, C2 beaconing, ARP spoofing detection
- Kill chain correlation (multi-stage attack detection)
- TLS fingerprinting (JA3)
- Advanced detectors: lateral movement, temporal anomaly, slow exfiltration, DGA
- Threat intelligence feeds (abuse.ch, MISP, OpenCTI)
- Honeypot decoy services

**Active Defense**
- Automated IP blocking (iptables/nftables)
- Rate limiting, quarantine, RST kill, DNS sinkhole
- Graduated escalation ladder (MONITOR → THROTTLE → ISOLATE → BLOCK → NETWORK_ALERT)
- Auto de-escalation when attacks stop
- Post-action verification (checks that blocks actually took effect)
- Netgate firewall integration (pfSense / OPNsense)

**Incident Response**
- Two modes: confirmation (admin approves first) or immediate (act first, inform after)
- Email notifications to admins and users (shutdown request, status report)
- Client agent for workstation popups and local forensic collection
- Pre-defense snapshots with rollback capability
- Complaint PDF generation (country-adapted: IE, FR, US)
- Deep attacker reconnaissance (WHOIS, geolocation, port scan, OS fingerprint)

**Dashboard & API**
- Real-time web dashboard (Flask + SocketIO) with HTTPS
- REST API for all operations
- GRC module (risks, assets, policies, audits, vendors)
- Compliance scoring with framework mapping (ISO 27001, NIST, CIS)
- Global search across all entities

**Security Hardening**
- AES-128-CBC secrets encryption (Fernet vault)
- HMAC-SHA256 authentication for client agents
- CSRF protection, rate limiting, login lockout
- Hash-chained audit log (tamper-proof)
- Code integrity verification at startup
- SSH hardening (auto-disable password auth when keys exist)
- OS-level hardening checks
- Privilege dropping after binding raw sockets

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    CGS Sentinel                      │
│                                                      │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────┐  │
│  │ Sniffer  │→ │ Analyzers │→ │ Defense Engine    │  │
│  │ (scapy)  │  │ (threats) │  │ (iptables/nft)   │  │
│  └──────────┘  └───────────┘  └──────────────────┘  │
│       ↓              ↓               ↓               │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────┐  │
│  │Correlator│  │ Kill Chain│  │ Incident Engine  │  │
│  └──────────┘  └───────────┘  └──────────────────┘  │
│                      ↓                               │
│  ┌──────────────────────────────────────────────┐    │
│  │ Dashboard (Flask + SocketIO) · HTTPS :8443   │    │
│  └──────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
         ↕                              ↕
   ┌───────────┐                 ┌─────────────┐
   │ Client    │  (polling)      │ Netgate FW  │
   │ Agents    │                 │ (pfSense/   │
   │ (popups)  │                 │  OPNsense)  │
   └───────────┘                 └─────────────┘
```

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/loicata/cgs.git
cd cgs
docker compose up -d
```

Then open https://localhost:8443 and follow the setup wizard.

### Manual Installation

```bash
# Install system dependencies
sudo apt-get install -y python3.13 python3-pip libpcap-dev \
    iptables nftables nmap openssl tcpdump iproute2

# Install Python dependencies
pip install -r requirements.txt

# Run the setup wizard
sudo python3 cli.py setup

# Start the daemon
sudo python3 cli.py start
```

### Client Agent (optional)

Deploy on each workstation for popup notifications and local forensic collection:

```bash
python3 cgs-agent.py --server https://SENTINEL_IP:8443 --secret YOUR_SHARED_SECRET
```

No admin privileges required on the workstation.

## CLI Commands

```bash
sudo cgs start          # Start the daemon
sudo cgs scan           # Manual ARP discovery
sudo cgs portscan       # Port scan
cgs status              # System status
cgs alerts              # Recent alerts
cgs inventory           # Network inventory
cgs passwd              # Change web password
sudo cgs setup          # Configuration wizard
sudo cgs console        # TUI administration console
```

## Configuration

All settings are in `config.yaml`. Key sections:

| Section | Description |
|---------|-------------|
| `network` | Subnets to monitor, interface, exclusions |
| `defense` | Active defense mode, thresholds, whitelist |
| `email` | SMTP, admin emails, user directory |
| `suricata` | Optional Suricata integration (eve.json, syslog, TCP) |
| `client_agent` | Workstation agent settings, shared secret |
| `netgate` | pfSense / OPNsense API integration |
| `honeypot` | Decoy service ports |
| `detectors` | Advanced detector configuration |

## Testing

```bash
# Run all tests
python3 -m pytest tests/ -q

# Run with coverage
python3 -m pytest tests/ --cov=core --cov=analyzers --cov=web --cov-report=term-missing

# Security analysis
bandit -r core/ analyzers/ web/ daemon.py -c .bandit
pip-audit -r requirements.txt
```

**1947 tests** covering 37 modules with an average coverage of **96%**.

## CI/CD

The GitHub Actions pipeline (`.github/workflows/ci.yml`) runs on every push to `main`:

1. **Tests** — pytest with coverage threshold (>= 80%)
2. **pip-audit** — Dependency vulnerability scan
3. **Bandit** — Static security analysis (blocks on HIGH/MEDIUM)
4. **Docker** — Build and push to GitHub Container Registry (only if all checks pass)

## Project Structure

```
cgs/
├── core/               # Core modules (37 files)
│   ├── security.py     # Encryption, CSRF, rate limiting, validation
│   ├── defense.py      # Active defense engine (iptables/nftables)
│   ├── incident.py     # Incident response orchestration
│   ├── sniffer.py      # Network packet capture
│   ├── hardening.py    # TLS, SSH, integrity checks
│   └── ...
├── analyzers/          # Threat analysis (6 files)
│   ├── threat_engine.py  # Port scan, brute-force, beaconing detection
│   ├── detectors.py      # Advanced detectors (lateral movement, DGA...)
│   ├── correlator.py     # Multi-source event correlation
│   └── ...
├── web/                # Web dashboard (7 files)
│   ├── app.py          # Flask application
│   ├── routes_auth.py  # Authentication, setup wizard
│   └── ...
├── tests/              # Test suite (42 files, 1947 tests)
├── daemon.py           # Main daemon orchestrator
├── cli.py              # Command-line interface
├── cgs-agent.py        # Client agent (workstations)
├── config.yaml         # Configuration file
├── Dockerfile          # Multi-stage production image
├── docker-compose.yml  # Docker deployment
└── .github/workflows/  # CI/CD pipeline
```

## Security

- **311 security issues fixed** (bandit: 0 HIGH, 0 MEDIUM, 0 LOW on source code)
- **0 known vulnerabilities** in dependencies (pip-audit clean)
- **3 bugs discovered and fixed** through testing
- All secrets use environment variables or encrypted config (Fernet AES-128-CBC)
- Non-root Docker container with minimal capabilities
- Read-only filesystem with tmpfs

## License

All rights reserved.

## Author

Loic Ader — [cipango56@pm.me](mailto:cipango56@pm.me)
