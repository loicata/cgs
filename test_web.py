#!/usr/bin/env python3
"""
CGS — Test web interface with sample data.
"""
import os, sys, subprocess

# ── Auto-install missing dependencies ──
REQUIRED = {
    "peewee": "peewee", "flask": "flask", "flask_socketio": "flask-socketio",
    "gevent": "gevent", "bcrypt": "bcrypt", "yaml": "pyyaml",
    "markupsafe": "markupsafe", "scapy": "scapy", "psutil": "psutil",
}
missing = []
for mod, pkg in REQUIRED.items():
    try:
        __import__(mod)
    except ImportError:
        missing.append(pkg)
if missing:
    print(f"Installing missing packages: {', '.join(missing)}")
    subprocess.check_call([sys.executable, "-m", "pip", "install",
                           "--break-system-packages", *missing],
                          stdout=subprocess.DEVNULL)
    print("Dependencies installed.\n")

import random
from datetime import datetime, timedelta
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Use home directory for test data
data_dir = os.path.join(os.path.expanduser("~"), ".cgs_test")
os.makedirs(data_dir, exist_ok=True)

db_path = os.path.join(data_dir, "cgs.db")
db_exists = os.path.exists(db_path)

# Auto-detect subnet
def _detect_subnet():
    try:
        import socket, struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        prefix = ip.rsplit(".", 1)[0]
        return f"{prefix}.0/24"
    except Exception:
        return "192.168.1.0/24"

test_config_path = os.path.join(data_dir, "config.yaml")
import yaml
# Only create config if it doesn't exist (preserve setup changes)
if not os.path.exists(test_config_path):
    detected_subnet = _detect_subnet()
    with open(test_config_path, "w") as f:
        yaml.dump({
            "general": {"data_dir": data_dir, "log_dir": data_dir},
            "web": {"enabled": True, "host": "127.0.0.1", "port": 8443},
            "network": {"subnets": [detected_subnet], "interface": "auto", "exclude_ips": []},
            "email": {"enabled": False},
            "defense": {"enabled": True, "mode": "confirmation"},
        }, f)
    print(f"  Config created with subnet: {detected_subnet}")

from core.database import (init_db, Host, Port, Alert, DnsLog, BaselineStat, Flow,
                           Risk, Asset, Policy, PolicyAck, Audit, AuditFinding,
                           Vendor, VendorQuestion, RiskControlMap, ComplianceSnapshot,
                           ComplianceAnswer)
init_db(data_dir)

print(f"  Database: {db_path} ({'existing' if db_exists else 'new'})")

# ── Config & Web server ──
from core.config import Config
cfg = Config(test_config_path)

from web.app import init_app
import psutil

class HealthStub:
    def check_all(self):
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        nets = {}
        for name, addrs in psutil.net_if_addrs().items():
            if name == "lo": continue
            ip = next((a.address for a in addrs if a.family.name == "AF_INET"), "")
            mac = next((a.address for a in addrs if a.family.name == "AF_PACKET"), "")
            up = name in psutil.net_if_stats() and psutil.net_if_stats()[name].isup
            nets[name] = {"ip": ip, "mac": mac, "up": up}
        return {
            "system": {
                "cpu_percent": cpu, "memory_percent": mem.percent,
                "mem_used_gb": f"{mem.used/1e9:.1f}", "mem_total_gb": f"{mem.total/1e9:.1f}",
                "uptime_h": round((datetime.now() - datetime.fromtimestamp(psutil.boot_time())).seconds / 3600, 1),
                "load_1": os.getloadavg()[0],
            },
            "disk": {"/": {"used_pct": disk.percent, "free_gb": f"{disk.free/1e9:.1f}"}},
            "network": nets,
        }

class ThreatStub:
    stats = {}
    def get_threat_summary(self):
        return {
            "active_scanners": 2, "beacon_pairs": 1,
            "top_risk_hosts": [
                {"ip": "10.0.0.55", "score": 88, "os": "Linux"},
                {"ip": "192.168.1.99", "score": 72, "os": "Linux"},
                {"ip": "192.168.1.20", "score": 45, "os": "Linux"},
            ],
        }

class SnifferStub:
    stats = {"pps": random.randint(50, 200), "mbps": round(random.uniform(1, 15), 1),
             "packets": random.randint(100000, 999999), "active_flows": random.randint(20, 80),
             "uptime": "2h 15m"}

modules = {
    "health": HealthStub(),
    "sniffer": SnifferStub(),
    "engine": ThreatStub(),
}

flask_app, sio = init_app(cfg, modules)

print(f"""
\033[0;32m
   ██████╗ ██████╗ ███████╗
  ██╔════╝██╔════╝ ██╔════╝
  ██║     ██║  ███╗███████╗
  ██║     ██║   ██║╚════██║
  ╚██████╗╚██████╔╝███████║
   ╚═════╝ ╚═════╝ ╚══════╝\033[0m
  \033[1;37mCGS serveur\033[0m — Cybersecurity Guardian System

  URL:  \033[0;36mhttp://localhost:8443\033[0m
  Data: {data_dir}

  Ctrl+C to stop
""")

sio.run(flask_app, host="127.0.0.1", port=8443, debug=False, use_reloader=False, log_output=True)  # nosec B104
