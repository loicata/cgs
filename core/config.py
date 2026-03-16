"""YAML configuration with defaults."""
import os, secrets, yaml, logging
from pathlib import Path

logger = logging.getLogger("cgs.config")

DEFAULTS = {
    "general": {"data_dir": "/opt/cgs/data", "log_dir": "/var/log/cgs", "log_level": "INFO"},
    "network": {"subnets": ["192.168.1.0/24"], "interface": "auto", "exclude_ips": []},
    "discovery": {
        "arp_interval": 300, "port_scan_interval": 3600,
        "top_ports": [21,22,23,25,53,80,110,135,139,143,443,445,993,995,
                      1433,1521,3306,3389,5432,5900,6379,8080,8443,27017],
        "service_detection": True, "os_fingerprint": True,
        "use_nmap": True,
    },
    "sniffer": {"enabled": True, "promiscuous": True, "bpf_filter": ""},
    "suricata": {"eve_file": "", "syslog_port": "", "tcp_port": ""},
    "defense": {
        "enabled": True, "mode": "confirmation", "auto_block": True,
        "auto_block_severity": 1, "alert_count_threshold": 5,
        "alert_count_window": 300,
        "block_ttl_seconds": 3600, "rate_limit_ttl_seconds": 1800,
        "quarantine_ttl_seconds": 7200,
        "whitelist_ips": [],
        "whitelist_macs": [],
    },
    "email": {
        "enabled": False, "smtp_server": "", "smtp_port": 587,
        "smtp_tls": True, "smtp_user": "", "smtp_password": "",
        "from_address": "sentinel@cgs.local",
        "sentinel_url": "https://localhost:8443",
        "approval_timeout_minutes": 15,
        "timeout_auto_approve": False,
        "shutdown_check_interval": 10,
        "shutdown_max_wait_minutes": 30,
        "security_contact": "the IT security team",
        "include_legal_info": True,
        "attach_forensic_file": True,
        "country": "IE",
        "admin_emails": [], "user_directory": [],
    },
    "recon": {
        "abuseipdb_key": "",
        "virustotal_key": "",
        "shodan_key": "",
        "greynoise_key": "",
        "otx_key": "",
    },
    "netgate": {
        "enabled": False, "type": "", "host": "", "port": 443,
        "verify_ssl": False, "block_alias": "CGS_Block", "timeout": 15,
        "pfsense_api_client": "", "pfsense_api_key": "",
        "opnsense_key": "", "opnsense_secret": "",
    },
    "analysis": {
        "portscan_threshold": 15, "bruteforce_threshold": 10,
        "bruteforce_window": 60, "beacon_tolerance": 0.15,
        "dns_entropy_threshold": 3.5, "exfil_mb": 100,
        "new_service_alert": True,
    },
    "identity": {
        "spoof_threshold": 50,
        "learning_hours": 48,
    },
    "client_agent": {
        "enabled": True,
        "message_ttl_minutes": 120,
        "collect_after_incident": True,
        "ack_timeout_seconds": 120,
        "shared_secret": "",
    },
    "notifications": {
        "slack": {"enabled": False, "webhook_url": ""},
        "teams": {"enabled": False, "webhook_url": ""},
        "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
    },
    "alerts": {"cooldown_seconds": 300, "max_per_hour": 120,
               "email": {"enabled": False}, "webhook": {"enabled": False},
               "syslog": {"enabled": True}},
    "web": {"enabled": True, "host": "127.0.0.1", "port": 8443,
            "secret": "", "username": "admin", "password_hash": ""},
    "retention": {"alerts_days": 90, "events_days": 30, "flows_days": 14},
}

class Config:
    def __init__(self, path=None):
        self.path = Path(path) if path else Path("/opt/cgs/config.yaml")
        self._path = str(self.path)  # String version for web/app.py
        self._d = {}
        self._load()

    def _load(self):
        if self.path.exists():
            with open(self.path) as f:
                self._d = yaml.safe_load(f) or {}
        self._d = self._merge(DEFAULTS, self._d)
        self._ensure_dirs()

    @staticmethod
    def _merge(b, o):
        r = dict(b)
        for k, v in o.items():
            if k in r and isinstance(r[k], dict) and isinstance(v, dict):
                r[k] = Config._merge(r[k], v)
            else:
                r[k] = v
        return r

    def _ensure_dirs(self):
        for k in ("general.data_dir", "general.log_dir"):
            Path(self.get(k)).mkdir(parents=True, exist_ok=True)

    def get(self, dotted, default=None):
        keys = dotted.split(".")
        v = self._d
        for k in keys:
            if isinstance(v, dict): v = v.get(k)
            else: return default
            if v is None: return default
        return v

    def set(self, dotted, value):
        keys = dotted.split(".")
        d = self._d
        for k in keys[:-1]: d = d.setdefault(k, {})
        d[keys[-1]] = value

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            yaml.dump(self._d, f, default_flow_style=False, allow_unicode=True)
