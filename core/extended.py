"""
CyberGuard Sentinel — Extended features module.

Contains:
  1. HashChainAudit    — Tamper-proof audit log (hash-chained entries)
  2. BackupManager     — Encrypted backup of DB, snapshots, config
  3. HotRules          — YAML-based detection rules, reloadable at runtime
  4. WeeklyReport      — Automated periodic report generation
  5. SIEMExporter      — Syslog/CEF export to external SIEM
  6. ThreatIntel       — MISP/OpenCTI threat intelligence feed
  7. FalsePositive     — Feedback-driven threshold adjustment per host
"""

import csv
import hashlib
import io
import json
import logging
import os
import re
import socket
import threading
import time
import yaml
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger("cyberguard.extended")


# ══════════════════════════════════════════════════
# 1. Hash-chained audit log (tamper-proof)
# ══════════════════════════════════════════════════

class HashChainAudit:
    """
    Each audit entry contains the SHA-256 hash of the previous entry.
    Any modification to a past entry breaks the chain and is detectable.
    Format: JSONL with fields: seq, ts, event, detail, prev_hash, hash
    """

    def __init__(self, config):
        self.log_dir = config.get("general.log_dir", "/var/log/cyberguard")
        self.filepath = os.path.join(self.log_dir, "audit_chain.jsonl")
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = "GENESIS"

        # Resume from last entry
        self._resume()

    def _resume(self):
        """Load last hash from existing chain."""
        try:
            if os.path.exists(self.filepath):
                with open(self.filepath, "r") as f:
                    last = None
                    for line in f:
                        line = line.strip()
                        if line:
                            last = line
                    if last:
                        entry = json.loads(last)
                        self._seq = entry.get("seq", 0)
                        self._prev_hash = entry.get("hash", "GENESIS")
        except Exception:
            pass

    def log(self, event: str, detail: str = "", source: str = "",
            severity: int = 5, ip: str = ""):
        """Append a hash-chained audit entry."""
        with self._lock:
            self._seq += 1
            entry = {
                "seq": self._seq,
                "ts": datetime.now().isoformat(),
                "event": event,
                "detail": detail[:1000],
                "source": source,
                "severity": severity,
                "ip": ip,
                "prev_hash": self._prev_hash,
            }
            # Compute hash of this entry (excluding 'hash' field itself)
            payload = json.dumps(entry, sort_keys=True)
            entry["hash"] = hashlib.sha256(payload.encode()).hexdigest()
            self._prev_hash = entry["hash"]

            try:
                with open(self.filepath, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception as e:
                logger.error("Audit chain write failed: %s", e)

    def verify(self) -> dict:
        """Verify the entire chain integrity. Returns {ok, entries, first_broken}."""
        try:
            with open(self.filepath, "r") as f:
                lines = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            return {"ok": True, "entries": 0, "first_broken": None}

        prev_hash = "GENESIS"
        for i, line in enumerate(lines):
            entry = json.loads(line)
            stored_hash = entry.pop("hash", "")
            if entry.get("prev_hash") != prev_hash:
                return {"ok": False, "entries": len(lines),
                        "first_broken": i + 1, "reason": "prev_hash mismatch"}
            payload = json.dumps(entry, sort_keys=True)
            computed = hashlib.sha256(payload.encode()).hexdigest()
            if computed != stored_hash:
                return {"ok": False, "entries": len(lines),
                        "first_broken": i + 1, "reason": "hash mismatch"}
            prev_hash = stored_hash

        return {"ok": True, "entries": len(lines), "first_broken": None}


# ══════════════════════════════════════════════════
# 2. Encrypted backup
# ══════════════════════════════════════════════════

class BackupManager:
    """
    Creates encrypted backups of critical data:
    - SQLite database
    - Config file
    - Snapshots
    - Audit chain
    - Forensic reports
    """

    def __init__(self, config):
        self.cfg = config
        self.data_dir = config.get("general.data_dir", "/var/lib/cyberguard/data")
        self.log_dir = config.get("general.log_dir", "/var/log/cyberguard")
        self.config_path = config.get("_config_path", "/etc/cyberguard/config.yaml")
        self.backup_dir = config.get("backup.directory",
                                      os.path.join(self.log_dir, "backups"))
        os.makedirs(self.backup_dir, exist_ok=True)

    def create(self, passphrase: str = "") -> str:
        """
        Create a backup tarball. Optionally encrypted with passphrase.
        Returns filepath of the backup.
        """
        import tarfile

        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        tar_path = os.path.join(self.backup_dir, f"cyberguard_backup_{now}.tar.gz")

        with tarfile.open(tar_path, "w:gz") as tar:
            # Database
            db_path = os.path.join(self.data_dir, "cyberguard.db")
            if os.path.exists(db_path):
                tar.add(db_path, arcname="data/cyberguard.db")

            # Config
            if os.path.exists(self.config_path):
                tar.add(self.config_path, arcname="config/config.yaml")

            # Fingerprints
            fp_path = os.path.join(self.data_dir, "fingerprints.json")
            if os.path.exists(fp_path):
                tar.add(fp_path, arcname="data/fingerprints.json")

            # Audit chain
            audit_path = os.path.join(self.log_dir, "audit_chain.jsonl")
            if os.path.exists(audit_path):
                tar.add(audit_path, arcname="logs/audit_chain.jsonl")

            # Snapshots
            snap_dir = os.path.join(self.log_dir, "snapshots")
            if os.path.isdir(snap_dir):
                for fn in os.listdir(snap_dir):
                    tar.add(os.path.join(snap_dir, fn), arcname=f"snapshots/{fn}")

            # Forensic reports
            forensic_dir = os.path.join(self.log_dir, "forensics")
            if os.path.isdir(forensic_dir):
                for fn in os.listdir(forensic_dir):
                    tar.add(os.path.join(forensic_dir, fn), arcname=f"forensics/{fn}")

        # Encrypt if passphrase provided
        if passphrase:
            enc_path = tar_path + ".enc"
            try:
                from core.security import SecretsVault
                vault = SecretsVault(passphrase)
                with open(tar_path, "rb") as f:
                    data = f.read()
                encrypted = vault.encrypt(data.hex())
                with open(enc_path, "w") as f:
                    f.write(encrypted)
                os.remove(tar_path)
                logger.info("Encrypted backup created: %s", enc_path)
                return enc_path
            except Exception as e:
                logger.warning("Encryption failed, keeping unencrypted: %s", e)

        size_mb = round(os.path.getsize(tar_path) / 1024 / 1024, 2)
        logger.info("Backup created: %s (%.2f MB)", tar_path, size_mb)
        return tar_path

    def list_backups(self) -> list[dict]:
        """List available backups."""
        backups = []
        for fn in sorted(os.listdir(self.backup_dir), reverse=True):
            if fn.startswith("cyberguard_backup_"):
                fp = os.path.join(self.backup_dir, fn)
                backups.append({
                    "filename": fn,
                    "filepath": fp,
                    "size_mb": round(os.path.getsize(fp) / 1024 / 1024, 2),
                    "created": fn.split("_")[2].split(".")[0],
                    "encrypted": fn.endswith(".enc"),
                })
        return backups


# ══════════════════════════════════════════════════
# 3. Hot-reloadable detection rules (YAML)
# ══════════════════════════════════════════════════

class HotRules:
    """
    Loads detection rules from a YAML file. Rules can be reloaded
    at runtime without restarting the daemon.

    Rule format:
      - name: "SSH Brute Force"
        category: "brute_force"
        severity: 2
        condition:
          type: "threshold"
          field: "dst_port"
          value: 22
          count: 10
          window: 60
        action: "block"
    """

    def __init__(self, config):
        self.rules_path = config.get("rules.path",
                                      "/etc/cyberguard/rules.yaml")
        self.rules = []
        self._lock = threading.Lock()
        self._last_mtime = 0
        self.reload()

        # Watch for changes
        threading.Thread(target=self._watch_loop, daemon=True,
                        name="rules-watch").start()

    def reload(self) -> int:
        """Load or reload rules from YAML file."""
        try:
            if not os.path.exists(self.rules_path):
                return 0
            with open(self.rules_path) as f:
                data = yaml.safe_load(f) or {}
            with self._lock:
                self.rules = data.get("rules", [])
            self._last_mtime = os.path.getmtime(self.rules_path)
            logger.info("Rules loaded: %d rules from %s", len(self.rules), self.rules_path)
            return len(self.rules)
        except Exception as e:
            logger.error("Rules load failed: %s", e)
            return 0

    def match(self, event: dict) -> list[dict]:
        """Check an event against all rules. Returns matching rules."""
        matches = []
        with self._lock:
            for rule in self.rules:
                if self._check_rule(rule, event):
                    matches.append(rule)
        return matches

    def _check_rule(self, rule: dict, event: dict) -> bool:
        cond = rule.get("condition", {})
        ctype = cond.get("type", "")

        if ctype == "exact":
            field = cond.get("field", "")
            value = cond.get("value", "")
            return event.get(field) == value

        if ctype == "contains":
            field = cond.get("field", "")
            value = cond.get("value", "").lower()
            return value in str(event.get(field, "")).lower()

        if ctype == "regex":
            field = cond.get("field", "")
            pattern = cond.get("pattern", "")
            return bool(re.search(pattern, str(event.get(field, ""))))

        if ctype == "port":
            return event.get("dst_port") == cond.get("value")

        return False

    def _watch_loop(self):
        """Reload rules if file changes."""
        while True:
            time.sleep(10)
            try:
                if os.path.exists(self.rules_path):
                    mtime = os.path.getmtime(self.rules_path)
                    if mtime > self._last_mtime:
                        self.reload()
                        logger.info("Rules hot-reloaded")
            except Exception:
                pass

    @property
    def stats(self) -> dict:
        with self._lock:
            return {"rules_loaded": len(self.rules), "rules_path": self.rules_path}


# ══════════════════════════════════════════════════
# 4. Weekly report generator
# ══════════════════════════════════════════════════

class WeeklyReport:
    """Generates and emails periodic summary reports."""

    def __init__(self, config, alert_fn=None):
        self.cfg = config
        self._alert = alert_fn
        self.enabled = config.get("reports.weekly_enabled", True)
        self.day = config.get("reports.weekly_day", "monday")
        self.hour = config.get("reports.weekly_hour", 8)

    def generate(self, days: int = 7) -> dict:
        """Generate a summary report for the last N days."""
        from core.database import Alert, Host, db

        since = datetime.now() - timedelta(days=days)
        report = {
            "period": f"Last {days} days",
            "generated_at": datetime.now().isoformat(),
            "alerts": {"total": 0, "by_severity": {}, "by_category": {}},
            "hosts": {"total": 0, "at_risk": 0},
            "incidents": {"total": 0, "resolved": 0, "pending": 0},
            "top_attackers": [],
            "top_targets": [],
        }

        try:
            with db.atomic():
                alerts = list(Alert.select().where(Alert.ts >= since))

            report["alerts"]["total"] = len(alerts)
            sev_counts = defaultdict(int)
            cat_counts = defaultdict(int)
            attackers = defaultdict(int)
            targets = defaultdict(int)

            for a in alerts:
                sev_counts[a.severity] += 1
                cat_counts[a.category] += 1
                if a.src_ip:
                    attackers[a.src_ip] += 1
                if a.dst_ip:
                    targets[a.dst_ip] += 1

            report["alerts"]["by_severity"] = dict(sev_counts)
            report["alerts"]["by_category"] = dict(
                sorted(cat_counts.items(), key=lambda x: -x[1])[:10])
            report["top_attackers"] = sorted(
                attackers.items(), key=lambda x: -x[1])[:10]
            report["top_targets"] = sorted(
                targets.items(), key=lambda x: -x[1])[:10]

            hosts = list(Host.select())
            report["hosts"]["total"] = len(hosts)
            report["hosts"]["at_risk"] = sum(
                1 for h in hosts if getattr(h, "risk_score", 0) > 50)

        except Exception as e:
            report["error"] = str(e)

        return report

    def generate_html(self, days: int = 7) -> str:
        """Generate HTML report."""
        data = self.generate(days)
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CyberGuard Weekly Report</title></head>
<body style="font-family:Arial;max-width:700px;margin:20px auto;padding:20px">
<h1 style="color:#1F2937">CyberGuard Sentinel — Weekly Report</h1>
<p style="color:#666">Period: {data['period']} | Generated: {data['generated_at']}</p>

<h2>Alerts</h2>
<table style="border-collapse:collapse;width:100%">
<tr><td style="padding:8px;border:1px solid #ddd"><strong>Total alerts</strong></td>
    <td style="padding:8px;border:1px solid #ddd">{data['alerts']['total']}</td></tr>
<tr><td style="padding:8px;border:1px solid #ddd"><strong>Critical (sev 1-2)</strong></td>
    <td style="padding:8px;border:1px solid #ddd;color:red">{data['alerts']['by_severity'].get(1,0) + data['alerts']['by_severity'].get(2,0)}</td></tr>
</table>

<h2>Top Attackers</h2>
<table style="border-collapse:collapse;width:100%">
<tr style="background:#f5f5f5"><th style="padding:8px;border:1px solid #ddd">IP</th>
    <th style="padding:8px;border:1px solid #ddd">Alerts</th></tr>
{''.join(f'<tr><td style="padding:8px;border:1px solid #ddd">{ip}</td><td style="padding:8px;border:1px solid #ddd">{c}</td></tr>' for ip, c in data['top_attackers'][:5])}
</table>

<h2>Hosts</h2>
<p>Total: {data['hosts']['total']} | At risk: {data['hosts']['at_risk']}</p>

<p style="color:#999;font-size:12px;margin-top:30px">
CyberGuard Sentinel v2.2.3 — Automated weekly report</p>
</body></html>"""


# ══════════════════════════════════════════════════
# 5. SIEM export (Syslog / CEF)
# ══════════════════════════════════════════════════

class SIEMExporter:
    """
    Exports alerts to external SIEM in CEF (Common Event Format).
    Supports syslog UDP/TCP transport.
    """

    def __init__(self, config):
        self.enabled = config.get("siem.enabled", False)
        self.host = config.get("siem.host", "")
        self.port = config.get("siem.port", 514)
        self.protocol = config.get("siem.protocol", "udp")
        self.facility = config.get("siem.facility", "local0")
        self._sock = None

        if self.enabled and self.host:
            self._connect()
            logger.info("SIEM export enabled: %s:%d (%s)",
                       self.host, self.port, self.protocol)

    def _connect(self):
        try:
            if self.protocol == "tcp":
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.connect((self.host, self.port))
            else:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception as e:
            logger.error("SIEM connection failed: %s", e)

    def export(self, severity: int, category: str, title: str,
               src_ip: str = "", dst_ip: str = "", detail: str = ""):
        """Export an alert in CEF format."""
        if not self.enabled or not self._sock:
            return

        # Map severity (1=critical → 10, 5=info → 1)
        cef_sev = max(1, min(10, 11 - severity * 2))

        cef = (
            f"CEF:0|CyberGuard|Sentinel|2.0|{category}|{title}|{cef_sev}|"
            f"src={src_ip} dst={dst_ip} msg={detail[:200]}"
        )

        syslog_msg = f"<{self._pri(cef_sev)}>{datetime.now().strftime('%b %d %H:%M:%S')} "
        syslog_msg += f"cyberguard: {cef}\n"

        try:
            if self.protocol == "tcp":
                self._sock.sendall(syslog_msg.encode())
            else:
                self._sock.sendto(syslog_msg.encode(), (self.host, self.port))
        except Exception as e:
            logger.debug("SIEM send failed: %s", e)
            self._connect()  # Reconnect

    def _pri(self, severity: int) -> int:
        """Compute syslog PRI value."""
        # local0 = facility 16
        facility = 16
        # Map CEF severity to syslog severity
        if severity >= 8:
            sev = 2   # critical
        elif severity >= 5:
            sev = 4   # warning
        else:
            sev = 6   # info
        return facility * 8 + sev


# ══════════════════════════════════════════════════
# 6. Threat intelligence feed (MISP / OpenCTI)
# ══════════════════════════════════════════════════

class ThreatIntel:
    """
    Queries external threat intelligence platforms for IOC enrichment.
    Supports MISP and OpenCTI REST APIs.
    """

    def __init__(self, config):
        self.misp_url = config.get("threat_intel.misp_url", "")
        self.misp_key = config.get("threat_intel.misp_key", "")
        self.opencti_url = config.get("threat_intel.opencti_url", "")
        self.opencti_token = config.get("threat_intel.opencti_token", "")
        self.enabled = bool(self.misp_url or self.opencti_url)

        # Local cache: IOC → {seen, severity, tags, source}
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()

        if self.enabled:
            logger.info("Threat intel enabled: MISP=%s OpenCTI=%s",
                       "yes" if self.misp_url else "no",
                       "yes" if self.opencti_url else "no")

    def check_ip(self, ip: str) -> dict:
        """Check an IP against threat intel sources. Returns enrichment data."""
        with self._lock:
            if ip in self._cache:
                cached = self._cache[ip]
                if time.time() - cached.get("checked_at", 0) < 3600:
                    return cached

        result = {"ip": ip, "known_malicious": False, "tags": [], "sources": [],
                  "checked_at": time.time()}

        if self.misp_url:
            misp_data = self._query_misp(ip)
            if misp_data:
                result["known_malicious"] = True
                result["tags"].extend(misp_data.get("tags", []))
                result["sources"].append("MISP")
                result["misp"] = misp_data

        if self.opencti_url:
            octi_data = self._query_opencti(ip)
            if octi_data:
                result["known_malicious"] = True
                result["tags"].extend(octi_data.get("labels", []))
                result["sources"].append("OpenCTI")
                result["opencti"] = octi_data

        with self._lock:
            self._cache[ip] = result

        return result

    def _query_misp(self, ip: str) -> dict:
        """Query MISP for an IP indicator."""
        if not self.misp_url or not self.misp_key:
            return {}
        try:
            import urllib.request
            url = f"{self.misp_url}/attributes/restSearch"
            data = json.dumps({"value": ip, "type": "ip-src", "limit": 5}).encode()
            req = urllib.request.Request(url, data=data, method="POST",
                headers={"Authorization": self.misp_key,
                         "Content-Type": "application/json", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                attrs = result.get("response", {}).get("Attribute", [])
                if attrs:
                    return {
                        "found": True,
                        "events": len(attrs),
                        "tags": list(set(
                            t.get("name", "") for a in attrs
                            for t in a.get("Tag", [])
                        )),
                    }
        except Exception as e:
            logger.debug("MISP query failed for %s: %s", ip, e)
        return {}

    def _query_opencti(self, ip: str) -> dict:
        """Query OpenCTI for an IP indicator."""
        if not self.opencti_url or not self.opencti_token:
            return {}
        try:
            import urllib.request
            url = f"{self.opencti_url}/graphql"
            query = {
                "query": f'''{{ stixCyberObservables(search: "{ip}", types: ["IPv4-Addr"]) {{
                    edges {{ node {{ observable_value, x_opencti_score,
                             objectLabel {{ edges {{ node {{ value }} }} }} }} }} }} }}'''
            }
            data = json.dumps(query).encode()
            req = urllib.request.Request(url, data=data, method="POST",
                headers={"Authorization": f"Bearer {self.opencti_token}",
                         "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                edges = result.get("data", {}).get("stixCyberObservables", {}).get("edges", [])
                if edges:
                    node = edges[0].get("node", {})
                    labels = [e["node"]["value"] for e in
                             node.get("objectLabel", {}).get("edges", [])]
                    return {
                        "found": True,
                        "score": node.get("x_opencti_score", 0),
                        "labels": labels,
                    }
        except Exception as e:
            logger.debug("OpenCTI query failed for %s: %s", ip, e)
        return {}

    @property
    def stats(self) -> dict:
        with self._lock:
            return {"enabled": self.enabled, "cached_iocs": len(self._cache),
                    "misp": bool(self.misp_url), "opencti": bool(self.opencti_url)}


# ══════════════════════════════════════════════════
# 7. False positive feedback & threshold adjustment
# ══════════════════════════════════════════════════

class FalsePositiveManager:
    """
    Tracks false positive feedback per host and adjusts detection
    thresholds accordingly. If an admin marks an alert as false positive,
    the system increases the threshold for that specific host + category
    combination, reducing future noise.
    """

    def __init__(self, config):
        self.data_dir = config.get("general.data_dir", "/var/lib/cyberguard/data")
        self.filepath = os.path.join(self.data_dir, "false_positives.json")
        self._lock = threading.Lock()
        # Structure: {ip: {category: {count, last_reported, threshold_boost}}}
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.filepath):
                with open(self.filepath) as f:
                    self._data = json.load(f)
        except Exception:
            self._data = {}

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
            with open(self.filepath, "w") as f:
                json.dump(self._data, f, indent=2)
        except Exception:
            pass

    def report_false_positive(self, ip: str, category: str) -> dict:
        """Admin reports an alert as false positive for this host + category."""
        with self._lock:
            if ip not in self._data:
                self._data[ip] = {}
            if category not in self._data[ip]:
                self._data[ip][category] = {
                    "count": 0, "threshold_boost": 0,
                    "last_reported": "",
                }

            entry = self._data[ip][category]
            entry["count"] += 1
            entry["last_reported"] = datetime.now().isoformat()

            # Increase threshold: each FP report adds 20% to the threshold
            # for this host + category (capped at 5x = 500%)
            entry["threshold_boost"] = min(500, entry["count"] * 20)

            self._save()
            logger.info("False positive recorded: %s/%s (count=%d, boost=%d%%)",
                       ip, category, entry["count"], entry["threshold_boost"])
            return entry

    def get_threshold_multiplier(self, ip: str, category: str) -> float:
        """
        Returns the threshold multiplier for a host + category.
        1.0 = normal, 2.0 = double threshold (fewer alerts), etc.
        """
        with self._lock:
            entry = self._data.get(ip, {}).get(category, {})
            boost = entry.get("threshold_boost", 0)
            return 1.0 + boost / 100.0

    def get_all(self) -> dict:
        with self._lock:
            return dict(self._data)

    def reset(self, ip: str, category: str = ""):
        """Reset false positive data for a host (and optionally category)."""
        with self._lock:
            if category:
                self._data.get(ip, {}).pop(category, None)
            else:
                self._data.pop(ip, None)
            self._save()
