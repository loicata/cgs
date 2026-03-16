#!/usr/bin/env python3
"""
CGS — Secure Client Agent (runs on workstations).

Security architecture:
  - Sentinel NEVER connects to this machine
  - Admin NEVER connects to this machine
  - Agent authenticates Sentinel with a shared secret (configured at install)
  - Popup messages are PREDEFINED locally — server only sends a type code,
    never arbitrary text (prevents social engineering via compromised Sentinel)
  - Forensic reports are saved to Desktop ONLY — never sent anywhere
  - User must consent to forensic collection via popup

Usage:
  python3 cgs-agent.py --server https://192.168.1.100:8443 --secret MY_SHARED_KEY
  python3 cgs-agent.py --server https://sentinel:8443 --secret MY_KEY --no-verify-ssl

The --secret must match client_agent.shared_secret in Sentinel's config.yaml.
"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import platform
import subprocess
import sys
import time
import urllib.request
import urllib.error
import ssl
from datetime import datetime
from pathlib import Path

__version__ = "2.2.3"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("cgs-agent")


# ══════════════════════════════════════════════════
# PREDEFINED MESSAGES — hardcoded, not from server
# ══════════════════════════════════════════════════
# The server only sends a message TYPE ("shutdown", "all_clear", etc.).
# The actual text shown to the user is defined HERE, in the agent.
# A compromised Sentinel cannot change what the user sees.

MESSAGES = {
    "shutdown": {
        "title": "SECURITY ALERT — CGS",
        "body": (
            "A cyberattack has been detected targeting your computer.\n\n"
            "Please shut down your computer IMMEDIATELY.\n\n"
            "You will receive a notification once the threat has been "
            "eradicated and it is safe to restart.\n\n"
            "If your computer is the only way to access your emails, "
            "please contact the IT security team directly."
        ),
    },
    "all_clear": {
        "title": "Threat resolved — CGS",
        "body": (
            "The cyberattack has been successfully neutralized.\n\n"
            "You can turn your computer back on and resume work normally.\n\n"
            "If you have any questions, please contact the IT security team."
        ),
    },
    "risk_warning": {
        "title": "WARNING — Do NOT restart — CGS",
        "body": (
            "The incident has been partially resolved but a residual "
            "risk remains.\n\n"
            "Do NOT turn your computer back on.\n\n"
            "Please contact the IT security team for instructions."
        ),
    },
    "collect_forensic": {
        "title": "Security scan request — CGS",
        "body": (
            "The security team requests a local security scan of your "
            "computer following a recent incident.\n\n"
            "This scan is READ-ONLY and will not modify anything.\n"
            "A report will be saved to your Desktop.\n"
            "The report stays on YOUR computer — it is NOT sent anywhere.\n\n"
            "Click OK to proceed, or close this window to decline."
        ),
    },
    "collect_done": {
        "title": "Scan complete — CGS",
        "body": (
            "The security scan is complete.\n\n"
            "The report has been saved to your Desktop.\n"
            "You can review it and decide whether to share it with "
            "the security team."
        ),
    },
}

# Only these types are accepted — anything else is silently ignored
ALLOWED_TYPES = set(MESSAGES.keys())


# ══════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════

class AgentConfig:
    def __init__(self, args):
        url = args.server.rstrip("/")
        if not url.startswith("https://"):
            raise ValueError("Server URL must use https:// scheme")
        self.server_url = url
        self.shared_secret = args.secret
        self.verify_ssl = not args.no_verify_ssl
        self.hostname = platform.node()
        self.username = (os.environ.get("USER") or
                         os.environ.get("USERNAME") or "unknown")
        self.os_type = self._detect_os()
        self.desktop_path = self._find_desktop()

    def _detect_os(self) -> str:
        s = platform.system().lower()
        if "windows" in s:
            return "windows"
        if "darwin" in s:
            return "macos"
        return "linux"

    def _find_desktop(self) -> str:
        home = Path.home()
        desktop = home / "Desktop"
        if not desktop.exists():
            for name in ("Bureau", "Escritorio", "Schreibtisch"):
                alt = home / name
                if alt.exists():
                    return str(alt)
            return str(home)
        return str(desktop)


# ══════════════════════════════════════════════════
# Sentinel API client (outbound only, authenticated)
# ══════════════════════════════════════════════════

class SentinelClient:
    """Communicates with Sentinel. Outbound ONLY. Authenticated via HMAC."""

    def __init__(self, config: AgentConfig):
        self.cfg = config
        self.base = config.server_url
        self._ctx = ssl.create_default_context()
        if not config.verify_ssl:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _sign(self, payload: str) -> str:
        """Compute HMAC-SHA256 signature using shared secret."""
        return hmac.new(
            self.cfg.shared_secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

    def _verify_response(self, data: dict) -> bool:
        """Verify server response signature (server proves its identity)."""
        server_sig = data.get("_sig", "")
        if not server_sig:
            return False
        check_data = {k: v for k, v in data.items() if k != "_sig"}
        expected = self._sign(json.dumps(check_data, sort_keys=True))
        return hmac.compare_digest(server_sig, expected)

    def check(self) -> tuple[list, int]:
        """
        Poll Sentinel. Returns (messages, poll_interval).
        Verifies server identity via HMAC signature.
        """
        try:
            timestamp = str(int(time.time()))
            sig = self._sign(f"check:{self.cfg.hostname}:{timestamp}")

            url = (f"{self.base}/api/client/check"
                   f"?hostname={self.cfg.hostname}"
                   f"&ts={timestamp}&sig={sig}")
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, context=self._ctx, timeout=10) as resp:  # nosec B310 — scheme validated in AgentConfig.__init__
                data = json.loads(resp.read())

                if not self._verify_response(data):
                    log.warning("Server signature INVALID — ignoring response "
                               "(possible MITM or compromised Sentinel)")
                    return [], 60

                messages = [
                    m for m in data.get("messages", [])
                    if m.get("type") in ALLOWED_TYPES
                ]
                return messages, data.get("poll_interval", 60)

        except urllib.error.URLError:
            return [], 60
        except Exception as e:
            log.debug("Poll failed: %s", e)
            return [], 60

    def ack(self, message_id: str) -> bool:
        """Acknowledge a message (authenticated)."""
        try:
            payload = json.dumps({
                "message_id": message_id,
                "hostname": self.cfg.hostname,
                "user": self.cfg.username,
                "ts": str(int(time.time())),
            }, sort_keys=True)
            sig = self._sign(payload)

            url = f"{self.base}/api/client/ack"
            body = json.dumps({
                **json.loads(payload),
                "_sig": sig,
            }).encode()
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, context=self._ctx, timeout=10) as resp:  # nosec B310 — scheme validated in AgentConfig.__init__
                return resp.status == 200
        except Exception as e:
            log.debug("Ack failed: %s", e)
            return False


# ══════════════════════════════════════════════════
# Local popup display (predefined messages only)
# ══════════════════════════════════════════════════

def show_popup(msg_type: str, os_type: str = "linux") -> bool:
    """
    Display a PREDEFINED popup. msg_type must be in MESSAGES.
    Returns True if user acknowledged.
    """
    if msg_type not in MESSAGES:
        log.warning("Unknown message type '%s' — ignoring", msg_type)
        return False

    title = MESSAGES[msg_type]["title"]
    body = MESSAGES[msg_type]["body"]

    try:
        if os_type == "windows":
            return _popup_windows(title, body)
        elif os_type == "macos":
            return _popup_macos(title, body)
        else:
            return _popup_linux(title, body)
    except Exception as e:
        log.warning("Popup failed: %s", e)
        return False


def _popup_windows(title: str, body: str) -> bool:
    ps_cmd = (
        'Add-Type -AssemblyName System.Windows.Forms; '
        '[System.Windows.Forms.MessageBox]::Show('
        f'"{body}", "{title}", "OK", "Warning")'
    )
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=600,
        )
        return "OK" in result.stdout
    except Exception:
        return False


def _popup_linux(title: str, body: str) -> bool:
    env = os.environ.copy()
    env.setdefault("DISPLAY", ":0")
    for cmd_args in [
        ["zenity", "--warning", f"--title={title}", f"--text={body}",
         "--width=500", "--no-wrap"],
        ["kdialog", "--sorry", body, "--title", title],
        ["xmessage", "-center", "-buttons", "OK", f"{title}\n\n{body}"],
    ]:
        try:
            result = subprocess.run(
                cmd_args, env=env, capture_output=True, timeout=600)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    try:
        subprocess.run(["notify-send", "-u", "critical", title, body],
                      env=env, capture_output=True, timeout=5)
    except Exception as e:
        log.debug("Failed to send desktop notification: %s", e)
    return False


def _popup_macos(title: str, body: str) -> bool:
    try:
        script = (
            f'display dialog "{body}" with title "{title}" '
            f'buttons {{"OK"}} default button 1 with icon caution '
            f'giving up after 600')
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=620)
        return result.returncode == 0
    except Exception:
        return False


# ══════════════════════════════════════════════════
# Local forensic collection (Desktop only, NEVER sent)
# ══════════════════════════════════════════════════

def collect_local_forensics(config: AgentConfig, incident_id: str) -> str:
    """
    Collects forensic evidence LOCALLY. READ-ONLY.
    Saves to Desktop ONLY. NEVER sends data anywhere.
    Returns filepath of saved report.
    """
    log.info("Starting local forensic collection (read-only)...")
    report = {
        "_notice": (
            "This report was generated locally on this computer. "
            "It has NOT been sent to anyone. You can review it and "
            "decide whether to share it with the security team."
        ),
        "agent_version": __version__,
        "hostname": config.hostname,
        "username": config.username,
        "os": config.os_type,
        "os_detail": platform.platform(),
        "incident_id": incident_id,
        "collected_at": datetime.now().isoformat(),
        "evidence": {},
        "scan": {},
    }

    if config.os_type == "windows":
        report["evidence"] = _collect_windows()
        report["scan"] = _scan_windows()
    else:
        report["evidence"] = _collect_unix(macos=(config.os_type == "macos"))
        report["scan"] = _scan_unix()

    filename = (f"CGS_Forensic_{incident_id}_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    filepath = os.path.join(config.desktop_path, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str, ensure_ascii=False)

    log.info("Report saved to Desktop: %s", filepath)
    log.info("NOT sent anywhere — you decide whether to share it.")
    return filepath


def _run_local(cmd: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ["/bin/sh", "-c", cmd],
            capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip() or result.stderr.strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return f"[error: {e}]"


def _collect_unix(macos: bool = False) -> dict:
    e = {}
    cmds = {
        "hostname": "hostname", "uname": "uname -a", "uptime": "uptime",
        "processes": "ps auxww",
        "connections": "ss -anp 2>/dev/null || netstat -anp 2>/dev/null",
        "listening": "ss -lntu 2>/dev/null || netstat -lntu 2>/dev/null",
        "arp_table": "arp -an 2>/dev/null || ip neigh 2>/dev/null",
        "routes": "ip route 2>/dev/null || netstat -rn 2>/dev/null",
        "dns_config": "cat /etc/resolv.conf 2>/dev/null",
        "last_logins": "last -20 2>/dev/null", "who": "w 2>/dev/null",
        "crontabs": "crontab -l 2>/dev/null",
        "users": "cat /etc/passwd 2>/dev/null",
        "recent_tmp": "find /tmp -type f -mtime -1 -ls 2>/dev/null | head -30",
        "open_files_net": "lsof -i -P -n 2>/dev/null | head -40",
    }
    if not macos:
        cmds["systemd_timers"] = "systemctl list-timers --all 2>/dev/null"
        cmds["systemd_enabled"] = "systemctl list-unit-files --state=enabled 2>/dev/null"
        cmds["modules"] = "lsmod 2>/dev/null"
        cmds["auth_log"] = ("tail -100 /var/log/auth.log 2>/dev/null || "
                            "journalctl -u sshd -n 100 --no-pager 2>/dev/null")
        cmds["syslog"] = ("tail -50 /var/log/syslog 2>/dev/null || "
                          "journalctl -n 50 --no-pager 2>/dev/null")
    else:
        cmds["launchd"] = "launchctl list 2>/dev/null | head -30"
    for key, cmd in cmds.items():
        result = _run_local(cmd)
        if result and "[error" not in result:
            e[key] = result
    return e


def _collect_windows() -> dict:
    e = {}
    cmds = {
        "hostname": "hostname",
        "systeminfo": 'powershell -Command "systeminfo | Select-Object -First 25"',
        "processes": 'powershell -Command "Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Csv"',
        "services": 'powershell -Command "Get-Service | Where-Object {$_.Status -eq \'Running\'} | Select-Object Name,DisplayName | ConvertTo-Csv"',
        "connections": 'powershell -Command "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | ConvertTo-Csv"',
        "listening": 'powershell -Command "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort | ConvertTo-Csv"',
        "dns_cache": 'powershell -Command "Get-DnsClientCache | Select-Object -First 30 | ConvertTo-Csv"',
        "arp_table": "arp -a", "routes": "route print",
        "logged_in": 'powershell -Command "query user 2>$null"',
        "scheduled_tasks": 'powershell -Command "Get-ScheduledTask | Where-Object {$_.State -ne \'Disabled\'} | Select-Object TaskName,TaskPath,State | ConvertTo-Csv"',
        "startup": 'powershell -Command "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | ConvertTo-Csv"',
        "local_users": 'powershell -Command "Get-LocalUser | Select-Object Name,Enabled,LastLogon | ConvertTo-Csv"',
        "recent_events": 'powershell -Command "Get-EventLog -LogName Security -Newest 30 | Select-Object TimeGenerated,EntryType,Message | ConvertTo-Csv"',
        "temp_files": 'powershell -Command "Get-ChildItem $env:TEMP -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv"',
        "defender_status": 'powershell -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Csv"',
        "shares": "net share",
    }
    for key, cmd in cmds.items():
        result = _run_local(cmd, timeout=60)
        if result and "[error" not in result:
            e[key] = result
    return e


def _scan_unix() -> dict:
    scan = {"available": False, "results": ""}
    check = _run_local("command -v clamscan && echo FOUND")
    if "FOUND" in check:
        scan.update({"available": True, "engine": "ClamAV",
            "results": _run_local("clamscan --infected --no-summary --recursive /tmp /var/tmp /home 2>/dev/null | head -50", 300) or "No threats found",
            "scan_time": datetime.now().isoformat()})
        return scan
    check = _run_local("command -v rkhunter && echo FOUND")
    if "FOUND" in check:
        scan.update({"available": True, "engine": "rkhunter",
            "results": _run_local("rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | head -50", 300) or "No threats found",
            "scan_time": datetime.now().isoformat()})
        return scan
    scan["results"] = "No AV engine available"
    return scan


def _scan_windows() -> dict:
    scan = {"available": False, "results": ""}
    status = _run_local('powershell -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled | ConvertTo-Csv"')
    if "True" in status:
        scan["available"] = True; scan["engine"] = "Windows Defender"
        _run_local('powershell -Command "Start-MpScan -ScanType QuickScan"', 300)
        scan["threats"] = _run_local('powershell -Command "Get-MpThreatDetection | Select-Object ThreatID,ProcessName,InitialDetectionTime | ConvertTo-Csv"') or "No threats"
        scan["threat_catalog"] = _run_local('powershell -Command "Get-MpThreat | Select-Object ThreatID,ThreatName,SeverityID,IsActive | ConvertTo-Csv"') or "No active threats"
        scan["scan_time"] = datetime.now().isoformat()
    else:
        scan["results"] = "Windows Defender not available"
    return scan


# ══════════════════════════════════════════════════
# Main loop
# ══════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="CGS Client Agent — secure, zero-privilege",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Security:\n"
            "  --secret authenticates both agent and Sentinel (HMAC-SHA256)\n"
            "  Popup messages are PREDEFINED locally (server sends type codes only)\n"
            "  Forensic reports are saved to Desktop only (never sent anywhere)\n\n"
            "Examples:\n"
            "  python3 cgs-agent.py --server https://192.168.1.100:8443 --secret MyKey123\n"))
    parser.add_argument("--server", required=True, help="Sentinel URL (https://ip:port)")
    parser.add_argument("--secret", required=True, help="Shared secret (must match Sentinel config)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Skip SSL verification")
    parser.add_argument("--once", action="store_true", help="Check once and exit")
    parser.add_argument("--version", action="version", version=f"cgs-agent {__version__}")
    args = parser.parse_args()

    config = AgentConfig(args)
    client = SentinelClient(config)

    log.info("CGS Agent v%s started", __version__)
    log.info("  Hostname : %s", config.hostname)
    log.info("  OS       : %s", config.os_type)
    log.info("  Server   : %s", config.server_url)
    log.info("  Auth     : HMAC-SHA256 (shared secret)")
    log.info("  Messages : predefined locally (type codes only from server)")
    log.info("  Forensic : Desktop only (never sent)")
    log.info("  Polling  : adaptive (60s idle / 5s active)")
    log.info("")

    poll_interval = 60

    while True:
        try:
            messages, server_interval = client.check()
            poll_interval = server_interval

            for msg in messages:
                msg_id = msg.get("id", "")
                msg_type = msg.get("type", "")
                incident_id = msg.get("incident_id", "")

                if msg_type not in ALLOWED_TYPES:
                    log.warning("Rejected unknown message type: '%s'", msg_type)
                    client.ack(msg_id)
                    continue

                log.info("Received: %s (incident %s)", msg_type, incident_id)

                if msg_type in ("shutdown", "all_clear", "risk_warning"):
                    acked = show_popup(msg_type, config.os_type)
                    client.ack(msg_id)
                    log.info("Popup: %s (acked=%s)", msg_type, acked)

                elif msg_type == "collect_forensic":
                    user_ok = show_popup("collect_forensic", config.os_type)
                    client.ack(msg_id)
                    if user_ok:
                        log.info("User approved forensic collection")
                        filepath = collect_local_forensics(config, incident_id)
                        show_popup("collect_done", config.os_type)
                    else:
                        log.info("User declined forensic collection")

        except KeyboardInterrupt:
            log.info("Agent stopped.")
            sys.exit(0)
        except Exception as e:
            log.debug("Error: %s", e)

        if args.once:
            break
        time.sleep(poll_interval)


if __name__ == "__main__":
    main()
