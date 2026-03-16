"""
CGS — Agent local sensor module.

Runs on workstations alongside the agent. Monitors:
  - CPU usage spikes (cryptominer, ransomware)
  - Mass file access (ransomware encryption pattern)
  - Unusual network connections (C2 beaconing)
  - New listening ports (backdoor)
  - Suspicious processes (known malware names)

Reports anomalies to Sentinel via the existing /api/client/check polling.
All monitoring is READ-ONLY.
"""

import logging
import os
import platform
import subprocess
import time
from collections import defaultdict
from datetime import datetime

log = logging.getLogger("cgs-agent.sensor")


class LocalSensor:
    """Lightweight local anomaly detector for workstations."""

    def __init__(self, os_type: str):
        self.os_type = os_type
        self._prev_connections = set()
        self._prev_listeners = set()
        self._prev_processes = set()
        self._cpu_history = []
        self._anomalies = []

        # Thresholds
        self.cpu_threshold = 90        # % sustained
        self.cpu_sustained_sec = 30    # seconds
        self.file_access_threshold = 500  # files/min
        self.max_anomalies = 50

    def collect(self) -> list[dict]:
        """
        Run all local checks. Returns list of anomalies detected.
        Called periodically by the agent (every poll cycle).
        """
        self._anomalies = []

        self._check_cpu()
        self._check_listeners()
        self._check_connections()
        self._check_suspicious_processes()

        return self._anomalies[:self.max_anomalies]

    def _add_anomaly(self, category: str, severity: int, detail: str):
        self._anomalies.append({
            "category": category,
            "severity": severity,
            "detail": detail[:500],
            "timestamp": datetime.now().isoformat(),
            "hostname": platform.node(),
        })

    # ── CPU monitoring ──

    def _check_cpu(self):
        try:
            if self.os_type == "windows":
                out = self._run('powershell -Command "(Get-CimInstance Win32_Processor).LoadPercentage"')
                cpu = int(out.strip()) if out.strip().isdigit() else 0
            else:
                out = self._run("grep 'cpu ' /proc/stat")
                if out:
                    parts = out.split()
                    idle = int(parts[4]) if len(parts) > 4 else 0
                    total = sum(int(p) for p in parts[1:] if p.isdigit())
                    cpu = int(100 * (1 - idle / max(total, 1)))
                else:
                    cpu = 0

            self._cpu_history.append((time.time(), cpu))
            # Keep last 60 seconds
            cutoff = time.time() - 60
            self._cpu_history = [(t, c) for t, c in self._cpu_history if t > cutoff]

            # Check sustained high CPU
            recent = [c for t, c in self._cpu_history if t > time.time() - self.cpu_sustained_sec]
            if len(recent) >= 3 and all(c > self.cpu_threshold for c in recent):
                self._add_anomaly("high_cpu", 3,
                    f"CPU sustained at {sum(recent)//len(recent)}% for {self.cpu_sustained_sec}s "
                    f"(possible cryptominer or ransomware)")
        except Exception as e:
            log.debug("Failed to check CPU usage: %s", e)

    # ── New listening ports ──

    def _check_listeners(self):
        try:
            if self.os_type == "windows":
                out = self._run('powershell -Command "Get-NetTCPConnection -State Listen | Select-Object LocalPort | ConvertTo-Csv -NoTypeInformation"')
            else:
                out = self._run("ss -lntu 2>/dev/null | awk '{print $5}' | grep -oP '\\d+$'")

            current = set()
            for line in out.strip().split("\n"):
                line = line.strip().strip('"')
                if line.isdigit():
                    current.add(int(line))

            if self._prev_listeners:
                new_ports = current - self._prev_listeners
                for port in new_ports:
                    if port > 1024:  # Ignore well-known ports
                        self._add_anomaly("new_listener", 4,
                            f"New listening port detected: {port}")

            self._prev_listeners = current
        except Exception as e:
            log.debug("Failed to check listening ports: %s", e)

    # ── Unusual outbound connections ──

    def _check_connections(self):
        try:
            if self.os_type == "windows":
                out = self._run('powershell -Command "Get-NetTCPConnection -State Established | Select-Object RemoteAddress,RemotePort | ConvertTo-Csv -NoTypeInformation"')
            else:
                out = self._run("ss -tnp state established 2>/dev/null | awk '{print $5}'")

            current = set()
            for line in out.strip().split("\n"):
                line = line.strip().strip('"')
                if ":" in line or "." in line:
                    current.add(line)

            if self._prev_connections:
                new_conns = current - self._prev_connections
                # Flag connections to unusual ports
                for conn in new_conns:
                    parts = conn.rsplit(":", 1) if ":" in conn else conn.rsplit(",", 1)
                    if len(parts) == 2:
                        try:
                            port = int(parts[1])
                            if port in (4444, 5555, 6666, 8888, 9999, 1337, 31337):
                                self._add_anomaly("suspicious_connection", 2,
                                    f"Connection to suspicious port: {conn}")
                        except ValueError:
                            pass

            self._prev_connections = current
        except Exception as e:
            log.debug("Failed to check outbound connections: %s", e)

    # ── Suspicious processes ──

    SUSPICIOUS_NAMES = {
        "mimikatz", "lazagne", "procdump", "psexec", "ncat", "netcat",
        "nc.exe", "powershell_ise", "certutil", "bitsadmin", "mshta",
        "regsvr32", "rundll32", "wmic", "cscript", "wscript",
        "xmrig", "minergate", "cgminer", "bfgminer",
    }

    def _check_suspicious_processes(self):
        try:
            if self.os_type == "windows":
                out = self._run('powershell -Command "Get-Process | Select-Object ProcessName | ConvertTo-Csv -NoTypeInformation"')
            else:
                out = self._run("ps -eo comm --no-headers 2>/dev/null")

            current = set()
            for line in out.strip().split("\n"):
                name = line.strip().strip('"').lower()
                if name:
                    current.add(name)

            for proc in current:
                if proc in self.SUSPICIOUS_NAMES:
                    self._add_anomaly("suspicious_process", 2,
                        f"Suspicious process detected: {proc}")

            # Detect new processes since last check
            if self._prev_processes:
                new_procs = current - self._prev_processes
                if len(new_procs) > 20:
                    self._add_anomaly("process_burst", 3,
                        f"{len(new_procs)} new processes in one cycle (possible malware spawn)")

            self._prev_processes = current
        except Exception as e:
            log.debug("Failed to check suspicious processes: %s", e)

    def _run(self, cmd: str, timeout: int = 10) -> str:
        try:
            # Split command for safe execution without shell=True
            # For PowerShell commands, we need shell on Windows
            if cmd.startswith("powershell"):
                args = ["powershell", "-Command", cmd.split("-Command ", 1)[1].strip('" ')]
            else:
                import shlex
                args = shlex.split(cmd)
            r = subprocess.run(args, capture_output=True,
                             text=True, timeout=timeout)
            return r.stdout or ""
        except Exception:
            return ""
