"""
CGS — Resilience & self-protection module.

Prevents silent failures under server load:

  1. SelfMonitor     — Watches CPU, RAM, disk I/O, disk space of the Sentinel
                       server itself. Fires alerts when thresholds are exceeded.
  2. DegradedMode    — When resources are critical, disables non-essential tasks
                       (reports, recon, baseline) and keeps only capture + defense.
  3. BufferGuard     — Monitors kernel packet drop counters and increases
                       socket buffer if drops detected.
  4. BackupSafe      — Runs backups with ionice/nice to avoid starving the daemon.
  5. WAL mode        — Configures SQLite in WAL mode to allow concurrent reads
                       during writes (no more "database is locked").
"""

import logging
import os
import subprocess
import threading
import time

logger = logging.getLogger("cgs.resilience")


# ══════════════════════════════════════════════════
# 1. Self-monitoring
# ══════════════════════════════════════════════════

class SelfMonitor:
    """
    Monitors the Sentinel server's own health.
    Fires alerts and triggers degraded mode when thresholds are exceeded.
    """

    def __init__(self, config, alert_fn=None, degraded_mode=None):
        self.cfg = config
        self._alert = alert_fn or (lambda **kw: None)
        self._degraded = degraded_mode

        # Thresholds
        self.cpu_threshold = config.get("resilience.cpu_threshold", 85)
        self.ram_threshold = config.get("resilience.ram_threshold", 90)
        self.disk_threshold = config.get("resilience.disk_threshold", 90)
        self.iowait_threshold = config.get("resilience.iowait_threshold", 50)

        # State
        self._prev_cpu = None
        self._consecutive_overload = 0
        self._overload_threshold = 3  # 3 consecutive checks before degraded mode

    def check(self) -> dict:
        """Run all self-health checks. Returns status dict."""
        status = {
            "cpu_percent": self._get_cpu(),
            "ram_percent": self._get_ram(),
            "disk_percent": self._get_disk(),
            "iowait_percent": self._get_iowait(),
            "load_avg": self._get_load(),
            "overloaded": False,
            "degraded_mode": False,
        }

        alerts = []
        if status["cpu_percent"] > self.cpu_threshold:
            alerts.append(f"CPU at {status['cpu_percent']}% (threshold {self.cpu_threshold}%)")
        if status["ram_percent"] > self.ram_threshold:
            alerts.append(f"RAM at {status['ram_percent']}% (threshold {self.ram_threshold}%)")
        if status["disk_percent"] > self.disk_threshold:
            alerts.append(f"Disk at {status['disk_percent']}% (threshold {self.disk_threshold}%)")
        if status["iowait_percent"] > self.iowait_threshold:
            alerts.append(f"I/O wait at {status['iowait_percent']}% (threshold {self.iowait_threshold}%)")

        if alerts:
            self._consecutive_overload += 1
            status["overloaded"] = True

            # Fire alert
            self._alert(
                severity=2 if self._consecutive_overload >= self._overload_threshold else 3,
                source="self_monitor",
                category="server_overload",
                title=f"Sentinel server overloaded ({self._consecutive_overload} consecutive)",
                detail=" | ".join(alerts),
            )

            # Enter degraded mode if sustained
            if self._consecutive_overload >= self._overload_threshold and self._degraded:
                if not self._degraded.active:
                    self._degraded.enter(reason=" | ".join(alerts))
                    status["degraded_mode"] = True
        else:
            # Recovery
            if self._consecutive_overload > 0 and self._degraded and self._degraded.active:
                self._degraded.exit()
            self._consecutive_overload = 0

        status["degraded_mode"] = self._degraded.active if self._degraded else False
        return status

    def _get_cpu(self) -> float:
        try:
            with open("/proc/stat") as f:
                line = f.readline()
            parts = line.split()
            idle = int(parts[4])
            total = sum(int(p) for p in parts[1:8])

            if self._prev_cpu is None:
                self._prev_cpu = (idle, total)
                return 0.0

            prev_idle, prev_total = self._prev_cpu
            self._prev_cpu = (idle, total)

            d_idle = idle - prev_idle
            d_total = total - prev_total
            if d_total == 0:
                return 0.0
            return round(100.0 * (1.0 - d_idle / d_total), 1)
        except Exception:
            return 0.0

    def _get_ram(self) -> float:
        try:
            with open("/proc/meminfo") as f:
                lines = f.readlines()
            info = {}
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    info[parts[0].rstrip(":")] = int(parts[1])
            total = info.get("MemTotal", 1)
            available = info.get("MemAvailable", total)
            return round(100.0 * (1.0 - available / total), 1)
        except Exception:
            return 0.0

    def _get_disk(self) -> float:
        try:
            st = os.statvfs("/var/log/cgs")
            used = (st.f_blocks - st.f_bfree) / max(st.f_blocks, 1)
            return round(used * 100, 1)
        except Exception:
            return 0.0

    def _get_iowait(self) -> float:
        try:
            with open("/proc/stat") as f:
                line = f.readline()
            parts = line.split()
            if len(parts) >= 6:
                iowait = int(parts[5])
                total = sum(int(p) for p in parts[1:8])
                return round(100.0 * iowait / max(total, 1), 1)
        except Exception as e:
            logger.debug("Failed to read I/O wait: %s", e)
        return 0.0

    def _get_load(self) -> list:
        try:
            return list(os.getloadavg())
        except Exception:
            return [0.0, 0.0, 0.0]


# ══════════════════════════════════════════════════
# 2. Degraded mode
# ══════════════════════════════════════════════════

class DegradedMode:
    """
    When active, non-essential tasks are suspended to preserve
    resources for packet capture and defense actions.

    Suspended:
      - ARP sweep (discovery)
      - Port scanning
      - Baseline computation
      - Anomaly detection
      - Weekly reports
      - Backups

    Kept running:
      - Packet capture (sniffer) — CRITICAL
      - Threat detection engine — CRITICAL
      - Defense actions (iptables) — CRITICAL
      - Alert engine — CRITICAL
      - Kill chain detector — CRITICAL
      - Incident response — CRITICAL
      - Client agent polling (lightweight) — KEPT
    """

    def __init__(self, config, alert_fn=None):
        self.cfg = config
        self._alert = alert_fn or (lambda **kw: None)
        self.active = False
        self.entered_at = 0.0
        self.reason = ""
        self._lock = threading.Lock()

    def enter(self, reason: str = ""):
        with self._lock:
            if self.active:
                return
            self.active = True
            self.entered_at = time.time()
            self.reason = reason
        logger.warning("⚠️ DEGRADED MODE ACTIVATED: %s", reason)
        logger.warning("   Suspended: discovery, port scan, baseline, reports, backups")
        logger.warning("   Kept: capture, detection, defense, incidents, alerts")
        self._alert(
            severity=2, source="resilience", category="degraded_mode",
            title="Sentinel entered DEGRADED MODE",
            detail=f"Reason: {reason}. Non-essential tasks suspended to preserve "
                   f"resources for packet capture and defense.",
        )

    def exit(self):
        with self._lock:
            if not self.active:
                return
            duration = int(time.time() - self.entered_at)
            self.active = False
            self.reason = ""
        logger.info("✅ Degraded mode DEACTIVATED after %ds — full operations resumed", duration)
        self._alert(
            severity=5, source="resilience", category="degraded_mode_exit",
            title="Sentinel exited degraded mode",
            detail=f"Server resources recovered after {duration}s. Full operations resumed.",
        )

    def should_run(self, task_name: str) -> bool:
        """
        Check if a task should run. Returns False for non-essential
        tasks when in degraded mode.
        """
        if not self.active:
            return True

        # Essential tasks always run
        essential = {
            "sniffer", "threat_engine", "defense", "alert",
            "incident", "killchain", "client_poll",
        }
        if task_name in essential:
            return True

        # Non-essential tasks are suspended
        logger.debug("Task '%s' suspended (degraded mode)", task_name)
        return False

    @property
    def stats(self) -> dict:
        return {
            "active": self.active,
            "reason": self.reason,
            "duration": int(time.time() - self.entered_at) if self.active else 0,
        }


# ══════════════════════════════════════════════════
# 3. Kernel buffer guard (packet drop prevention)
# ══════════════════════════════════════════════════

class BufferGuard:
    """
    Monitors kernel packet drops on the capture interface.
    If drops are detected, increases the socket buffer size.
    """

    def __init__(self, config, alert_fn=None):
        self.cfg = config
        self._alert = alert_fn or (lambda **kw: None)
        self.interface = config.get("general.interface", "eth0")
        self._prev_drops = None
        self._buffer_increased = False

        # Try to set initial buffer size
        self._set_rmem()

    def _set_rmem(self):
        """Increase kernel receive buffer max to 16MB."""
        try:
            with open("/proc/sys/net/core/rmem_max") as f:
                current = int(f.read().strip())
            target = 16 * 1024 * 1024  # 16 MB
            if current < target:
                with open("/proc/sys/net/core/rmem_max", "w") as f:
                    f.write(str(target))
                logger.info("Increased rmem_max: %d → %d bytes", current, target)
        except (PermissionError, FileNotFoundError) as e:
            logger.debug("Failed to set rmem_max: %s", e)

    def check(self) -> dict:
        """Check for packet drops. Returns stats."""
        stats = {"drops": 0, "delta": 0, "buffer_increased": self._buffer_increased}

        try:
            with open(f"/sys/class/net/{self.interface}/statistics/rx_dropped") as f:
                drops = int(f.read().strip())
            stats["drops"] = drops

            if self._prev_drops is not None:
                delta = drops - self._prev_drops
                stats["delta"] = delta

                if delta > 0:
                    logger.warning("⚠️ %d packets dropped on %s since last check",
                                  delta, self.interface)
                    self._alert(
                        severity=3, source="resilience", category="packet_drops",
                        title=f"{delta} packets dropped on {self.interface}",
                        detail=f"Total drops: {drops}. Possible capture gap — "
                               f"attacks may go undetected.",
                    )

                    # Try to increase buffer
                    if not self._buffer_increased:
                        self._increase_sniff_buffer()

            self._prev_drops = drops
        except (FileNotFoundError, ValueError) as e:
            logger.debug("Failed to read packet drop stats: %s", e)

        return stats

    def _increase_sniff_buffer(self):
        """Increase scapy sniff buffer via setsockopt."""
        try:
            # This is informational — the actual increase happens in sniffer.py
            # We set the kernel global max here
            with open("/proc/sys/net/core/rmem_default", "w") as f:
                f.write(str(8 * 1024 * 1024))  # 8 MB default
            self._buffer_increased = True
            logger.info("Increased default socket buffer to 8 MB")
        except (PermissionError, FileNotFoundError) as e:
            logger.debug("Failed to increase sniff buffer: %s", e)


# ══════════════════════════════════════════════════
# 4. Safe backup (non-blocking)
# ══════════════════════════════════════════════════

class SafeBackup:
    """
    Wraps BackupManager to run backups with:
      - ionice (class 3 = idle I/O priority)
      - nice (low CPU priority)
      - SQLite .backup() API (online, non-blocking)
    """

    def __init__(self, config, backup_manager, degraded_mode=None):
        self.cfg = config
        self.backup_mgr = backup_manager
        self._degraded = degraded_mode
        self._running = False
        self._lock = threading.Lock()

    def run(self) -> str:
        """Run a safe, non-blocking backup. Returns filepath or empty string."""
        with self._lock:
            if self._running:
                logger.info("Backup already in progress — skipping")
                return ""
            self._running = True

        try:
            # Skip if in degraded mode
            if self._degraded and self._degraded.active:
                logger.info("Backup skipped (degraded mode)")
                return ""

            # First, create a safe SQLite copy using .backup() API
            self._safe_sqlite_copy()

            # Run backup at low I/O priority
            filepath = self._low_priority_backup()
            return filepath

        except Exception as e:
            logger.error("Safe backup failed: %s", e)
            return ""
        finally:
            with self._lock:
                self._running = False

    def _safe_sqlite_copy(self):
        """Create a consistent SQLite copy using the backup API (non-blocking)."""
        import sqlite3

        src_path = os.path.join(
            self.cfg.get("general.data_dir", "/var/lib/cgs/data"),
            "cgs.db"
        )
        dst_path = src_path + ".backup"

        if not os.path.exists(src_path):
            return

        try:
            src = sqlite3.connect(src_path)
            dst = sqlite3.connect(dst_path)
            src.backup(dst, pages=100, sleep=0.05)  # 100 pages at a time, 50ms pause
            dst.close()
            src.close()
            logger.debug("SQLite online backup completed: %s", dst_path)
        except Exception as e:
            logger.warning("SQLite backup API failed: %s", e)

    def _low_priority_backup(self) -> str:
        """Run the actual backup with low I/O and CPU priority."""
        # Set our own process to idle I/O class
        try:
            pid = os.getpid()
            subprocess.run(["ionice", "-c", "3", "-p", str(pid)],
                          capture_output=True, timeout=5)
            subprocess.run(["renice", "19", "-p", str(pid)],
                          capture_output=True, timeout=5)
        except Exception as e:
            logger.debug("Failed to set low I/O priority for backup: %s", e)

        filepath = self.backup_mgr.create()

        # Restore normal priority
        try:
            pid = os.getpid()
            subprocess.run(["ionice", "-c", "2", "-n", "4", "-p", str(pid)],
                          capture_output=True, timeout=5)
            subprocess.run(["renice", "0", "-p", str(pid)],
                          capture_output=True, timeout=5)
        except Exception as e:
            logger.debug("Failed to restore normal I/O priority after backup: %s", e)

        return filepath


# ══════════════════════════════════════════════════
# 5. SQLite WAL mode
# ══════════════════════════════════════════════════

def enable_wal_mode(db_path: str):
    """
    Enable WAL (Write-Ahead Logging) mode on SQLite database.
    This allows concurrent readers during writes — no more "database is locked".
    Should be called once at startup.
    """
    import sqlite3
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")  # Faster, still crash-safe with WAL
        conn.execute("PRAGMA busy_timeout=5000")    # Wait 5s before returning BUSY
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        logger.info("SQLite WAL mode enabled (journal_mode=%s)", mode)
    except Exception as e:
        logger.warning("Failed to enable WAL mode: %s", e)
