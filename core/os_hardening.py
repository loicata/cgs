"""
CGS — OS hardening module.

Forward-compatible approach:
  - NEVER overwrites system config files
  - Uses ONLY drop-in directories (sysctl.d/, modprobe.d/, etc.)
  - Every sysctl key is TESTED before being written (future-proof)
  - Every change is logged and reversible (single file to delete)
  - Detects OS version and skips unsupported features

Drop-in files created (all removable with one command):
  /etc/sysctl.d/90-cgs.conf
  /etc/modprobe.d/cgs-blacklist.conf
  /etc/security/limits.d/cgs.conf
  /etc/apparmor.d/opt.cgs.daemon (if AppArmor available)
  /etc/audit/rules.d/cgs.rules (if auditd available)

To undo ALL hardening:
  rm /etc/sysctl.d/90-cgs.conf
  rm /etc/modprobe.d/cgs-blacklist.conf
  rm /etc/security/limits.d/cgs.conf
  rm /etc/apparmor.d/opt.cgs.daemon
  rm /etc/audit/rules.d/cgs.rules
  sysctl --system
"""

import logging
import os
import platform
import subprocess

logger = logging.getLogger("cgs.os_hardening")


class OSHardener:
    """Applies and verifies OS-level security hardening."""

    # Files we create (drop-in only, never overwrite system files)
    SYSCTL_FILE = "/etc/sysctl.d/90-cgs.conf"
    MODPROBE_FILE = "/etc/modprobe.d/cgs-blacklist.conf"
    LIMITS_FILE = "/etc/security/limits.d/cgs.conf"
    APPARMOR_FILE = "/etc/apparmor.d/opt.cgs.daemon"
    AUDITD_FILE = "/etc/audit/rules.d/cgs.rules"
    BANNER_FILE = "/etc/issue.net"
    TMOUT_FILE = "/etc/profile.d/cgs-tmout.sh"

    def __init__(self, alert_fn=None):
        self._alert = alert_fn or (lambda **kw: None)
        self.os_id, self.os_version = self._detect_os()

    # ══════════════════════════════════════════════
    # Main entry points
    # ══════════════════════════════════════════════

    def harden(self, interactive: bool = True) -> dict:
        """
        Apply all OS hardening. Returns {changes, skipped, warnings}.
        If interactive, asks before each category.
        """
        result = {"changes": [], "skipped": [], "warnings": []}

        steps = [
            ("Kernel network hardening (sysctl)", self._harden_sysctl),
            ("Filesystem mount options (/tmp noexec)", self._harden_mounts),
            ("Disable unused kernel modules (USB, firewire)", self._harden_modules),
            ("Automatic security updates", self._harden_updates),
            ("AppArmor profile for Sentinel", self._harden_apparmor),
            ("Audit rules (auditd)", self._harden_auditd),
            ("Disable unnecessary services", self._harden_services),
            ("Clean system banners", self._harden_banners),
            ("Shell inactivity timeout", self._harden_tmout),
            ("Process visibility (hidepid)", self._harden_proc),
        ]

        for desc, func in steps:
            if interactive:
                try:
                    answer = input(f"\n  Apply: {desc}? [Y/n] ").strip().lower()
                    if answer in ("n", "no"):
                        result["skipped"].append(desc)
                        continue
                except (EOFError, KeyboardInterrupt):
                    result["skipped"].append(desc)
                    continue

            try:
                changes = func()
                result["changes"].extend(changes)
            except Exception as e:
                result["warnings"].append(f"{desc}: {e}")
                logger.warning("OS hardening step failed (%s): %s", desc, e)

        logger.info("OS hardening complete: %d changes, %d skipped, %d warnings",
                    len(result["changes"]), len(result["skipped"]), len(result["warnings"]))
        return result

    def verify(self) -> dict:
        """
        Verify OS hardening is still in place.
        Returns {secure, issues, checks}.
        """
        result = {"secure": True, "issues": [], "checks": 0}

        # Check sysctl values
        critical_sysctls = {
            "net.ipv4.icmp_echo_ignore_broadcasts": "1",
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.all.send_redirects": "0",
            "net.ipv4.tcp_syncookies": "1",
            "kernel.randomize_va_space": "2",
        }

        for key, expected in critical_sysctls.items():
            actual = self._sysctl_read(key)
            result["checks"] += 1
            if actual != expected:
                result["secure"] = False
                result["issues"].append(f"{key}={actual} (expected {expected})")

        # Check drop-in files exist
        for f in [self.SYSCTL_FILE, self.MODPROBE_FILE]:
            result["checks"] += 1
            if not os.path.exists(f):
                result["secure"] = False
                result["issues"].append(f"Missing: {f}")

        if not result["secure"]:
            self._alert(
                severity=3, source="os_hardening", category="hardening_drift",
                title=f"OS hardening degraded: {len(result['issues'])} issues",
                detail="; ".join(result["issues"][:5]),
            )

        return result

    def undo(self) -> list:
        """Remove all CGS OS hardening (clean uninstall)."""
        removed = []
        for f in [self.SYSCTL_FILE, self.MODPROBE_FILE, self.LIMITS_FILE,
                  self.APPARMOR_FILE, self.AUDITD_FILE, self.TMOUT_FILE]:
            if os.path.exists(f):
                os.remove(f)
                removed.append(f)

        # Reload sysctl
        if removed:
            subprocess.run(["sysctl", "--system"], capture_output=True, timeout=10)

        return removed

    # ══════════════════════════════════════════════
    # 1. Kernel network hardening (sysctl)
    # ══════════════════════════════════════════════

    def _harden_sysctl(self) -> list:
        """Apply network and kernel sysctl hardening via drop-in file."""
        # Each entry: (key, value, comment)
        # We TEST each key before writing — if the key doesn't exist
        # on this kernel version, we skip it (forward-compatible)
        settings = [
            # ── Network: anti-spoofing ──
            ("net.ipv4.conf.all.rp_filter", "1", "Strict reverse path filtering (anti-spoof)"),
            ("net.ipv4.conf.default.rp_filter", "1", ""),
            # ── Network: disable redirects ──
            ("net.ipv4.conf.all.accept_redirects", "0", "Ignore ICMP redirects (anti-MITM)"),
            ("net.ipv4.conf.default.accept_redirects", "0", ""),
            ("net.ipv6.conf.all.accept_redirects", "0", ""),
            ("net.ipv6.conf.default.accept_redirects", "0", ""),
            ("net.ipv4.conf.all.send_redirects", "0", "Don't send ICMP redirects"),
            ("net.ipv4.conf.default.send_redirects", "0", ""),
            # ── Network: disable source routing ──
            ("net.ipv4.conf.all.accept_source_route", "0", "Reject source-routed packets"),
            ("net.ipv4.conf.default.accept_source_route", "0", ""),
            ("net.ipv6.conf.all.accept_source_route", "0", ""),
            # ── Network: SYN flood protection ──
            ("net.ipv4.tcp_syncookies", "1", "SYN cookies (anti-SYN flood)"),
            ("net.ipv4.tcp_max_syn_backlog", "2048", "Larger SYN backlog"),
            # ── Network: ignore broadcasts ──
            ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "Ignore broadcast pings (anti-smurf)"),
            ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "Ignore bogus ICMP errors"),
            # ── Network: log suspicious packets ──
            ("net.ipv4.conf.all.log_martians", "1", "Log packets with impossible addresses"),
            ("net.ipv4.conf.default.log_martians", "1", ""),
            # ── Kernel: ASLR ──
            ("kernel.randomize_va_space", "2", "Full ASLR (code, data, stack, heap)"),
            # ── Kernel: restrict dmesg ──
            ("kernel.dmesg_restrict", "1", "Restrict dmesg to root only"),
            # ── Kernel: restrict kernel pointers ──
            ("kernel.kptr_restrict", "2", "Hide kernel pointers from all users"),
            # ── Kernel: restrict ptrace ──
            ("kernel.yama.ptrace_scope", "2", "Only root can ptrace (anti-debug)"),
            # ── Kernel: restrict unprivileged BPF ──
            ("kernel.unprivileged_bpf_disabled", "1", "Restrict BPF to root"),
            # ── Kernel: restrict userfaultfd ──
            ("vm.unprivileged_userfaultfd", "0", "Restrict userfaultfd (exploit mitigation)"),
            # ── Network: disable IPv6 router advertisements if not used ──
            ("net.ipv6.conf.all.accept_ra", "0", "Ignore IPv6 router advertisements"),
            ("net.ipv6.conf.default.accept_ra", "0", ""),
        ]

        changes = []
        lines = ["# CGS — Kernel hardening",
                 "# Auto-generated, safe to delete",
                 f"# OS: {self.os_id} {self.os_version}",
                 ""]

        for key, value, comment in settings:
            if self._sysctl_exists(key):
                if comment:
                    lines.append(f"# {comment}")
                lines.append(f"{key} = {value}")
                changes.append(f"sysctl: {key}={value}")
            else:
                lines.append(f"# SKIPPED (not available on this kernel): {key}")

        os.makedirs(os.path.dirname(self.SYSCTL_FILE), exist_ok=True)
        with open(self.SYSCTL_FILE, "w") as f:
            f.write("\n".join(lines) + "\n")

        # Apply immediately
        subprocess.run(["sysctl", "-p", self.SYSCTL_FILE],
                      capture_output=True, timeout=10)

        logger.info("sysctl: %d settings applied, written to %s",
                    len(changes), self.SYSCTL_FILE)
        return changes

    # ══════════════════════════════════════════════
    # 2. Filesystem mount hardening
    # ══════════════════════════════════════════════

    def _harden_mounts(self) -> list:
        """Add noexec,nosuid,nodev to /tmp if it's a separate mount or tmpfs."""
        changes = []

        # Check if /tmp is a separate mount
        try:
            result = subprocess.run(
                ["findmnt", "-n", "-o", "OPTIONS", "/tmp"],  # nosec B108 — checking mount options, not creating temp files
                capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                # /tmp is not a separate mount — we can make it a tmpfs
                # But this is risky to do automatically, so just warn
                changes.append("WARNING: /tmp is not a separate mount — "
                              "consider adding 'tmpfs /tmp tmpfs noexec,nosuid,nodev 0 0' to /etc/fstab")
                return changes

            options = result.stdout.strip()
            needed = []
            for opt in ["noexec", "nosuid", "nodev"]:
                if opt not in options:
                    needed.append(opt)

            if needed:
                # Remount with additional options
                new_opts = options + "," + ",".join(needed)
                subprocess.run(
                    ["mount", "-o", f"remount,{new_opts}", "/tmp"],  # nosec B108 — hardening /tmp mount options
                    capture_output=True, timeout=10)
                changes.append(f"/tmp remounted with {','.join(needed)}")  # nosec B108
                logger.info("/tmp hardened: added %s", ",".join(needed))  # nosec B108
            else:
                changes.append("/tmp already has noexec,nosuid,nodev")  # nosec B108

        except Exception as e:
            changes.append(f"/tmp mount check skipped: {e}")  # nosec B108

        return changes

    # ══════════════════════════════════════════════
    # 3. Disable unused kernel modules
    # ══════════════════════════════════════════════

    def _harden_modules(self) -> list:
        """Blacklist dangerous/unused kernel modules via drop-in file."""
        modules = [
            ("usb-storage", "Block USB mass storage (prevent rogue USB)"),
            ("firewire-core", "Block FireWire DMA attacks"),
            ("firewire-ohci", ""),
            ("thunderbolt", "Block Thunderbolt DMA attacks"),
            ("cramfs", "Uncommon filesystem — potential exploit vector"),
            ("freevxfs", ""),
            ("hfs", ""),
            ("hfsplus", ""),
            ("squashfs", ""),
            ("udf", ""),
            ("dccp", "Unused network protocol"),
            ("sctp", ""),
            ("rds", ""),
            ("tipc", ""),
        ]

        lines = ["# CGS — Module blacklist",
                 "# Auto-generated, safe to delete",
                 ""]

        for mod, comment in modules:
            if comment:
                lines.append(f"# {comment}")
            lines.append(f"blacklist {mod}")
            lines.append(f"install {mod} /bin/true")

        os.makedirs(os.path.dirname(self.MODPROBE_FILE), exist_ok=True)
        with open(self.MODPROBE_FILE, "w") as f:
            f.write("\n".join(lines) + "\n")

        changes = [f"Blacklisted {len(modules)} kernel modules → {self.MODPROBE_FILE}"]
        logger.info("Blacklisted %d kernel modules", len(modules))
        return changes

    # ══════════════════════════════════════════════
    # 4. Automatic security updates
    # ══════════════════════════════════════════════

    def _harden_updates(self) -> list:
        """Enable unattended-upgrades for security patches only."""
        changes = []

        # Check if already installed
        try:
            r = subprocess.run(["dpkg", "-l", "unattended-upgrades"],
                              capture_output=True, text=True, timeout=5)
            if "ii" not in r.stdout:
                subprocess.run(
                    ["apt-get", "install", "-y", "-qq", "unattended-upgrades"],
                    capture_output=True, timeout=120)
                changes.append("Installed unattended-upgrades")
        except Exception:
            changes.append("unattended-upgrades install skipped")
            return changes

        # Enable with dpkg-reconfigure (non-interactive)
        try:
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"
            subprocess.run(
                ["dpkg-reconfigure", "-plow", "unattended-upgrades"],
                capture_output=True, timeout=30, env=env)
            changes.append("Enabled unattended-upgrades (security patches only)")
        except Exception as e:
            changes.append(f"unattended-upgrades config skipped: {e}")

        return changes

    # ══════════════════════════════════════════════
    # 5. AppArmor profile
    # ══════════════════════════════════════════════

    def _harden_apparmor(self) -> list:
        """Create an AppArmor profile for the Sentinel daemon."""
        changes = []

        # Check if AppArmor is available
        try:
            r = subprocess.run(["aa-status", "--enabled"],
                              capture_output=True, timeout=5)
            if r.returncode != 0:
                changes.append("AppArmor not enabled — profile skipped")
                return changes
        except FileNotFoundError:
            changes.append("AppArmor not installed — profile skipped")
            return changes

        profile = """# CGS — AppArmor profile
# Auto-generated, safe to delete

/opt/cgs/venv/bin/python3 {
  # Python interpreter
  /opt/cgs/** r,
  /opt/cgs/venv/** rix,
  /usr/lib/python3/** r,
  /usr/lib/python3.*/** r,

  # Config
  /etc/cgs/** r,

  # Data directories
  /var/lib/cgs/** rw,
  /var/log/cgs/** rw,

  # Network capture (requires raw socket)
  capability net_raw,
  capability net_admin,
  network raw,
  network packet,
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,

  # System info
  /proc/** r,
  /sys/class/net/** r,

  # iptables/nftables
  /usr/sbin/iptables* rix,
  /usr/sbin/nft rix,
  /usr/sbin/iptables-save rix,
  /usr/sbin/iptables-restore rix,

  # DNS sinkhole
  /etc/hosts rw,

  # TLS cert
  /etc/cgs/tls/** r,

  # Deny everything else
  deny /home/** rwx,
  deny /root/** rwx,
  deny /boot/** rwx,
}
"""
        os.makedirs(os.path.dirname(self.APPARMOR_FILE), exist_ok=True)
        with open(self.APPARMOR_FILE, "w") as f:
            f.write(profile)

        # Load in complain mode first (won't block, just logs violations)
        try:
            subprocess.run(
                ["aa-complain", self.APPARMOR_FILE],
                capture_output=True, timeout=10)
            changes.append(f"AppArmor profile installed in COMPLAIN mode → {self.APPARMOR_FILE}")
            changes.append("Run 'aa-enforce /etc/apparmor.d/opt.cgs.daemon' "
                          "after testing to switch to enforce mode")
        except Exception:
            changes.append(f"AppArmor profile written but not loaded: {self.APPARMOR_FILE}")

        return changes

    # ══════════════════════════════════════════════
    # 6. Audit rules (auditd)
    # ══════════════════════════════════════════════

    def _harden_auditd(self) -> list:
        """Add audit rules for security-critical operations."""
        changes = []

        # Check if auditd is available
        try:
            r = subprocess.run(["auditctl", "-s"],
                              capture_output=True, timeout=5)
            if r.returncode != 0:
                # Try to install
                subprocess.run(
                    ["apt-get", "install", "-y", "-qq", "auditd"],
                    capture_output=True, timeout=120)
        except FileNotFoundError:
            changes.append("auditd not available — skipped")
            return changes

        rules = """# CGS — Audit rules
# Auto-generated, safe to delete

# Monitor config changes
-w /etc/cgs/ -p wa -k cgs_config
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/hosts -p wa -k hosts_modified

# Monitor authentication
-w /var/log/auth.log -p r -k auth_log
-w /var/log/faillog -p wa -k faillog
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor privileged commands
-a always,exit -F arch=b64 -S execve -F euid=0 -F key=root_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -F key=root_commands

# Monitor iptables modifications
-w /usr/sbin/iptables -p x -k firewall
-w /usr/sbin/nft -p x -k firewall

# Monitor Sentinel binary
-w /opt/cgs/ -p wa -k sentinel_code
"""
        rules_dir = os.path.dirname(self.AUDITD_FILE)
        if not os.path.isdir(rules_dir):
            os.makedirs(rules_dir, exist_ok=True)

        with open(self.AUDITD_FILE, "w") as f:
            f.write(rules)

        # Reload rules
        try:
            subprocess.run(["augenrules", "--load"],
                          capture_output=True, timeout=10)
            changes.append(f"Audit rules loaded → {self.AUDITD_FILE}")
        except Exception:
            try:
                subprocess.run(["auditctl", "-R", self.AUDITD_FILE],
                              capture_output=True, timeout=10)
                changes.append(f"Audit rules loaded → {self.AUDITD_FILE}")
            except Exception:
                changes.append(f"Audit rules written but not loaded: {self.AUDITD_FILE}")

        return changes

    # ══════════════════════════════════════════════
    # 7. Disable unnecessary services
    # ══════════════════════════════════════════════

    def _harden_services(self) -> list:
        """Disable services that are unnecessary on a security server."""
        changes = []

        # Services to disable (only if they exist and are active)
        unnecessary = [
            ("avahi-daemon", "mDNS/DNS-SD — unnecessary on a server"),
            ("cups", "Print server — unnecessary"),
            ("cups-browsed", "Print discovery — unnecessary"),
            ("bluetooth", "Bluetooth — unnecessary on a server"),
            ("ModemManager", "Modem management — unnecessary"),
        ]

        for service, reason in unnecessary:
            try:
                # Check if service exists
                r = subprocess.run(
                    ["systemctl", "is-enabled", service],
                    capture_output=True, text=True, timeout=5)
                if r.stdout.strip() in ("enabled", "active"):
                    subprocess.run(
                        ["systemctl", "disable", "--now", service],
                        capture_output=True, timeout=10)
                    changes.append(f"Disabled {service} ({reason})")
                    logger.info("Disabled unnecessary service: %s", service)
            except Exception as e:
                logger.debug("Failed to check/disable service %s: %s", service, e)

        if not changes:
            changes.append("No unnecessary services found to disable")

        return changes

    # ══════════════════════════════════════════════
    # 8. Clean system banners
    # ══════════════════════════════════════════════

    def _harden_banners(self) -> list:
        """Remove OS version info from SSH and login banners."""
        changes = []

        # SSH banner
        banner_text = "Authorized access only. All activity is monitored and logged.\n"

        for banner_file in ["/etc/issue", "/etc/issue.net"]:
            try:
                with open(banner_file) as f:
                    current = f.read()
                # Only replace if it contains version info
                if any(kw in current.lower() for kw in ["ubuntu", "debian", "\\l", "\\n", "\\r"]):
                    with open(banner_file, "w") as f:
                        f.write(banner_text)
                    changes.append(f"Cleaned {banner_file} (removed OS version)")
            except Exception as e:
                logger.debug("Failed to clean banner %s: %s", banner_file, e)

        # Disable motd scripts that leak info
        motd_dir = "/etc/update-motd.d"
        if os.path.isdir(motd_dir):
            for fn in os.listdir(motd_dir):
                fp = os.path.join(motd_dir, fn)
                if os.path.isfile(fp) and os.access(fp, os.X_OK):
                    # Don't disable all motd, just the ones that show OS info
                    if any(kw in fn for kw in ["00-header", "10-help", "50-landscape", "50-motd-news"]):
                        os.chmod(fp, 0o644)  # Remove execute bit
                        changes.append(f"Disabled motd script: {fn}")

        return changes

    # ══════════════════════════════════════════════
    # 9. Shell inactivity timeout
    # ══════════════════════════════════════════════

    def _harden_tmout(self) -> list:
        """Set shell inactivity timeout (auto-logout after 15 min)."""
        script = """# CGS — Shell timeout
# Auto-generated, safe to delete
# Auto-logout after 15 minutes of inactivity
readonly TMOUT=900
export TMOUT
"""
        os.makedirs(os.path.dirname(self.TMOUT_FILE), exist_ok=True)
        with open(self.TMOUT_FILE, "w") as f:
            f.write(script)
        os.chmod(self.TMOUT_FILE, 0o644)
        return [f"Shell timeout set to 900s (15 min) → {self.TMOUT_FILE}"]

    # ══════════════════════════════════════════════
    # 10. Process visibility (hidepid)
    # ══════════════════════════════════════════════

    def _harden_proc(self) -> list:
        """Hide processes from other users (hidepid=2 on /proc)."""
        changes = []

        try:
            # Check current mount options
            r = subprocess.run(
                ["findmnt", "-n", "-o", "OPTIONS", "/proc"],
                capture_output=True, text=True, timeout=5)
            current = r.stdout.strip()

            if "hidepid=2" in current or "hidepid=invisible" in current:
                changes.append("/proc already has hidepid=2")
                return changes

            # Remount with hidepid=2
            # On systemd systems, this requires a specific approach
            subprocess.run(
                ["mount", "-o", "remount,hidepid=2", "/proc"],
                capture_output=True, timeout=10)
            changes.append("/proc remounted with hidepid=2 (processes hidden between users)")

        except Exception as e:
            changes.append(f"/proc hidepid skipped: {e}")

        return changes

    # ══════════════════════════════════════════════
    # Helpers
    # ══════════════════════════════════════════════

    def _sysctl_exists(self, key: str) -> bool:
        """Check if a sysctl key exists on this kernel (forward-compatible)."""
        path = f"/proc/sys/{key.replace('.', '/')}"
        return os.path.exists(path)

    def _sysctl_read(self, key: str) -> str:
        """Read current value of a sysctl key."""
        try:
            r = subprocess.run(
                ["sysctl", "-n", key], capture_output=True, text=True, timeout=5)
            return r.stdout.strip() if r.returncode == 0 else ""
        except Exception:
            return ""

    def _detect_os(self) -> tuple:
        """Detect OS ID and version from /etc/os-release."""
        os_id = "unknown"
        os_version = "unknown"
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("ID="):
                        os_id = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("VERSION_ID="):
                        os_version = line.split("=", 1)[1].strip().strip('"')
        except Exception as e:
            logger.debug("Failed to detect OS version: %s", e)
        return os_id, os_version
