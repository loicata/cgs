"""
CyberGuard Sentinel — Advanced security hardening.

  1. TLSAutoGen       — Generates self-signed TLS certificate at install
  2. LoginGuard       — Account lockout after N failed login attempts
  3. ApprovalPIN      — Second-factor PIN for incident approval links
  4. IntegrityCheck   — Verifies Sentinel code files at startup (SHA-256 manifest)
  5. FirewallVerifier — Periodically checks iptables rules are still in place
"""

import hashlib
import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime

logger = logging.getLogger("cyberguard.hardening")


# ══════════════════════════════════════════════════
# 1. Auto-generate TLS certificate
# ══════════════════════════════════════════════════

class TLSAutoGen:
    """
    Generates a self-signed TLS certificate at install so HTTPS
    is the default, not an option. Cert stored in /etc/cyberguard/tls/.
    """

    CERT_DIR = "/etc/cyberguard/tls"
    CERT_FILE = "sentinel.crt"
    KEY_FILE = "sentinel.key"

    @classmethod
    def ensure_cert(cls, config) -> tuple[str, str]:
        """
        Returns (cert_path, key_path). Generates if missing.
        Called at daemon startup before web server starts.
        """
        cert_path = config.get("web.ssl_cert", os.path.join(cls.CERT_DIR, cls.CERT_FILE))
        key_path = config.get("web.ssl_key", os.path.join(cls.CERT_DIR, cls.KEY_FILE))

        if os.path.exists(cert_path) and os.path.exists(key_path):
            logger.info("TLS certificate found: %s", cert_path)
            return cert_path, key_path

        # Generate self-signed cert
        os.makedirs(os.path.dirname(cert_path), exist_ok=True)

        hostname = "cyberguard-sentinel"
        try:
            import socket
            hostname = socket.gethostname()
        except Exception:
            pass

        try:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "3650", "-nodes",
                "-subj", f"/CN={hostname}/O=CyberGuard Sentinel/OU=Auto-Generated",
            ], capture_output=True, timeout=30, check=True)

            os.chmod(key_path, 0o600)
            os.chmod(cert_path, 0o644)
            logger.info("TLS self-signed certificate generated: %s (valid 10 years)", cert_path)
            return cert_path, key_path

        except FileNotFoundError:
            logger.warning("openssl not found — HTTPS disabled. Install openssl package.")
            return "", ""
        except subprocess.CalledProcessError as e:
            logger.error("TLS cert generation failed: %s", e.stderr.decode()[:200])
            return "", ""
        except Exception as e:
            logger.error("TLS cert generation failed: %s", e)
            return "", ""


# ══════════════════════════════════════════════════
# 2. Login lockout
# ══════════════════════════════════════════════════

class LoginGuard:
    """
    Tracks failed login attempts per IP.
    After max_attempts failures within window, the IP is locked out
    for lockout_duration seconds.
    """

    def __init__(self, config):
        self.max_attempts = config.get("web.max_login_attempts", 5)
        self.window = config.get("web.login_window_seconds", 300)
        self.lockout_duration = config.get("web.lockout_duration_seconds", 900)

        # {ip: {"attempts": [(timestamp, ...)], "locked_until": float}}
        self._data: dict[str, dict] = {}
        self._lock = threading.Lock()

        # Cleanup thread
        threading.Thread(target=self._cleanup_loop, daemon=True,
                        name="login-guard-gc").start()

    def record_failure(self, ip: str):
        """Record a failed login attempt."""
        now = time.time()
        with self._lock:
            if ip not in self._data:
                self._data[ip] = {"attempts": [], "locked_until": 0}
            entry = self._data[ip]
            entry["attempts"].append(now)
            # Keep only attempts within window
            cutoff = now - self.window
            entry["attempts"] = [t for t in entry["attempts"] if t > cutoff]
            # Lock if threshold reached
            if len(entry["attempts"]) >= self.max_attempts:
                entry["locked_until"] = now + self.lockout_duration
                logger.warning("Account locked for IP %s (%d failed attempts, "
                              "lockout %ds)", ip, len(entry["attempts"]),
                              self.lockout_duration)

    def record_success(self, ip: str):
        """Clear failures after successful login."""
        with self._lock:
            self._data.pop(ip, None)

    def is_locked(self, ip: str) -> tuple[bool, int]:
        """Check if IP is locked. Returns (locked, seconds_remaining)."""
        with self._lock:
            entry = self._data.get(ip)
            if not entry:
                return False, 0
            if entry["locked_until"] > time.time():
                remaining = int(entry["locked_until"] - time.time())
                return True, remaining
            return False, 0

    def get_attempts(self, ip: str) -> int:
        """Get number of recent failed attempts for an IP."""
        with self._lock:
            entry = self._data.get(ip)
            if not entry:
                return 0
            cutoff = time.time() - self.window
            return len([t for t in entry["attempts"] if t > cutoff])

    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            now = time.time()
            with self._lock:
                for ip in list(self._data.keys()):
                    entry = self._data[ip]
                    cutoff = now - self.window
                    entry["attempts"] = [t for t in entry["attempts"] if t > cutoff]
                    if not entry["attempts"] and entry["locked_until"] < now:
                        del self._data[ip]


# ══════════════════════════════════════════════════
# 3. Approval PIN (second factor)
# ══════════════════════════════════════════════════

class ApprovalPIN:
    """
    When an incident is created, a random 6-digit PIN is generated
    and shown ONLY in the web dashboard. The email approval link
    requires this PIN to complete. Even if the email is intercepted,
    the attacker doesn't have the PIN.
    """

    def __init__(self):
        self._pins: dict[str, dict] = {}  # incident_id → {pin, created, used}
        self._lock = threading.Lock()

    def generate(self, incident_id: str) -> str:
        """Generate a 6-digit PIN for an incident. Returns the PIN."""
        import secrets
        pin = f"{secrets.randbelow(1000000):06d}"
        with self._lock:
            self._pins[incident_id] = {
                "pin": pin,
                "created": time.time(),
                "used": False,
            }
        logger.info("Approval PIN generated for %s (visible in dashboard only)",
                   incident_id)
        return pin

    def verify(self, incident_id: str, pin: str) -> bool:
        """Verify a PIN for an incident. Single-use."""
        with self._lock:
            data = self._pins.get(incident_id)
            if not data:
                return False
            if data["used"]:
                return False
            # Expire after 2 hours
            if time.time() - data["created"] > 7200:
                return False
            if data["pin"] == pin:
                data["used"] = True
                return True
            return False

    def get_pin_for_dashboard(self, incident_id: str) -> str:
        """
        Returns the PIN for display in the dashboard ONLY.
        This is never sent by email.
        """
        with self._lock:
            data = self._pins.get(incident_id)
            if not data or data["used"]:
                return ""
            if time.time() - data["created"] > 7200:
                return ""
            return data["pin"]

    def cleanup(self):
        cutoff = time.time() - 7200
        with self._lock:
            self._pins = {k: v for k, v in self._pins.items()
                         if v["created"] > cutoff}


# ══════════════════════════════════════════════════
# 4. Self-integrity check
# ══════════════════════════════════════════════════

class IntegrityCheck:
    """
    At startup, computes SHA-256 of all Sentinel Python files and
    compares against a stored manifest. If any file has been modified,
    an alert is fired.

    The manifest is generated at install time (postinst) and stored
    in /var/lib/cyberguard/data/integrity_manifest.json.
    """

    INSTALL_DIR = "/opt/cyberguard"
    MANIFEST_PATH = "/var/lib/cyberguard/data/integrity_manifest.json"

    @classmethod
    def generate_manifest(cls) -> dict:
        """Generate SHA-256 manifest of all installed Python files."""
        manifest = {"generated_at": datetime.now().isoformat(), "files": {}}
        for root, dirs, files in os.walk(cls.INSTALL_DIR):
            for fn in sorted(files):
                if not fn.endswith((".py", ".html", ".yaml")):
                    continue
                filepath = os.path.join(root, fn)
                rel = os.path.relpath(filepath, cls.INSTALL_DIR)
                with open(filepath, "rb") as f:
                    sha = hashlib.sha256(f.read()).hexdigest()
                manifest["files"][rel] = sha

        os.makedirs(os.path.dirname(cls.MANIFEST_PATH), exist_ok=True)
        with open(cls.MANIFEST_PATH, "w") as f:
            json.dump(manifest, f, indent=2)
        os.chmod(cls.MANIFEST_PATH, 0o600)

        logger.info("Integrity manifest generated: %d files", len(manifest["files"]))
        return manifest

    @classmethod
    def verify(cls, alert_fn=None) -> dict:
        """
        Verify all files against the manifest.
        Returns {ok, modified, missing, extra, details}.
        """
        result = {"ok": True, "modified": [], "missing": [], "extra": [],
                  "total_checked": 0}

        if not os.path.exists(cls.MANIFEST_PATH):
            logger.warning("No integrity manifest found — generating one now")
            cls.generate_manifest()
            result["ok"] = True
            result["note"] = "First run — manifest generated"
            return result

        with open(cls.MANIFEST_PATH) as f:
            manifest = json.load(f)

        stored = manifest.get("files", {})

        # Check each file in manifest
        for rel, expected_hash in stored.items():
            filepath = os.path.join(cls.INSTALL_DIR, rel)
            result["total_checked"] += 1

            if not os.path.exists(filepath):
                result["missing"].append(rel)
                result["ok"] = False
                continue

            with open(filepath, "rb") as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()

            if actual_hash != expected_hash:
                result["modified"].append(rel)
                result["ok"] = False

        # Check for extra files not in manifest
        for root, dirs, files in os.walk(cls.INSTALL_DIR):
            for fn in files:
                if not fn.endswith((".py", ".html", ".yaml")):
                    continue
                filepath = os.path.join(root, fn)
                rel = os.path.relpath(filepath, cls.INSTALL_DIR)
                if rel not in stored:
                    result["extra"].append(rel)

        if not result["ok"]:
            msg = []
            if result["modified"]:
                msg.append(f"{len(result['modified'])} modified: {', '.join(result['modified'][:5])}")
            if result["missing"]:
                msg.append(f"{len(result['missing'])} missing: {', '.join(result['missing'][:5])}")

            logger.error("INTEGRITY CHECK FAILED: %s", " | ".join(msg))

            if alert_fn:
                alert_fn(
                    severity=1, source="integrity", category="tampered",
                    title="CRITICAL: Sentinel code integrity check FAILED",
                    detail=" | ".join(msg),
                )
        else:
            logger.info("Integrity check passed: %d files verified", result["total_checked"])

        return result


# ══════════════════════════════════════════════════
# 5. Firewall rule verifier
# ══════════════════════════════════════════════════

class FirewallVerifier:
    """
    Periodically verifies that expected iptables rules are still in place.
    If rules have been flushed or modified externally, fires an alert
    and re-applies them.
    """

    def __init__(self, config, alert_fn=None, defense_engine=None):
        self.cfg = config
        self._alert = alert_fn or (lambda **kw: None)
        self._defense = defense_engine
        self._expected_rules: list[str] = []
        self._lock = threading.Lock()

    def snapshot_expected(self):
        """Capture current CyberGuard rules as the expected state."""
        rules = self._get_current_rules()
        with self._lock:
            self._expected_rules = rules
        if rules:
            logger.debug("Firewall verifier: %d expected rules captured", len(rules))

    def verify(self) -> dict:
        """
        Check that expected rules are still present.
        Returns {ok, missing_rules, total_expected, total_current}.
        """
        with self._lock:
            expected = list(self._expected_rules)

        if not expected:
            return {"ok": True, "missing_rules": [], "total_expected": 0,
                    "total_current": 0, "note": "No rules to verify"}

        current = self._get_current_rules()
        missing = [r for r in expected if r not in current]

        result = {
            "ok": len(missing) == 0,
            "missing_rules": missing,
            "total_expected": len(expected),
            "total_current": len(current),
        }

        if missing:
            logger.warning("FIREWALL TAMPERED: %d/%d CyberGuard rules missing!",
                          len(missing), len(expected))

            self._alert(
                severity=1, source="firewall_verifier", category="rules_tampered",
                title=f"CRITICAL: {len(missing)} firewall rules removed!",
                detail=f"Expected {len(expected)} rules, found {len(current)}. "
                       f"Missing: {'; '.join(missing[:5])}",
            )

            # Re-apply missing rules
            self._reapply(missing)
        else:
            logger.debug("Firewall verification: %d/%d rules OK", len(current), len(expected))

        return result

    def _get_current_rules(self) -> list[str]:
        """Get current CyberGuard iptables rules."""
        try:
            r = subprocess.run(
                ["iptables", "-L", "CYBERGUARD", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                return []
            # Parse: skip header lines, return rule lines
            rules = []
            for line in r.stdout.strip().split("\n")[2:]:  # Skip chain header + column names
                line = line.strip()
                if line:
                    rules.append(line)
            return rules
        except Exception:
            return []

    def _reapply(self, missing_rules: list[str]):
        """Attempt to re-apply missing rules."""
        if not self._defense:
            return

        reapplied = 0
        for rule in missing_rules:
            parts = rule.split()
            # Parse: "1  DROP  all  --  45.33.32.156  0.0.0.0/0"
            if len(parts) >= 5 and parts[1] in ("DROP", "REJECT"):
                src = parts[3] if parts[3] != "0.0.0.0/0" else None
                if src:
                    try:
                        subprocess.run(
                            ["iptables", "-A", "CYBERGUARD", "-s", src, "-j", parts[1]],
                            capture_output=True, timeout=5)
                        reapplied += 1
                    except Exception:
                        pass

        if reapplied:
            logger.warning("Re-applied %d/%d missing firewall rules", reapplied, len(missing_rules))
            self._alert(
                severity=3, source="firewall_verifier", category="rules_reapplied",
                title=f"Firewall rules re-applied: {reapplied}/{len(missing_rules)}",
                detail="Rules were removed externally and have been restored.",
            )


# ══════════════════════════════════════════════════
# 6. SSH hardening
# ══════════════════════════════════════════════════

class SSHHardener:
    """
    Verifies and hardens SSH configuration on the Sentinel server.

    If SSH key authentication is in use, password authentication
    MUST be disabled — otherwise an attacker can bypass the key
    by brute-forcing the password.

    This class:
      1. Detects if any SSH authorized_keys exist (key auth is configured)
      2. Checks sshd_config for password auth status
      3. Disables password auth if keys are present and password is still on
      4. Also hardens: PermitRootLogin, PermitEmptyPasswords, MaxAuthTries
      5. Restarts sshd to apply changes
      6. Provides a verify() method for periodic checks
    """

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_DIR = "/etc/ssh/sshd_config.d"
    BACKUP_SUFFIX = ".cyberguard.bak"

    def __init__(self, alert_fn=None):
        self._alert = alert_fn or (lambda **kw: None)

    # ── Main entry point ──

    def harden(self, interactive: bool = True) -> dict:
        """
        Check and harden SSH configuration.
        If interactive=True, asks before making changes (used by setup wizard).
        If interactive=False, applies changes silently (used by postinst).
        Returns {ok, changes, warnings}.
        """
        result = {"ok": True, "changes": [], "warnings": []}

        if not os.path.exists(self.SSHD_CONFIG):
            result["warnings"].append("sshd_config not found — SSH may not be installed")
            return result

        # Step 1: Detect if SSH keys are configured
        has_keys = self._detect_ssh_keys()
        if not has_keys:
            result["warnings"].append("No SSH authorized_keys found — "
                                      "password auth left as-is (no keys to fall back to)")
            return result

        # Step 2: Read current sshd_config
        config = self._read_sshd_config()
        changes_needed = []

        # Check PasswordAuthentication
        if self._get_effective_value(config, "PasswordAuthentication") != "no":
            changes_needed.append(("PasswordAuthentication", "no",
                "SSH keys detected but password auth is still enabled — "
                "an attacker can bypass keys by brute-forcing the password"))

        # Check KbdInteractiveAuthentication (replaces ChallengeResponseAuthentication)
        if self._get_effective_value(config, "KbdInteractiveAuthentication") != "no":
            changes_needed.append(("KbdInteractiveAuthentication", "no",
                "Keyboard-interactive auth should be disabled when using keys"))

        # Check ChallengeResponseAuthentication (legacy, some systems still use it)
        if self._get_effective_value(config, "ChallengeResponseAuthentication") != "no":
            changes_needed.append(("ChallengeResponseAuthentication", "no",
                "Challenge-response auth should be disabled when using keys"))

        # Check PermitRootLogin
        root_val = self._get_effective_value(config, "PermitRootLogin")
        if root_val not in ("no", "prohibit-password", "without-password"):
            changes_needed.append(("PermitRootLogin", "prohibit-password",
                "Root login should be restricted to key-only"))

        # Check PermitEmptyPasswords
        if self._get_effective_value(config, "PermitEmptyPasswords") != "no":
            changes_needed.append(("PermitEmptyPasswords", "no",
                "Empty passwords must never be allowed"))

        # Check MaxAuthTries
        try:
            max_tries = int(self._get_effective_value(config, "MaxAuthTries") or "6")
            if max_tries > 3:
                changes_needed.append(("MaxAuthTries", "3",
                    "Reduce max auth tries to slow brute force"))
        except ValueError:
            changes_needed.append(("MaxAuthTries", "3",
                "MaxAuthTries should be set explicitly"))

        if not changes_needed:
            logger.info("SSH hardening: already secure (keys present, password disabled)")
            result["changes"].append("SSH already properly hardened")
            return result

        # Step 3: Report findings
        logger.warning("SSH hardening: %d changes needed", len(changes_needed))
        for directive, value, reason in changes_needed:
            logger.warning("  → %s should be set to %s (%s)", directive, value, reason)

        # Step 4: Apply changes
        if interactive:
            print("\n  SSH keys detected on this server.")
            print("  The following changes are recommended:\n")
            for directive, value, reason in changes_needed:
                print(f"    • {directive} → {value}")
                print(f"      {reason}\n")

            try:
                answer = input("  Apply these SSH hardening changes? [Y/n] ").strip().lower()
                if answer in ("n", "no"):
                    result["warnings"].append("SSH hardening skipped by admin")
                    self._alert(
                        severity=3, source="ssh_hardening", category="skipped",
                        title="SSH hardening skipped by admin",
                        detail="Password auth remains enabled despite SSH keys being present",
                    )
                    return result
            except (EOFError, KeyboardInterrupt):
                result["warnings"].append("SSH hardening skipped (non-interactive)")
                return result

        # Step 5: Backup original config
        self._backup_config()

        # Step 6: Apply each change
        for directive, value, reason in changes_needed:
            self._set_directive(directive, value)
            result["changes"].append(f"{directive} → {value}")
            logger.info("SSH: set %s %s", directive, value)

        # Step 7: Validate config before restart
        if not self._validate_config():
            # Rollback
            self._restore_backup()
            result["ok"] = False
            result["warnings"].append("sshd_config validation failed — changes rolled back")
            logger.error("SSH hardening rolled back: config validation failed")
            return result

        # Step 8: Restart sshd
        if self._restart_sshd():
            result["changes"].append("sshd restarted successfully")
            logger.info("SSH hardened and sshd restarted: %d changes applied",
                       len(changes_needed))
            self._alert(
                severity=5, source="ssh_hardening", category="hardened",
                title=f"SSH hardened: {len(changes_needed)} changes applied",
                detail="; ".join(f"{d}={v}" for d, v, _ in changes_needed),
            )
        else:
            # Rollback on restart failure
            self._restore_backup()
            self._restart_sshd()
            result["ok"] = False
            result["warnings"].append("sshd restart failed — changes rolled back")
            logger.error("SSH hardening rolled back: sshd restart failed")

        return result

    # ── Periodic verification ──

    def verify(self) -> dict:
        """
        Verify SSH is still properly hardened.
        Returns {secure, issues}.
        Called periodically by daemon.
        """
        result = {"secure": True, "issues": []}

        if not os.path.exists(self.SSHD_CONFIG):
            return result

        has_keys = self._detect_ssh_keys()
        if not has_keys:
            return result  # No keys = nothing to check

        config = self._read_sshd_config()

        checks = [
            ("PasswordAuthentication", "no"),
            ("PermitEmptyPasswords", "no"),
        ]

        for directive, expected in checks:
            actual = self._get_effective_value(config, directive)
            if actual != expected:
                result["secure"] = False
                result["issues"].append(
                    f"{directive} is '{actual}' (should be '{expected}')")

        if not result["secure"]:
            self._alert(
                severity=2, source="ssh_hardening", category="ssh_weakened",
                title="SSH security degraded: password auth re-enabled!",
                detail="; ".join(result["issues"]),
            )

        return result

    # ── Internal helpers ──

    def _detect_ssh_keys(self) -> bool:
        """Check if any authorized_keys files exist on the system."""
        key_paths = [
            "/root/.ssh/authorized_keys",
            "/root/.ssh/authorized_keys2",
        ]
        # Also check all home directories
        try:
            for entry in os.listdir("/home"):
                home = f"/home/{entry}"
                if os.path.isdir(home):
                    key_paths.append(f"{home}/.ssh/authorized_keys")
                    key_paths.append(f"{home}/.ssh/authorized_keys2")
        except OSError:
            pass

        for path in key_paths:
            try:
                if os.path.exists(path) and os.path.getsize(path) > 0:
                    return True
            except OSError:
                pass
        return False

    def _read_sshd_config(self) -> str:
        """Read the main sshd_config + any includes."""
        content = ""
        try:
            with open(self.SSHD_CONFIG) as f:
                content = f.read()
        except Exception:
            return ""

        # Also read config.d/ directory (Ubuntu 22.04+)
        if os.path.isdir(self.SSHD_CONFIG_DIR):
            try:
                for fn in sorted(os.listdir(self.SSHD_CONFIG_DIR)):
                    if fn.endswith(".conf"):
                        with open(os.path.join(self.SSHD_CONFIG_DIR, fn)) as f:
                            content += "\n" + f.read()
            except Exception:
                pass

        return content

    def _get_effective_value(self, config: str, directive: str) -> str:
        """
        Get the effective value of an sshd directive.
        sshd uses first-match, so we return the first uncommented occurrence.
        Also checks sshd_config.d/ overrides (which are included at the top on Ubuntu).
        """
        import re
        # Find all uncommented occurrences
        pattern = re.compile(rf'^\s*{directive}\s+(\S+)', re.MULTILINE | re.IGNORECASE)
        matches = pattern.findall(config)
        if matches:
            return matches[-1].lower()  # Last match wins (config.d included after main)
        return ""

    def _set_directive(self, directive: str, value: str):
        """Set a directive in sshd_config. Replaces if exists, appends if not."""
        import re
        with open(self.SSHD_CONFIG) as f:
            lines = f.readlines()

        found = False
        new_lines = []
        for line in lines:
            # Match both commented and uncommented forms
            if re.match(rf'^\s*#?\s*{directive}\s', line, re.IGNORECASE):
                if not found:
                    new_lines.append(f"{directive} {value}\n")
                    found = True
                # Skip duplicate lines (commented or not)
            else:
                new_lines.append(line)

        if not found:
            # Append at end
            new_lines.append(f"\n# Added by CyberGuard Sentinel SSH hardening\n")
            new_lines.append(f"{directive} {value}\n")

        with open(self.SSHD_CONFIG, "w") as f:
            f.writelines(new_lines)

        # Also remove from config.d/ if overridden there (Ubuntu 22.04+)
        if os.path.isdir(self.SSHD_CONFIG_DIR):
            for fn in os.listdir(self.SSHD_CONFIG_DIR):
                if not fn.endswith(".conf"):
                    continue
                fp = os.path.join(self.SSHD_CONFIG_DIR, fn)
                try:
                    with open(fp) as f:
                        content = f.read()
                    if re.search(rf'^\s*{directive}\s', content, re.MULTILINE | re.IGNORECASE):
                        content = re.sub(
                            rf'^\s*{directive}\s+.*$',
                            f"{directive} {value}",
                            content, flags=re.MULTILINE | re.IGNORECASE)
                        with open(fp, "w") as f:
                            f.write(content)
                except Exception:
                    pass

    def _backup_config(self):
        """Backup sshd_config before modification."""
        import shutil
        backup = self.SSHD_CONFIG + self.BACKUP_SUFFIX
        if not os.path.exists(backup):
            shutil.copy2(self.SSHD_CONFIG, backup)
            os.chmod(backup, 0o600)

    def _restore_backup(self):
        """Restore sshd_config from backup."""
        import shutil
        backup = self.SSHD_CONFIG + self.BACKUP_SUFFIX
        if os.path.exists(backup):
            shutil.copy2(backup, self.SSHD_CONFIG)

    def _validate_config(self) -> bool:
        """Validate sshd_config syntax before restart."""
        try:
            result = subprocess.run(
                ["sshd", "-t"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.error("sshd_config validation failed: %s", result.stderr[:200])
                return False
            return True
        except FileNotFoundError:
            # sshd not found — skip validation
            return True
        except Exception as e:
            logger.error("sshd validation error: %s", e)
            return False

    def _restart_sshd(self) -> bool:
        """Restart sshd to apply changes."""
        for cmd in [
            ["systemctl", "restart", "sshd"],
            ["systemctl", "restart", "ssh"],
            ["service", "sshd", "restart"],
            ["service", "ssh", "restart"],
        ]:
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                if result.returncode == 0:
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return False
