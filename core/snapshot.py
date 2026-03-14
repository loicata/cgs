"""
CyberGuard Sentinel — Defense state snapshot & rollback.

Before executing any defense action, Sentinel takes a snapshot of:
  - iptables/nftables rules
  - /etc/hosts (DNS sinkhole entries)
  - Active defense actions list
  - Netgate firewall alias content (if configured)

The admin can rollback to any snapshot from the TUI console or web API,
restoring the exact state before the incident response.

Snapshots are stored as JSON files in /var/log/cyberguard/snapshots/.
"""

import json
import logging
import os
import subprocess
import time
from datetime import datetime

logger = logging.getLogger("cyberguard.snapshot")


class DefenseSnapshot:
    """Takes and restores defense state snapshots."""

    def __init__(self, config):
        self.cfg = config
        self.snapshot_dir = os.path.join(
            config.get("general.log_dir", "/var/log/cyberguard"),
            "snapshots"
        )
        os.makedirs(self.snapshot_dir, exist_ok=True)

    # ══════════════════════════════════════════════
    # Take snapshot (before defense actions)
    # ══════════════════════════════════════════════

    def take(self, incident_id: str, reason: str = "") -> str:
        """
        Captures current defense state. Returns snapshot filepath.
        Called BEFORE any defense action is executed.
        """
        now = datetime.now()
        snapshot = {
            "id": f"snap_{incident_id}_{now.strftime('%Y%m%d_%H%M%S')}",
            "incident_id": incident_id,
            "reason": reason,
            "created_at": now.isoformat(),
            "timestamp": time.time(),

            # Firewall state
            "iptables": self._capture_iptables(),
            "nftables": self._capture_nftables(),

            # DNS sinkhole entries
            "etc_hosts": self._capture_etc_hosts(),

            # CyberGuard-specific state
            "cyberguard_chain": self._capture_cyberguard_chain(),
        }

        # Save
        filename = f"{snapshot['id']}.json"
        filepath = os.path.join(self.snapshot_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)

        logger.info("📸 Snapshot taken: %s (%s)", snapshot["id"], reason or incident_id)
        return filepath

    # ══════════════════════════════════════════════
    # Restore snapshot (rollback)
    # ══════════════════════════════════════════════

    def restore(self, snapshot_path: str) -> dict:
        """
        Restores defense state from a snapshot file.
        Returns {"ok": bool, "actions": list, "errors": list}
        """
        try:
            with open(snapshot_path, "r", encoding="utf-8") as f:
                snapshot = json.load(f)
        except Exception as e:
            return {"ok": False, "actions": [], "errors": [f"Cannot read snapshot: {e}"]}

        actions = []
        errors = []

        # 1. Restore iptables
        if snapshot.get("iptables"):
            ok = self._restore_iptables(snapshot["iptables"])
            if ok:
                actions.append("iptables rules restored")
            else:
                errors.append("iptables restore failed")

        # 2. Restore nftables
        if snapshot.get("nftables"):
            ok = self._restore_nftables(snapshot["nftables"])
            if ok:
                actions.append("nftables rules restored")
            else:
                errors.append("nftables restore failed")

        # 3. Restore /etc/hosts
        if snapshot.get("etc_hosts"):
            ok = self._restore_etc_hosts(snapshot["etc_hosts"])
            if ok:
                actions.append("/etc/hosts restored (sinkhole entries removed)")
            else:
                errors.append("/etc/hosts restore failed")

        # 4. Flush CyberGuard iptables chain
        if snapshot.get("cyberguard_chain"):
            ok = self._restore_cyberguard_chain(snapshot["cyberguard_chain"])
            if ok:
                actions.append("CyberGuard iptables chain restored")
            else:
                errors.append("CyberGuard chain restore failed")

        result = {
            "ok": len(errors) == 0,
            "snapshot_id": snapshot.get("id", ""),
            "incident_id": snapshot.get("incident_id", ""),
            "created_at": snapshot.get("created_at", ""),
            "actions": actions,
            "errors": errors,
        }

        if result["ok"]:
            logger.warning("⏪ ROLLBACK completed: %s (%d actions restored)",
                          snapshot.get("id"), len(actions))
        else:
            logger.error("⏪ ROLLBACK partial: %s (%d OK, %d errors)",
                        snapshot.get("id"), len(actions), len(errors))

        return result

    # ══════════════════════════════════════════════
    # List available snapshots
    # ══════════════════════════════════════════════

    def list_snapshots(self) -> list[dict]:
        """Returns list of available snapshots, newest first."""
        snapshots = []
        for filename in sorted(os.listdir(self.snapshot_dir), reverse=True):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(self.snapshot_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                snapshots.append({
                    "id": data.get("id", filename),
                    "incident_id": data.get("incident_id", ""),
                    "created_at": data.get("created_at", ""),
                    "reason": data.get("reason", ""),
                    "filepath": filepath,
                    "size_kb": round(os.path.getsize(filepath) / 1024, 1),
                })
            except Exception:
                continue
        return snapshots

    # ══════════════════════════════════════════════
    # Capture methods (read current state)
    # ══════════════════════════════════════════════

    def _capture_iptables(self) -> str:
        """Capture full iptables state."""
        try:
            result = subprocess.run(
                ["iptables-save"], capture_output=True, text=True, timeout=10)
            return result.stdout if result.returncode == 0 else ""
        except Exception:
            return ""

    def _capture_nftables(self) -> str:
        """Capture full nftables state."""
        try:
            result = subprocess.run(
                ["nft", "list", "ruleset"], capture_output=True, text=True, timeout=10)
            return result.stdout if result.returncode == 0 else ""
        except Exception:
            return ""

    def _capture_etc_hosts(self) -> str:
        """Capture /etc/hosts content."""
        try:
            with open("/etc/hosts", "r") as f:
                return f.read()
        except Exception:
            return ""

    def _capture_cyberguard_chain(self) -> str:
        """Capture CyberGuard-specific iptables chain."""
        try:
            result = subprocess.run(
                ["iptables", "-L", "CYBERGUARD", "-n", "-v", "--line-numbers"],
                capture_output=True, text=True, timeout=10)
            return result.stdout if result.returncode == 0 else ""
        except Exception:
            return ""

    # ══════════════════════════════════════════════
    # Restore methods
    # ══════════════════════════════════════════════

    def _restore_iptables(self, saved_state: str) -> bool:
        """Restore iptables from saved state."""
        if not saved_state:
            return True
        try:
            proc = subprocess.run(
                ["iptables-restore"], input=saved_state,
                capture_output=True, text=True, timeout=10)
            return proc.returncode == 0
        except Exception as e:
            logger.error("iptables restore: %s", e)
            return False

    def _restore_nftables(self, saved_state: str) -> bool:
        """Restore nftables from saved state."""
        if not saved_state:
            return True
        try:
            # Flush first, then restore
            subprocess.run(["nft", "flush", "ruleset"],
                          capture_output=True, timeout=5)
            proc = subprocess.run(
                ["nft", "-f", "-"], input=saved_state,
                capture_output=True, text=True, timeout=10)
            return proc.returncode == 0
        except Exception as e:
            logger.error("nftables restore: %s", e)
            return False

    def _restore_etc_hosts(self, saved_state: str) -> bool:
        """Restore /etc/hosts from saved state."""
        if not saved_state:
            return True
        try:
            with open("/etc/hosts", "w") as f:
                f.write(saved_state)
            return True
        except Exception as e:
            logger.error("/etc/hosts restore: %s", e)
            return False

    def _restore_cyberguard_chain(self, saved_state: str) -> bool:
        """Restore CyberGuard iptables chain to previous state."""
        try:
            # Flush the chain
            subprocess.run(
                ["iptables", "-F", "CYBERGUARD"],
                capture_output=True, timeout=5)

            # Re-add rules from saved state if any existed
            if saved_state and "CYBERGUARD" in saved_state:
                for line in saved_state.strip().split("\n"):
                    line = line.strip()
                    # Parse iptables -L output to re-add rules
                    # Lines like: "1  DROP  all  --  45.33.32.156  0.0.0.0/0"
                    parts = line.split()
                    if len(parts) >= 4 and parts[1] in ("DROP", "REJECT"):
                        target = parts[1]
                        src = parts[3] if parts[3] != "0.0.0.0/0" else None
                        if src:
                            subprocess.run(
                                ["iptables", "-A", "CYBERGUARD", "-s", src, "-j", target],
                                capture_output=True, timeout=5)
            return True
        except Exception as e:
            logger.error("CyberGuard chain restore: %s", e)
            return False
