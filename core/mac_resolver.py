"""
CyberGuard Sentinel — MAC resolver ↔ IP.

Problem: on a DHCP network, IPs change (DHCP server reboot,
expiration de bail, etc.). Le Sentinel ne peut pas se fier aux IPs seules.

Solution: each host is identified by its MAC. The IP is a volatile
attribute updated dynamically. All decisions (block,
quarantine, directory, whitelist) can reference a MAC.

Ce module :
  - Maintains a real-time MAC ↔ IP table
  - Detects IP changes (DHCP renewal)
  - Automatically updates:
    · The host database
    · Defense rules (iptables) — re-blocks the new IP
    · User directory (MAC → email resolution)
    · La whitelist
  - Alerte (info) quand une IP change, sans faux positif "nouvel host"
"""

import logging
import threading
import time
from datetime import datetime

from core.database import Host, Port, Alert, db

logger = logging.getLogger("cyberguard.macresolver")


class MacIpResolver:
    """Dynamic MAC ↔ IP table avec propagation des changements."""

    def __init__(self, config, alert_fn):
        self.cfg = config
        self._alert = alert_fn

        # Main table: MAC → {ip, hostname, vendor, first_seen, last_seen}
        self._mac_table: dict[str, dict] = {}
        # Reverse index: IP → MAC (for fast resolution)
        self._ip_to_mac: dict[str, str] = {}
        self._lock = threading.Lock()

        # Registered callbacks par les autres modules quand une IP change
        self._on_ip_change_callbacks: list = []

        # Load state from DB on startup
        self._load_from_db()

    # ══════════════════════════════════════════════
    # Update (called by discovery module)
    # ══════════════════════════════════════════════
    def update(self, mac: str, ip: str, hostname: str = "", vendor: str = "",
               os_hint: str = "") -> dict:
        """
        Updates MAC ↔ IP association.
        Returns {"changed": bool, "old_ip": str, "new_ip": str, "mac": str}
        """
        if not mac or mac == "00:00:00:00:00:00" or not ip:
            return {"changed": False}

        mac = mac.lower()
        now = datetime.now()
        result = {"changed": False, "old_ip": "", "new_ip": ip, "mac": mac}

        with self._lock:
            if mac in self._mac_table:
                entry = self._mac_table[mac]
                old_ip = entry["ip"]

                if old_ip != ip:
                    # ═══ IP CHANGE DETECTED ═══
                    result["changed"] = True
                    result["old_ip"] = old_ip

                    logger.info(
                        "🔄 DHCP : %s changed IP : %s → %s (MAC=%s)",
                        entry.get("hostname") or mac, old_ip, ip, mac
                    )

                    # Update reverse index
                    self._ip_to_mac.pop(old_ip, None)
                    self._ip_to_mac[ip] = mac

                    # Update DB — merge, don't duplicate
                    self._handle_ip_change(mac, old_ip, ip)

                    # Alerte info (pas une menace)
                    self._alert(
                        severity=5, source="dhcp", category="ip_change",
                        title=f"IP change (DHCP) : {old_ip} → {ip}",
                        detail=f"MAC={mac} Hostname={entry.get('hostname', '')}",
                        src_ip=ip,
                        notify=False,
                    )

                # Update metadata
                entry["ip"] = ip
                entry["last_seen"] = now
                if hostname:
                    entry["hostname"] = hostname
                if vendor:
                    entry["vendor"] = vendor

            else:
                # New MAC never seen before
                self._mac_table[mac] = {
                    "ip": ip, "hostname": hostname, "vendor": vendor,
                    "os_hint": os_hint,
                    "first_seen": now, "last_seen": now,
                }
                self._ip_to_mac[ip] = mac

            # Si une autre MAC avait cette IP avant → conflit (rare mais possible)
            for other_mac, other_entry in self._mac_table.items():
                if other_mac != mac and other_entry["ip"] == ip:
                    logger.warning(
                        "⚠ IP conflict : %s assigned to MAC %s ET %s",
                        ip, mac, other_mac
                    )
                    other_entry["ip"] = ""  # Old association is obsolete

        # Propagate change to registered modules
        if result["changed"]:
            for cb in self._on_ip_change_callbacks:
                try:
                    cb(mac, result["old_ip"], ip)
                except Exception as e:
                    logger.error("Callback IP change : %s", e)

        return result

    # ══════════════════════════════════════════════
    # Resolvedtion
    # ══════════════════════════════════════════════
    def mac_to_ip(self, mac: str) -> str:
        """Returns l'IP actuelle d'une MAC."""
        with self._lock:
            entry = self._mac_table.get(mac.lower())
            return entry["ip"] if entry else ""

    def ip_to_mac(self, ip: str) -> str:
        """Returns the MAC associated with an IP."""
        with self._lock:
            return self._ip_to_mac.get(ip, "")

    def resolve_target(self, ip_or_mac: str) -> dict:
        """Resolves a target (IP or MAC) to {ip, mac, hostname}."""
        ip_or_mac = ip_or_mac.lower()
        with self._lock:
            # C'est une MAC ?
            if ":" in ip_or_mac and ip_or_mac in self._mac_table:
                entry = self._mac_table[ip_or_mac]
                return {"ip": entry["ip"], "mac": ip_or_mac,
                        "hostname": entry.get("hostname", "")}
            # C'est une IP ?
            if ip_or_mac in self._ip_to_mac:
                mac = self._ip_to_mac[ip_or_mac]
                entry = self._mac_table.get(mac, {})
                return {"ip": ip_or_mac, "mac": mac,
                        "hostname": entry.get("hostname", "")}
        return {"ip": ip_or_mac, "mac": "", "hostname": ""}

    def get_user_email(self, ip: str) -> dict:
        """
        Resolves a user's email from their current IP.
        Cherche d'abord par IP dans l'annuaire, puis par MAC.
        """
        directory = self.cfg.get("email.user_directory", [])

        # Recherche directe par IP
        for entry in directory:
            if entry.get("ip") == ip:
                return entry

        # Search by MAC (survives DHCP change)
        mac = self.ip_to_mac(ip)
        if mac:
            for entry in directory:
                if entry.get("mac", "").lower() == mac:
                    return entry

        return {}

    # ══════════════════════════════════════════════
    # Enregistrement de callbacks
    # ══════════════════════════════════════════════
    def on_ip_change(self, callback):
        """Registers a callback called when an IP changes.
        Signature : callback(mac: str, old_ip: str, new_ip: str)
        """
        self._on_ip_change_callbacks.append(callback)

    # ══════════════════════════════════════════════
    # BDD : gestion du changement d'IP
    # ══════════════════════════════════════════════
    def _handle_ip_change(self, mac: str, old_ip: str, new_ip: str):
        """Updates DB when a MAC changes IP (DHCP)."""
        try:
            with db.atomic():
                # Find host by MAC
                host = Host.get_or_none(Host.mac == mac)

                if host:
                    # Update existing host IP
                    old_host_ip = host.ip
                    host.ip = new_ip
                    host.last_seen = datetime.now()
                    host.save()

                    # Update associated ports
                    Port.update(host_ip=new_ip).where(Port.host_ip == old_host_ip).execute()

                    logger.info("DB: host MAC=%s IP %s → %s", mac, old_host_ip, new_ip)

                else:
                    # Chercher par ancienne IP
                    host = Host.get_or_none(Host.ip == old_ip)
                    if host:
                        host.ip = new_ip
                        host.mac = mac
                        host.last_seen = datetime.now()
                        host.save()
                        Port.update(host_ip=new_ip).where(Port.host_ip == old_ip).execute()

                # Remove potential duplicate with new IP
                duplicate = Host.get_or_none((Host.ip == new_ip) & (Host.mac != mac))
                if duplicate:
                    logger.info("DB: removing duplicate IP %s (MAC=%s)", new_ip, duplicate.mac)
                    Port.delete().where(Port.host_ip == new_ip).execute()
                    duplicate.delete_instance()

        except Exception as e:
            logger.error("Error BDD changement IP : %s", e)

    def _load_from_db(self):
        """Loads MAC ↔ IP table from DB on startup."""
        try:
            for h in Host.select().where(Host.mac.is_null(False)):
                if h.mac and h.ip:
                    mac = h.mac.lower()
                    self._mac_table[mac] = {
                        "ip": h.ip, "hostname": h.hostname or "",
                        "vendor": h.vendor or "", "os_hint": h.os_hint or "",
                        "first_seen": h.first_seen, "last_seen": h.last_seen,
                    }
                    self._ip_to_mac[h.ip] = mac
            logger.info("MAC table loaded : %d entries", len(self._mac_table))
        except Exception:
            pass  # DB not yet initialized

    # ══════════════════════════════════════════════
    # Whitelist par MAC
    # ══════════════════════════════════════════════
    def is_whitelisted(self, ip: str, whitelist_ips: set, whitelist_macs: set = None) -> bool:
        """Checks if an IP or its MAC is whitelisted."""
        if ip in whitelist_ips:
            return True
        if whitelist_macs:
            mac = self.ip_to_mac(ip)
            if mac and mac in whitelist_macs:
                return True
        return False

    # ══════════════════════════════════════════════
    # Stats
    # ══════════════════════════════════════════════
    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "total_macs": len(self._mac_table),
                "total_ips": len(self._ip_to_mac),
                "table": [
                    {"mac": mac, "ip": e["ip"], "hostname": e.get("hostname", ""),
                     "vendor": e.get("vendor", ""),
                     "last_seen": e["last_seen"].isoformat() if isinstance(e["last_seen"], datetime) else str(e["last_seen"])}
                    for mac, e in sorted(self._mac_table.items(), key=lambda x: x[1].get("last_seen", ""), reverse=True)
                ][:50],
            }
