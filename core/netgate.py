"""
CyberGuard Sentinel — Netgate firewall control (pfSense / OPNsense).

Allows Sentinel to act directly sur le perimeter firewall :
  - Add/remove IPs dans un block alias
  - Create dynamic block rules
  - Apply changes (reload firewall)
  - Read firewall state (interfaces, rules, aliases)

Supporte both Netgate firmware :
  - pfSense  : via le package pfSense-pkg-API (REST) ou FauxAPI
  - OPNsense : via native REST API (key + secret)

The main approach uses an alias (address table) named
"CyberGuard_Block" que le Sentinel remplit dynamiquement.
The admin just needs to create a block rule pointant vers cet alias.
"""

import json
import logging
import time
import urllib3
from datetime import datetime
from typing import Optional

import requests

logger = logging.getLogger("cyberguard.netgate")

# Disable SSL warnings pour les self-signed firewall certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NetgateFirewall:
    """Unified interface to control pfSense or OPNsense."""

    def __init__(self, config):
        self.cfg = config
        self.enabled = config.get("netgate.enabled", False)
        self.fw_type = config.get("netgate.type", "").lower()  # "pfsense" ou "opnsense"
        self.host = config.get("netgate.host", "")
        self.port = config.get("netgate.port", 443)
        self.verify_ssl = config.get("netgate.verify_ssl", False)
        self.timeout = config.get("netgate.timeout", 15)

        # Alias used for blocking (manually created on firewall)
        self.block_alias = config.get("netgate.block_alias", "CyberGuard_Block")

        # Auth pfSense (API key + client ID ou user/password pour FauxAPI)
        self.pf_api_key = config.get("netgate.pfsense_api_key", "")
        self.pf_api_client = config.get("netgate.pfsense_api_client", "")

        # Auth OPNsense (key + secret)
        self.opn_key = config.get("netgate.opnsense_key", "")
        self.opn_secret = config.get("netgate.opnsense_secret", "")

        self.base_url = f"https://{self.host}:{self.port}"

        # Cache of currently blocked IPs sur le firewall
        self._blocked_ips: set[str] = set()
        self._last_sync = 0

        if self.enabled:
            if not self.host:
                logger.error("Netgate enabled but no host configured.")
                self.enabled = False
            elif self.fw_type not in ("pfsense", "opnsense"):
                logger.error("Netgate unknown type : '%s' (pfsense or opnsense expected)", self.fw_type)
                self.enabled = False
            else:
                logger.info("Netgate %s configured : %s:%d (alias=%s)",
                           self.fw_type, self.host, self.port, self.block_alias)
                # Sync initiale
                self._sync_blocked()

    # ══════════════════════════════════════════════
    # Unified API
    # ══════════════════════════════════════════════

    def block_ip(self, ip: str, reason: str = "") -> bool:
        """Adds an IP to the block alias on Netgate firewall."""
        if not self.enabled:
            return False
        if ip in self._blocked_ips:
            logger.debug("IP %s already in Netgate alias", ip)
            return True

        logger.warning("🔥 Netgate : blocking %s sur %s (%s)", ip, self.host, reason)

        if self.fw_type == "pfsense":
            ok = self._pf_add_to_alias(ip)
        else:
            ok = self._opn_add_to_alias(ip)

        if ok:
            self._blocked_ips.add(ip)
            self._apply_changes()
            logger.warning("🔥 Netgate : %s blocked successfully", ip)
        else:
            logger.error("🔥 Netgate : block failed for %s", ip)
        return ok

    def unblock_ip(self, ip: str) -> bool:
        """Retire une IP de l'block alias."""
        if not self.enabled:
            return False

        logger.info("🔓 Netgate : unblocking %s", ip)

        if self.fw_type == "pfsense":
            ok = self._pf_remove_from_alias(ip)
        else:
            ok = self._opn_remove_from_alias(ip)

        if ok:
            self._blocked_ips.discard(ip)
            self._apply_changes()
        return ok

    def get_status(self) -> dict:
        """Returns Netgate firewall status."""
        if not self.enabled:
            return {"enabled": False}
        if self.fw_type == "pfsense":
            return self._pf_status()
        else:
            return self._opn_status()

    def get_blocked_ips(self) -> list[str]:
        """Returns la liste des IPs dans l'block alias."""
        self._sync_blocked()
        return sorted(self._blocked_ips)

    # ══════════════════════════════════════════════
    # pfSense (via pfSense-pkg-API REST)
    # ══════════════════════════════════════════════

    def _pf_request(self, method: str, endpoint: str, data: dict = None) -> Optional[dict]:
        """Query vers l'API REST pfSense."""
        url = f"{self.base_url}/api/v1{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"{self.pf_api_client} {self.pf_api_key}",
        }
        try:
            resp = requests.request(
                method, url, headers=headers, json=data,
                verify=self.verify_ssl, timeout=self.timeout,
            )
            if resp.status_code in (200, 201):
                return resp.json()
            logger.warning("pfSense API %s %s → %d : %s",
                          method, endpoint, resp.status_code, resp.text[:200])
            return None
        except requests.exceptions.ConnectionError:
            logger.error("pfSense unreachable : %s", self.host)
            return None
        except Exception as e:
            logger.error("pfSense API erreur : %s", e)
            return None

    def _pf_add_to_alias(self, ip: str) -> bool:
        """Adds an IP to a pfSense alias (address table)."""
        # Method 1: REST API (pfSense-pkg-API)
        result = self._pf_request("POST", "/firewall/alias/entry", {
            "name": self.block_alias,
            "address": [ip],
            "detail": [f"CyberGuard {datetime.now().strftime('%Y-%m-%d %H:%M')}"],
        })
        if result and result.get("status") == "ok":
            return True

        # Method 2: Add entry to existing alias
        result = self._pf_request("PUT", f"/firewall/alias", {
            "name": self.block_alias,
            "type": "host",
            "address": ip,
            "detail": f"CyberGuard block",
            "apply": True,
        })
        return result is not None

    def _pf_remove_from_alias(self, ip: str) -> bool:
        result = self._pf_request("DELETE", "/firewall/alias/entry", {
            "name": self.block_alias,
            "address": [ip],
        })
        return result is not None

    def _pf_status(self) -> dict:
        status = {"type": "pfsense", "host": self.host, "reachable": False}
        result = self._pf_request("GET", "/status/system")
        if result:
            data = result.get("data", {})
            status.update({
                "reachable": True,
                "hostname": data.get("hostname", ""),
                "version": data.get("system_version", ""),
                "uptime": data.get("uptime", ""),
                "cpu": data.get("cpu_usage", ""),
                "mem": data.get("mem_usage", ""),
            })
        # Compter les IPs dans l'alias
        alias_data = self._pf_request("GET", f"/firewall/alias?name={self.block_alias}")
        if alias_data and alias_data.get("data"):
            entries = alias_data["data"]
            if isinstance(entries, list):
                status["blocked_count"] = len(entries)
        return status

    # ══════════════════════════════════════════════
    # OPNsense (API REST native)
    # ══════════════════════════════════════════════

    def _opn_request(self, method: str, endpoint: str, data: dict = None) -> Optional[dict]:
        """Query vers l'API REST OPNsense."""
        url = f"{self.base_url}/api{endpoint}"
        try:
            resp = requests.request(
                method, url,
                auth=(self.opn_key, self.opn_secret),
                json=data,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return resp.json()
            logger.warning("OPNsense API %s %s → %d : %s",
                          method, endpoint, resp.status_code, resp.text[:200])
            return None
        except requests.exceptions.ConnectionError:
            logger.error("OPNsense unreachable : %s", self.host)
            return None
        except Exception as e:
            logger.error("OPNsense API erreur : %s", e)
            return None

    def _opn_add_to_alias(self, ip: str) -> bool:
        """Adds an IP to an OPNsense alias via l'API firewall."""
        # Retrieve alias UUID
        alias_uuid = self._opn_get_alias_uuid()
        if not alias_uuid:
            logger.error("Alias '%s' not found sur OPNsense. Create it in Firewall > Aliases.",
                        self.block_alias)
            return False

        # Retrieve current content de l'alias
        result = self._opn_request("GET", f"/firewall/alias_util/list/{self.block_alias}")
        current_rows = []
        if result and "rows" in result:
            current_rows = [r.get("ip") for r in result["rows"] if r.get("ip")]

        if ip in current_rows:
            return True

        # Ajouter l'IP via alias_util
        result = self._opn_request("POST", "/firewall/alias_util/add", {
            "alias": self.block_alias,
            "address": ip,
        })
        if result and result.get("status") in ("done", "ok"):
            return True

        # Fallback : modifier l'alias directement
        current_rows.append(ip)
        result = self._opn_request("POST", f"/firewall/alias/setItem/{alias_uuid}", {
            "alias": {
                "content": "\n".join(current_rows),
            }
        })
        return result is not None

    def _opn_remove_from_alias(self, ip: str) -> bool:
        result = self._opn_request("POST", "/firewall/alias_util/delete", {
            "alias": self.block_alias,
            "address": ip,
        })
        return result is not None or True

    def _opn_get_alias_uuid(self) -> Optional[str]:
        """Retrieves the block alias UUID on OPNsense."""
        result = self._opn_request("GET", "/firewall/alias/searchItem")
        if result and "rows" in result:
            for row in result["rows"]:
                if row.get("name") == self.block_alias:
                    return row.get("uuid")
        return None

    def _opn_status(self) -> dict:
        status = {"type": "opnsense", "host": self.host, "reachable": False}
        result = self._opn_request("GET", "/core/firmware/status")
        if result:
            status.update({
                "reachable": True,
                "version": result.get("product_version", ""),
                "hostname": result.get("product_name", ""),
            })
        # Compter les IPs dans l'alias
        alias_data = self._opn_request("GET", f"/firewall/alias_util/list/{self.block_alias}")
        if alias_data and "rows" in alias_data:
            status["blocked_count"] = len(alias_data["rows"])
        return status

    # ══════════════════════════════════════════════
    # Commun
    # ══════════════════════════════════════════════

    def _apply_changes(self):
        """Applies firewall changes (reloads rules)."""
        if self.fw_type == "pfsense":
            self._pf_request("POST", "/firewall/apply")
        else:
            self._opn_request("POST", "/firewall/alias_util/reconfigure")

    def _sync_blocked(self):
        """Synchronizes local list avec l'alias sur le firewall."""
        if not self.enabled:
            return
        now = time.time()
        if now - self._last_sync < 60:
            return
        self._last_sync = now

        try:
            if self.fw_type == "pfsense":
                data = self._pf_request("GET", f"/firewall/alias?name={self.block_alias}")
                if data and data.get("data"):
                    entries = data["data"]
                    if isinstance(entries, list):
                        for e in entries:
                            addr = e.get("address", "") if isinstance(e, dict) else str(e)
                            if addr:
                                self._blocked_ips.add(addr)
            else:
                data = self._opn_request("GET", f"/firewall/alias_util/list/{self.block_alias}")
                if data and "rows" in data:
                    for row in data["rows"]:
                        ip = row.get("ip", "")
                        if ip:
                            self._blocked_ips.add(ip)
            logger.debug("Sync Netgate : %d IPs dans l'alias", len(self._blocked_ips))
        except Exception as e:
            logger.warning("Sync Netgate failede : %s", e)

    @property
    def stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "type": self.fw_type,
            "host": self.host,
            "alias": self.block_alias,
            "blocked_count": len(self._blocked_ips),
        }
