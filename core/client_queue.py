"""
CGS — Client notification queue.

Zero-privilege architecture:
  - Sentinel NEVER connects to client machines
  - Clients poll Sentinel for pending notifications
  - Clients act locally (popup, forensic collection, scan)
  - Sentinel only stores a queue of pending messages per IP

Flow:
  1. Incident triggers → Sentinel enqueues a notification for the target IP
  2. Client polls GET /api/client/check → receives pending notification
  3. Client displays popup locally
  4. Client sends POST /api/client/ack → Sentinel records acknowledgement
  5. After resolution, client polls again → receives "collect forensic" instruction
  6. Client runs local collection, saves report to desktop
  7. Client can optionally POST the report back to Sentinel
"""

import json
import logging
import time
import threading
from datetime import datetime
from typing import Optional

logger = logging.getLogger("cgs.client_queue")


class ClientMessage:
    """A pending message for a client machine."""

    def __init__(self, msg_type: str, incident_id: str, payload: dict = None):
        self.id = f"{msg_type}-{incident_id}-{int(time.time())}"
        self.msg_type = msg_type       # "shutdown", "all_clear", "collect_forensic"
        self.incident_id = incident_id
        self.payload = payload or {}
        self.created_at = time.time()
        self.acked = False
        self.acked_at = 0.0
        self.acked_by = ""             # hostname or user that acknowledged

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.msg_type,
            "incident_id": self.incident_id,
            "payload": self.payload,
            "created_at": self.created_at,
            "created_iso": datetime.fromtimestamp(self.created_at).isoformat(),
            "acked": self.acked,
        }


class ClientNotificationQueue:
    """
    Holds pending notifications for client machines.
    Clients poll this queue — Sentinel never connects to them.
    """

    def __init__(self, config):
        self.cfg = config
        self.enabled = config.get("client_agent.enabled", True)
        self.message_ttl = config.get("client_agent.message_ttl_minutes", 120)
        self.security_contact = config.get("email.security_contact",
                                           "the IT security team")
        self.shared_secret = config.get("client_agent.shared_secret", "")

        # Queue: IP → list of ClientMessage
        self._queue: dict[str, list[ClientMessage]] = {}
        self._lock = threading.Lock()

        # Track which IPs have an active agent (based on polling)
        self._active_agents: dict[str, float] = {}  # IP → last poll timestamp

        # Ack wait timeout (seconds) — if popup not acked within this, fallback to email
        self.ack_timeout = config.get("client_agent.ack_timeout_seconds", 120)

        # Anti-replay protection
        from core.security import AntiReplay
        self._anti_replay = AntiReplay(window_seconds=60)

        # Cleanup thread
        threading.Thread(target=self._cleanup_loop, daemon=True,
                        name="client-queue-gc").start()

        if self.enabled:
            if not self.shared_secret:
                logger.warning("Client agent enabled but NO shared_secret configured. "
                              "Agents will not be able to authenticate.")
            logger.info("Client notification queue enabled (TTL=%d min, auth=%s, anti-replay=on)",
                       self.message_ttl, "HMAC" if self.shared_secret else "NONE")

    # ══════════════════════════════════════════════
    # HMAC authentication
    # ══════════════════════════════════════════════

    def _hmac_sign(self, payload: str) -> str:
        """Compute HMAC-SHA256 signature."""
        import hashlib, hmac as _hmac
        return _hmac.new(
            self.shared_secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()

    def verify_client(self, hostname: str, timestamp: str, signature: str) -> bool:
        """Verify client request HMAC signature + anti-replay."""
        if not self.shared_secret:
            return True  # No secret configured = accept all (warn at startup)
        # Anti-replay: check timestamp freshness
        valid, reason = self._anti_replay.check(timestamp, nonce=f"{hostname}:{timestamp}")
        if not valid:
            logger.warning("Anti-replay rejected request from %s: %s", hostname, reason)
            return False
        expected = self._hmac_sign(f"check:{hostname}:{timestamp}")
        import hmac as _hmac
        return _hmac.compare_digest(expected, signature)

    def verify_client_ack(self, data: dict) -> bool:
        """Verify client ack HMAC signature."""
        if not self.shared_secret:
            return True
        sig = data.pop("_sig", "")
        import hmac as _hmac
        expected = self._hmac_sign(json.dumps(data, sort_keys=True))
        return _hmac.compare_digest(expected, sig)

    def sign_response(self, data: dict) -> dict:
        """Sign server response so client can verify our identity."""
        if not self.shared_secret:
            return data
        sig = self._hmac_sign(json.dumps(data, sort_keys=True))
        data["_sig"] = sig
        return data

    # ══════════════════════════════════════════════
    # Enqueue (called by incident engine)
    # ══════════════════════════════════════════════

    def enqueue_shutdown(self, ip: str, incident_id: str,
                         threat_type: str = "", detail: str = "") -> str:
        """Queue a shutdown request for a client IP."""
        msg = ClientMessage("shutdown", incident_id, {
            "action": "shutdown",
            "title": "SECURITY ALERT — Shut down your computer",
            "message": (
                "A cyberattack has been detected targeting your computer.\n\n"
                "Please shut down your computer IMMEDIATELY.\n\n"
                "You will receive a notification once the threat has been "
                "eradicated and it is safe to restart.\n\n"
                f"If your computer is the only way to access your emails, "
                f"please contact {self.security_contact} directly."
            ),
            "threat_type": threat_type,
            "detail": detail[:500],
            "security_contact": self.security_contact,
            "severity": "critical",
        })
        self._add(ip, msg)
        logger.info("📢 Queued shutdown notification for %s (incident %s)", ip, incident_id)
        return msg.id

    def enqueue_all_clear(self, ip: str, incident_id: str,
                          resolved: bool = True, risk_detail: str = "") -> str:
        """Queue an all-clear (or risk warning) for a client IP."""
        if resolved:
            msg = ClientMessage("all_clear", incident_id, {
                "action": "all_clear",
                "title": "Threat eradicated — You can restart your computer",
                "message": (
                    "The cyberattack has been successfully neutralized.\n\n"
                    "You can turn your computer back on and resume work normally.\n\n"
                    "A detailed report has been sent to the security team."
                ),
                "severity": "info",
            })
        else:
            msg = ClientMessage("risk_warning", incident_id, {
                "action": "risk_warning",
                "title": "Residual risk — Do NOT restart your computer",
                "message": (
                    "The incident has been partially resolved but a residual "
                    "risk remains.\n\n"
                    "Do NOT turn your computer back on.\n\n"
                    f"Please contact {self.security_contact} for instructions.\n\n"
                    f"Details: {risk_detail}"
                ),
                "severity": "warning",
                "risk_detail": risk_detail,
            })
        self._add(ip, msg)
        logger.info("📢 Queued %s for %s (incident %s)", msg.msg_type, ip, incident_id)
        return msg.id

    def enqueue_collect_forensic(self, ip: str, incident_id: str) -> str:
        """Queue a forensic collection request for a client IP."""
        msg = ClientMessage("collect_forensic", incident_id, {
            "action": "collect_forensic",
            "title": "Security scan requested",
            "message": (
                "The security team requests a local security scan of your "
                "computer following the recent incident.\n\n"
                "A report will be generated on your Desktop.\n\n"
                "This scan is READ-ONLY and does not modify anything on your computer."
            ),
            "severity": "info",
        })
        self._add(ip, msg)
        logger.info("📢 Queued forensic collection for %s (incident %s)", ip, incident_id)
        return msg.id

    # ══════════════════════════════════════════════
    # Poll (called by client agent via API)
    # ══════════════════════════════════════════════

    def get_pending(self, ip: str) -> tuple[list[dict], int]:
        """
        Returns pending messages and recommended poll interval.
        - No pending messages → slow poll (60s)
        - Pending messages → fast poll (5s)
        """
        # Track this IP as having an active agent
        self._active_agents[ip] = time.time()

        with self._lock:
            messages = self._queue.get(ip, [])
            pending = [m.to_dict() for m in messages if not m.acked]

        # Adaptive interval: fast if messages pending, slow otherwise
        if pending:
            interval = 5
        else:
            interval = 60

        return pending, interval

    def has_active_agent(self, ip: str) -> bool:
        """Returns True if this IP has polled recently (agent is installed and running)."""
        last_seen = self._active_agents.get(ip, 0)
        # Consider agent active if it polled within the last 2 minutes
        return (time.time() - last_seen) < 120

    def acknowledge(self, ip: str, message_id: str,
                    hostname: str = "", user: str = "") -> bool:
        """Client acknowledges a message."""
        with self._lock:
            messages = self._queue.get(ip, [])
            for m in messages:
                if m.id == message_id and not m.acked:
                    m.acked = True
                    m.acked_at = time.time()
                    m.acked_by = f"{user}@{hostname}" if user else hostname
                    logger.info("📢 Message %s acknowledged by %s (%s)",
                               message_id, m.acked_by, ip)
                    return True
        return False

    def wait_for_ack(self, message_id: str, ip: str) -> bool:
        """
        Blocks until the message is acknowledged or timeout expires.
        Returns True if acked, False if timeout.
        """
        deadline = time.time() + self.ack_timeout
        check_interval = 3  # seconds

        while time.time() < deadline:
            with self._lock:
                messages = self._queue.get(ip, [])
                for m in messages:
                    if m.id == message_id and m.acked:
                        return True
            time.sleep(check_interval)

        return False

    # ══════════════════════════════════════════════
    # Internal
    # ══════════════════════════════════════════════

    def _add(self, ip: str, msg: ClientMessage):
        with self._lock:
            if ip not in self._queue:
                self._queue[ip] = []
            self._queue[ip].append(msg)

    def _cleanup_loop(self):
        """Remove expired messages."""
        while True:
            time.sleep(60)
            ttl = self.message_ttl * 60
            now = time.time()
            with self._lock:
                for ip in list(self._queue.keys()):
                    self._queue[ip] = [
                        m for m in self._queue[ip]
                        if now - m.created_at < ttl
                    ]
                    if not self._queue[ip]:
                        del self._queue[ip]

    @property
    def stats(self) -> dict:
        now = time.time()
        with self._lock:
            total = sum(len(msgs) for msgs in self._queue.values())
            pending = sum(
                1 for msgs in self._queue.values()
                for m in msgs if not m.acked
            )
        active_agents = sum(1 for t in self._active_agents.values() if now - t < 120)
        return {
            "enabled": self.enabled,
            "total_messages": total,
            "pending": pending,
            "hosts_with_messages": len(self._queue),
            "active_agents": active_agents,
            "known_agent_ips": [ip for ip, t in self._active_agents.items() if now - t < 120],
        }
