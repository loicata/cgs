"""Multi-channel notification dispatcher: Slack, Teams, Telegram."""
import logging, threading, time
from datetime import datetime
import requests

logger = logging.getLogger("cgs.notifications")
SEV = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW", 5: "INFO"}
SEV_COLOR = {1: "#e74c3c", 2: "#e67e22", 3: "#f1c40f", 4: "#3498db", 5: "#95a5a6"}
RATE_LIMIT = 30
RATE_WINDOW = 3600
MAX_DETAIL = 500
RETRY_ATTEMPTS = 2
RETRY_BACKOFF = 5


class _ChannelState:
    __slots__ = ("enabled", "sent", "errors", "rate_limited", "_timestamps", "_lock")

    def __init__(self, enabled=False):
        self.enabled = enabled
        self.sent = 0
        self.errors = 0
        self.rate_limited = 0
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = time.time()
        with self._lock:
            self._timestamps = [t for t in self._timestamps if now - t < RATE_WINDOW]
            if len(self._timestamps) >= RATE_LIMIT:
                self.rate_limited += 1
                return False
            self._timestamps.append(now)
            return True

    def record_ok(self):
        self.sent += 1

    def record_err(self):
        self.errors += 1

    def as_dict(self):
        return {"enabled": self.enabled, "sent": self.sent,
                "errors": self.errors, "rate_limited": self.rate_limited}


class NotificationDispatcher:
    def __init__(self, config):
        self.cfg = config
        self._channels: dict[str, _ChannelState] = {
            "slack": _ChannelState(bool(config.get("notifications.slack.enabled"))),
            "teams": _ChannelState(bool(config.get("notifications.teams.enabled"))),
            "telegram": _ChannelState(bool(config.get("notifications.telegram.enabled"))),
        }

    # ── public API ──────────────────────────────────

    def send(self, severity: int, title: str, detail: str = "",
             src_ip: str = "", dst_ip: str = ""):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        detail = (detail or "")[:MAX_DETAIL]
        for name, state in self._channels.items():
            if not state.enabled:
                continue
            if not state.allow():
                logger.debug("Rate-limited on %s", name)
                continue
            threading.Thread(
                target=self._deliver, daemon=True,
                args=(name, state, severity, title, detail, src_ip, dst_ip, ts),
            ).start()

    @property
    def stats(self) -> dict:
        return {n: s.as_dict() for n, s in self._channels.items()}

    # ── delivery with retry ─────────────────────────

    def _deliver(self, name, state, severity, title, detail, src_ip, dst_ip, ts):
        sender = {"slack": self._slack, "teams": self._teams,
                  "telegram": self._telegram}[name]
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                sender(severity, title, detail, src_ip, dst_ip, ts)
                state.record_ok()
                return
            except Exception as exc:
                logger.warning("%s attempt %d failed: %s", name, attempt, exc)
                if attempt < RETRY_ATTEMPTS:
                    time.sleep(RETRY_BACKOFF)
        state.record_err()

    # ── Slack ───────────────────────────────────────

    def _slack(self, sev, title, detail, src_ip, dst_ip, ts):
        url = self.cfg.get("notifications.slack.webhook_url", "")
        if not url:
            raise ValueError("Slack webhook URL not configured")
        label = SEV.get(sev, "INFO")
        color = SEV_COLOR.get(sev, "#95a5a6")
        fields = []
        if src_ip:
            fields.append({"type": "mrkdwn", "text": f"*Source:* `{src_ip}`"})
        if dst_ip:
            fields.append({"type": "mrkdwn", "text": f"*Dest:* `{dst_ip}`"})
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"[{label}] {title}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": detail or "_No details_"}},
        ]
        if fields:
            blocks.append({"type": "section", "fields": fields})
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn", "text": f"CGS | {ts}"}]})
        payload = {"attachments": [{"color": color, "blocks": blocks}]}
        r = requests.post(url, json=payload, timeout=10)
        r.raise_for_status()

    # ── Microsoft Teams ─────────────────────────────

    def _teams(self, sev, title, detail, src_ip, dst_ip, ts):
        url = self.cfg.get("notifications.teams.webhook_url", "")
        if not url:
            raise ValueError("Teams webhook URL not configured")
        label = SEV.get(sev, "INFO")
        color = SEV_COLOR.get(sev, "#95a5a6")
        facts = [{"name": "Severity", "value": label}, {"name": "Time", "value": ts}]
        if src_ip:
            facts.append({"name": "Source IP", "value": src_ip})
        if dst_ip:
            facts.append({"name": "Dest IP", "value": dst_ip})
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color.lstrip("#"),
            "summary": f"[{label}] {title}",
            "sections": [{
                "activityTitle": f"[{label}] {title}",
                "facts": facts,
                "text": detail or "No details",
                "markdown": True,
            }],
        }
        r = requests.post(url, json=card, timeout=10)
        r.raise_for_status()

    # ── Telegram ────────────────────────────────────

    def _telegram(self, sev, title, detail, src_ip, dst_ip, ts):
        token = self.cfg.get("notifications.telegram.bot_token", "")
        chat = self.cfg.get("notifications.telegram.chat_id", "")
        if not token or not chat:
            raise ValueError("Telegram bot_token/chat_id not configured")
        label = SEV.get(sev, "INFO")
        parts = [
            f"<b>[{label}]</b> {title}",
            detail or "<i>No details</i>",
        ]
        if src_ip:
            parts.append(f"<b>Src:</b> <code>{src_ip}</code>")
        if dst_ip:
            parts.append(f"<b>Dst:</b> <code>{dst_ip}</code>")
        parts.append(f"<i>{ts}</i>")
        text = "\n".join(parts)
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        r = requests.post(url, json={"chat_id": chat, "text": text,
                                      "parse_mode": "HTML"}, timeout=10)
        r.raise_for_status()
