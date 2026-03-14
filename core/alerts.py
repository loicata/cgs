"""Alert engine: deduplication, cooldown, multi-channel dispatch."""
import logging, smtplib, syslog, threading, time
from datetime import datetime
from email.mime.text import MIMEText
import requests
from core.database import Alert

logger = logging.getLogger("cyberguard.alerts")
SEV = {1:"CRITICAL",2:"HIGH",3:"MEDIUM",4:"LOW",5:"INFO"}
ICO = {1:"🔴",2:"🟠",3:"🟡",4:"🔵",5:"⚪"}

class AlertEngine:
    def __init__(self, config):
        self.cfg = config
        self.cooldown = config.get("alerts.cooldown_seconds", 300)
        self.max_h = config.get("alerts.max_per_hour", 120)
        self._recent: dict[str, float] = {}
        self._hcount = 0; self._hstart = time.time()
        self._lock = threading.Lock()
        self._ws_cb = None  # injected by web

    def fire(self, severity=3, source="system", category="", title="",
             detail="", src_ip=None, dst_ip=None, ioc=None, raw=None,
             notify=True, **_):
        with self._lock:
            now = time.time()
            if now - self._hstart > 3600:
                self._hcount = 0; self._hstart = now
            if self._hcount >= self.max_h: return None
            self._hcount += 1
            dk = f"{source}:{category}:{title}:{src_ip}"
            if dk in self._recent and now - self._recent[dk] < self.cooldown:
                return None
            self._recent[dk] = now

        a = Alert.create(severity=severity, source=source, category=category,
                         title=title, detail=detail, src_ip=src_ip,
                         dst_ip=dst_ip, ioc=ioc)
        fn = logger.critical if severity <= 1 else logger.warning if severity <= 2 else logger.info
        fn("%s [%s] %s | %s", ICO.get(severity,""), SEV.get(severity,"?"), source, title)

        if self._ws_cb:
            try: self._ws_cb(self._ser(a))
            except: pass
        if notify and severity <= 3:
            self._dispatch(a)
        return a

    def _dispatch(self, a):
        ch = self.cfg.get("alerts", {})
        if ch.get("email",{}).get("enabled"):
            threading.Thread(target=self._email, args=(a,), daemon=True).start()
        if ch.get("webhook",{}).get("enabled"):
            threading.Thread(target=self._webhook, args=(a,), daemon=True).start()
        if ch.get("syslog",{}).get("enabled"):
            self._syslog(a)

    def _email(self, a):
        try:
            c = self.cfg.get("alerts.email")
            m = MIMEText(f"[{SEV[a.severity]}] {a.source}\n{a.title}\n\n{a.detail or ''}\nSrc={a.src_ip} Dst={a.dst_ip}")
            m["Subject"] = f"[CyberGuard][{SEV[a.severity]}] {a.title}"
            m["From"] = c["from"]; m["To"] = c["to"]
            with smtplib.SMTP(c["server"], c.get("port",587)) as s:
                if c.get("tls"): s.starttls()
                if c.get("user"): s.login(c["user"], c["password"])
                s.send_message(m)
        except Exception as e: logger.error("Email: %s", e)

    def _webhook(self, a):
        try:
            requests.post(self.cfg.get("alerts.webhook.url"),
                json={"text": f"{ICO[a.severity]} [{SEV[a.severity]}] {a.source}: {a.title}\n{a.detail or ''}"},
                timeout=10)
        except Exception as e: logger.error("Webhook: %s", e)

    def _syslog(self, a):
        try:
            p = {1:syslog.LOG_CRIT,2:syslog.LOG_ERR,3:syslog.LOG_WARNING}.get(a.severity, syslog.LOG_INFO)
            syslog.openlog("cyberguard", syslog.LOG_PID, syslog.LOG_LOCAL0)
            syslog.syslog(p, f"[{a.source}] {a.title}")
            syslog.closelog()
        except: pass

    @staticmethod
    def _ser(a):
        return {"id":a.id,"ts":a.ts.isoformat(),"severity":a.severity,
                "severity_label":SEV.get(a.severity),"source":a.source,
                "category":a.category,"title":a.title,"detail":a.detail,
                "src_ip":a.src_ip,"dst_ip":a.dst_ip,"ioc":a.ioc,"ack":a.ack}

    @staticmethod
    def get_recent(limit=200, max_sev=5):
        return [AlertEngine._ser(a) for a in
                Alert.select().where(Alert.severity <= max_sev).order_by(Alert.ts.desc()).limit(limit)]
