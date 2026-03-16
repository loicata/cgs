"""
CGS — Safety-first infrastructure (defense in depth).

Layer 1: @safe_thread / @safe_call decorators
    Wrap any function with try/except + crash counter + exponential backoff.
    Zero changes to existing logic.

Layer 2: Supervisor
    Monitors registered threads. Restarts dead ones. Fires alerts on failures.
    Extends the existing DegradedMode concept to cover all threads.

Layer 3: Email queue with retry
    Replaces fire-and-forget SMTP with a persistent retry queue.
"""

import functools
import logging
import threading
import time
from collections import defaultdict, deque

log = logging.getLogger("cgs.safety")


# ══════════════════════════════════════════════════
# Layer 1: Decorators
# ══════════════════════════════════════════════════

class _CrashTracker:
    """Tracks crashes per function for circuit breaker logic."""
    _data: dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
    _disabled: dict[str, float] = {}
    _lock = threading.Lock()

    @classmethod
    def record(cls, name: str) -> bool:
        """Record a crash. Returns True if circuit should open."""
        now = time.time()
        with cls._lock:
            cls._data[name].append(now)
            # 3 crashes in 10 minutes = circuit open
            recent = [t for t in cls._data[name] if now - t < 600]
            if len(recent) >= 3:
                cls._disabled[name] = now + 300  # disable for 5 min
                return True
        return False

    @classmethod
    def is_disabled(cls, name: str) -> bool:
        with cls._lock:
            until = cls._disabled.get(name, 0)
            if until and time.time() < until:
                return True
            if until:
                del cls._disabled[name]
            return False

    @classmethod
    def stats(cls) -> dict:
        with cls._lock:
            return {
                "crash_counts": {k: len(v) for k, v in cls._data.items()},
                "disabled": {k: round(v - time.time()) for k, v in cls._disabled.items()
                            if time.time() < v},
            }


def safe_thread(name: str = "", restart: bool = True, backoff: float = 5.0):
    """
    Decorator for thread target functions.
    Catches exceptions, logs them, optionally restarts with backoff.
    Circuit breaker: 3 crashes in 10 min = pause 5 min.

    Usage:
        @safe_thread("sniffer")
        def _sniff_loop(self): ...
    """
    def decorator(fn):
        fn_name = name or fn.__qualname__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            delay = backoff
            while True:
                if _CrashTracker.is_disabled(fn_name):
                    log.warning("[%s] circuit breaker active, waiting...", fn_name)
                    time.sleep(60)
                    continue
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    opened = _CrashTracker.record(fn_name)
                    if opened:
                        log.error("[%s] CIRCUIT OPEN (3 crashes in 10min): %s", fn_name, e)
                    else:
                        log.error("[%s] crashed: %s", fn_name, e, exc_info=True)

                    if not restart:
                        return
                    log.info("[%s] restarting in %.0fs...", fn_name, delay)
                    time.sleep(delay)
                    delay = min(delay * 2, 300)  # max 5 min backoff
        return wrapper
    return decorator


def safe_call(name: str = "", default=None, timeout: float = 30):
    """
    Decorator for functions that call external resources (iptables, SMTP, APIs).
    Catches exceptions, returns default on failure. No retry (caller decides).

    Usage:
        @safe_call("iptables_block")
        def _fw_block(self, ip): ...
    """
    def decorator(fn):
        fn_name = name or fn.__qualname__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                log.warning("[%s] failed: %s", fn_name, e)
                return default
        return wrapper
    return decorator


# ══════════════════════════════════════════════════
# Layer 2: Thread supervisor
# ══════════════════════════════════════════════════

class Supervisor:
    """
    Monitors registered threads and restarts them if they die.
    Fires alerts via alert_fn when a critical component fails.
    """

    def __init__(self, alert_fn=None):
        self._alert = alert_fn or (lambda **kw: None)
        # {name: {thread, target, args, kwargs, critical, restarts, max_restarts}}
        self._watched: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._running = True

        threading.Thread(target=self._monitor_loop, daemon=True,
                        name="supervisor").start()
        log.info("Supervisor started")

    def watch(self, name: str, thread: threading.Thread,
              target=None, args=(), kwargs=None,
              critical: bool = False, max_restarts: int = 5):
        """
        Register a thread to be monitored.
        If critical=True, an alert is fired when it dies.
        target/args/kwargs are used to restart the thread.
        """
        with self._lock:
            self._watched[name] = {
                "thread": thread,
                "target": target or thread._target,
                "args": args or getattr(thread, '_args', ()),
                "kwargs": kwargs or getattr(thread, '_kwargs', {}),
                "critical": critical,
                "restarts": 0,
                "max_restarts": max_restarts,
                "last_alive": time.time(),
            }

    def _monitor_loop(self):
        """Check all watched threads every 10 seconds."""
        while self._running:
            time.sleep(10)
            with self._lock:
                for name, info in list(self._watched.items()):
                    thread = info["thread"]
                    if thread.is_alive():
                        info["last_alive"] = time.time()
                        continue

                    # Thread is dead
                    if info["restarts"] >= info["max_restarts"]:
                        if info["critical"]:
                            log.error("CRITICAL: %s died and max restarts (%d) reached",
                                     name, info["max_restarts"])
                            self._alert(
                                severity=1, source="supervisor",
                                category="component_dead",
                                title=f"CRITICAL: {name} stopped (max restarts reached)",
                                detail=f"Restarted {info['restarts']} times. Manual intervention required.",
                            )
                        continue

                    # Restart
                    info["restarts"] += 1
                    log.warning("Restarting %s (attempt %d/%d)",
                               name, info["restarts"], info["max_restarts"])

                    try:
                        new_thread = threading.Thread(
                            target=info["target"],
                            args=info["args"],
                            kwargs=info["kwargs"] or {},
                            daemon=True,
                            name=name,
                        )
                        new_thread.start()
                        info["thread"] = new_thread

                        if info["critical"]:
                            self._alert(
                                severity=3, source="supervisor",
                                category="component_restarted",
                                title=f"{name} restarted (attempt {info['restarts']})",
                                detail=f"Thread was dead, restarted automatically.",
                                notify=False,
                            )
                    except Exception as e:
                        log.error("Failed to restart %s: %s", name, e)

    def stop(self):
        self._running = False

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "watched": {
                    name: {
                        "alive": info["thread"].is_alive(),
                        "critical": info["critical"],
                        "restarts": info["restarts"],
                        "max_restarts": info["max_restarts"],
                    }
                    for name, info in self._watched.items()
                },
                "crash_tracker": _CrashTracker.stats(),
            }


# ══════════════════════════════════════════════════
# Layer 3: Email retry queue
# ══════════════════════════════════════════════════

class EmailQueue:
    """
    Persistent email retry queue. Replaces fire-and-forget SMTP.
    Retries up to 3 times with exponential backoff (30s, 120s, 480s).
    """

    def __init__(self, config):
        self.cfg = config
        self._queue: deque = deque(maxlen=500)
        self._lock = threading.Lock()

        threading.Thread(target=self._process_loop, daemon=True,
                        name="email-queue").start()

    def enqueue(self, to: str, subject: str, body: str, html: bool = False,
                attachments: list = None):
        """Add an email to the retry queue."""
        with self._lock:
            self._queue.append({
                "to": to, "subject": subject, "body": body,
                "html": html, "attachments": attachments or [],
                "attempts": 0, "next_retry": time.time(),
                "created": time.time(),
            })

    def _process_loop(self):
        """Process the queue, retrying failed sends."""
        while True:
            time.sleep(10)
            now = time.time()
            with self._lock:
                pending = [m for m in self._queue if m["next_retry"] <= now]

            for msg in pending:
                success = self._send(msg)
                with self._lock:
                    if success:
                        try:
                            self._queue.remove(msg)
                        except ValueError:
                            pass
                    else:
                        msg["attempts"] += 1
                        if msg["attempts"] >= 3:
                            log.error("Email to %s failed after 3 attempts: %s",
                                     msg["to"], msg["subject"])
                            try:
                                self._queue.remove(msg)
                            except ValueError:
                                pass
                        else:
                            # Exponential backoff: 30s, 120s, 480s
                            msg["next_retry"] = now + 30 * (4 ** msg["attempts"])

    def _send(self, msg: dict) -> bool:
        """Attempt to send an email."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            smtp_server = self.cfg.get("email.smtp_server", "")
            if not smtp_server:
                return False

            if msg["html"]:
                m = MIMEMultipart("alternative")
                m.attach(MIMEText(msg["body"], "html", "utf-8"))
            else:
                m = MIMEText(msg["body"], "plain", "utf-8")

            m["Subject"] = msg["subject"]
            m["From"] = self.cfg.get("email.from_address", "sentinel@local")
            m["To"] = msg["to"]

            port = self.cfg.get("email.smtp_port", 587)
            if port == 465:
                srv = smtplib.SMTP_SSL(smtp_server, port, timeout=15)
            else:
                srv = smtplib.SMTP(smtp_server, port, timeout=15)
                if self.cfg.get("email.smtp_tls", True):
                    srv.starttls()

            user = self.cfg.get("email.smtp_user", "")
            if user:
                srv.login(user, self.cfg.get("email.smtp_password", ""))
            srv.send_message(m)
            srv.quit()
            return True

        except Exception as e:
            log.warning("Email send failed (attempt %d): %s",
                       msg["attempts"] + 1, e)
            return False

    @property
    def stats(self) -> dict:
        with self._lock:
            return {"pending": len(self._queue)}
