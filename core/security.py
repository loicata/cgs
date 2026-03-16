"""
CGS — Security hardening module.

Provides:
  1. Secrets encryption (Fernet AES-128-CBC) for config.yaml
  2. Anti-replay protection (timestamp window + nonce cache)
  3. API rate limiting (per-IP sliding window)
  4. CSRF token generation/validation
  5. Input validation helpers
  6. Log sanitization (redact emails, IPs on demand)
  7. Token expiration for approval/rejection links
  8. Agent integrity checksum
"""

import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("cgs.security")

# ══════════════════════════════════════════════════
# 1. Secrets encryption
# ══════════════════════════════════════════════════

class SecretsVault:
    """
    Encrypts/decrypts sensitive config values using Fernet (AES-128-CBC).
    Master key is derived from a passphrase via PBKDF2.
    Encrypted values are stored as "ENC:base64..." in config.yaml.
    """

    PREFIX = "ENC:"

    SALT_FILE = "/etc/cgs/.vault_salt"

    def __init__(self, passphrase: str = ""):
        self._fernet = None
        if passphrase:
            self._init_fernet(passphrase)

    def _get_or_create_salt(self) -> bytes:
        """Get per-installation random salt, or create one if missing."""
        try:
            if os.path.exists(self.SALT_FILE):
                with open(self.SALT_FILE, "rb") as f:
                    salt = f.read()
                if len(salt) >= 16:
                    return salt
            # Generate new random salt
            salt = os.urandom(32)
            os.makedirs(os.path.dirname(self.SALT_FILE), exist_ok=True)
            with open(self.SALT_FILE, "wb") as f:
                f.write(salt)
            os.chmod(self.SALT_FILE, 0o600)
            return salt
        except (OSError, PermissionError):
            # Fallback for non-root or missing dir: use machine-id based salt
            machine_salt = b"cgs-v2"
            try:
                with open("/etc/machine-id", "rb") as f:
                    machine_salt = f.read().strip()
            except (OSError, FileNotFoundError):
                pass
            return machine_salt

    def _init_fernet(self, passphrase: str):
        try:
            from cryptography.fernet import Fernet
            # Derive key from passphrase via PBKDF2 with per-installation salt
            salt = self._get_or_create_salt()
            key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100_000)
            fernet_key = base64.urlsafe_b64encode(key[:32])
            self._fernet = Fernet(fernet_key)
            logger.info("Secrets vault initialized (Fernet AES-128-CBC)")
        except ImportError:
            logger.warning("cryptography package not installed — secrets stored in plain text. "
                          "Install with: pip install cryptography")
            self._fernet = None

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a value. Returns 'ENC:base64...' string."""
        if not self._fernet or not plaintext:
            return plaintext
        token = self._fernet.encrypt(plaintext.encode())
        return self.PREFIX + base64.urlsafe_b64encode(token).decode()

    def decrypt(self, value: str) -> str:
        """Decrypt a value if it starts with 'ENC:'. Otherwise return as-is."""
        if not value or not value.startswith(self.PREFIX):
            return value
        if not self._fernet:
            logger.error("Cannot decrypt — no passphrase provided")
            return ""
        try:
            token = base64.urlsafe_b64decode(value[len(self.PREFIX):])
            return self._fernet.decrypt(token).decode()
        except Exception as e:
            logger.error("Decryption failed: %s", e)
            return ""

    def is_encrypted(self, value: str) -> bool:
        return isinstance(value, str) and value.startswith(self.PREFIX)

    # Fields that should be encrypted in config.yaml
    SENSITIVE_FIELDS = [
        "email.smtp_password",
        "client_agent.shared_secret",
        "web.password",
        "recon.abuseipdb_key",
        "recon.virustotal_key",
        "netgate.api_key",
        "netgate.api_secret",
    ]


# ══════════════════════════════════════════════════
# 2. Anti-replay protection
# ══════════════════════════════════════════════════

class AntiReplay:
    """
    Prevents replay attacks on HMAC-authenticated requests.
    - Rejects timestamps outside ±60s window
    - Caches nonces to prevent reuse
    """

    def __init__(self, window_seconds: int = 60, max_nonces: int = 10000):
        self.window = window_seconds
        self.max_nonces = max_nonces
        self._nonces: dict[str, float] = {}  # nonce → timestamp
        self._lock = threading.Lock()

        # Cleanup thread
        threading.Thread(target=self._cleanup_loop, daemon=True,
                        name="anti-replay-gc").start()

    def check(self, timestamp: str, nonce: str = "") -> tuple[bool, str]:
        """
        Validate a request's timestamp and optional nonce.
        Returns (valid, reason).
        """
        # Validate timestamp
        try:
            ts = int(timestamp)
        except (ValueError, TypeError):
            return False, "invalid timestamp"

        now = int(time.time())
        drift = abs(now - ts)
        if drift > self.window:
            return False, f"timestamp too old ({drift}s drift, max {self.window}s)"

        # Validate nonce (if provided)
        if nonce:
            with self._lock:
                if nonce in self._nonces:
                    return False, "nonce already used (replay detected)"
                self._nonces[nonce] = time.time()

        return True, "ok"

    def _cleanup_loop(self):
        while True:
            time.sleep(30)
            cutoff = time.time() - self.window * 2
            with self._lock:
                self._nonces = {k: v for k, v in self._nonces.items() if v > cutoff}
                # Hard limit
                if len(self._nonces) > self.max_nonces:
                    sorted_nonces = sorted(self._nonces.items(), key=lambda x: x[1])
                    self._nonces = dict(sorted_nonces[-self.max_nonces:])


# ══════════════════════════════════════════════════
# 3. API rate limiting
# ══════════════════════════════════════════════════

class RateLimiter:
    """
    Per-IP sliding window rate limiter.
    Default: 60 requests/minute for API, 10/minute for auth endpoints.
    """

    def __init__(self):
        self._windows: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

        # Cleanup thread
        threading.Thread(target=self._cleanup_loop, daemon=True,
                        name="rate-limiter-gc").start()

    def check(self, ip: str, limit: int = 60, window: int = 60) -> tuple[bool, int]:
        """
        Check if IP is within rate limit.
        Returns (allowed, remaining_requests).
        """
        now = time.time()
        cutoff = now - window

        with self._lock:
            # Remove expired entries
            self._windows[ip] = [t for t in self._windows[ip] if t > cutoff]
            count = len(self._windows[ip])

            if count >= limit:
                return False, 0

            self._windows[ip].append(now)
            return True, limit - count - 1

    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            cutoff = time.time() - 120
            with self._lock:
                for ip in list(self._windows.keys()):
                    self._windows[ip] = [t for t in self._windows[ip] if t > cutoff]
                    if not self._windows[ip]:
                        del self._windows[ip]


# ══════════════════════════════════════════════════
# 4. CSRF protection
# ══════════════════════════════════════════════════

class CSRFProtection:
    """Generates and validates CSRF tokens for web forms."""

    def __init__(self, secret_key: str = ""):
        self._secret = secret_key or secrets.token_hex(32)
        self._tokens: dict[str, float] = {}  # token → creation time
        self._lock = threading.Lock()
        self.token_ttl = 3600  # 1 hour

    def generate(self, session_id: str = "") -> str:
        """Generate a CSRF token."""
        token = secrets.token_hex(32)
        with self._lock:
            self._tokens[token] = time.time()
        return token

    def validate(self, token: str) -> bool:
        """Validate and consume a CSRF token."""
        if not token:
            return False
        with self._lock:
            created = self._tokens.pop(token, None)
        if created is None:
            return False
        if time.time() - created > self.token_ttl:
            return False
        return True

    def cleanup(self):
        cutoff = time.time() - self.token_ttl
        with self._lock:
            self._tokens = {k: v for k, v in self._tokens.items() if v > cutoff}


# ══════════════════════════════════════════════════
# 5. Input validation
# ══════════════════════════════════════════════════

class InputValidator:
    """Validates and sanitizes API inputs."""

    IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
    INCIDENT_RE = re.compile(r'^INC-\d{8}-\d+$')

    @staticmethod
    def ip(value: str) -> bool:
        if not InputValidator.IP_RE.match(value):
            return False
        return all(0 <= int(p) <= 255 for p in value.split("."))

    @staticmethod
    def mac(value: str) -> bool:
        return bool(InputValidator.MAC_RE.match(value))

    @staticmethod
    def incident_id(value: str) -> bool:
        return bool(InputValidator.INCIDENT_RE.match(value))

    @staticmethod
    def port(value) -> bool:
        try:
            return 1 <= int(value) <= 65535
        except (ValueError, TypeError):
            return False

    @staticmethod
    def safe_string(value: str, max_length: int = 500) -> str:
        """Sanitize a string: strip, truncate, remove control chars."""
        if not isinstance(value, str):
            return ""
        value = value.strip()[:max_length]
        # Remove control characters except newline/tab
        return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    @staticmethod
    def safe_path(value: str) -> bool:
        """Check path doesn't escape expected directories."""
        if not value:
            return False
        dangerous = ["..", "~", "$", "`", "|", ";", "&", ">", "<"]
        return not any(d in value for d in dangerous)


# ══════════════════════════════════════════════════
# 6. Log sanitization
# ══════════════════════════════════════════════════

class LogSanitizer:
    """Redacts sensitive data in log messages."""

    EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    # Match passwords in common formats
    SECRET_PATTERNS = [
        (re.compile(r'(password|secret|token|key|api_key)[\s=:]+\S+', re.I),
         r'\1=***REDACTED***'),
    ]

    @staticmethod
    def redact(message: str) -> str:
        """Redact emails and secrets from a log message."""
        # Redact emails
        message = LogSanitizer.EMAIL_RE.sub('[email-redacted]', message)
        # Redact secret patterns
        for pattern, replacement in LogSanitizer.SECRET_PATTERNS:
            message = pattern.sub(replacement, message)
        return message


class SanitizedFormatter(logging.Formatter):
    """Logging formatter that auto-redacts sensitive data."""

    def format(self, record):
        original = super().format(record)
        return LogSanitizer.redact(original)


# ══════════════════════════════════════════════════
# 7. Token expiration
# ══════════════════════════════════════════════════

class TokenManager:
    """Manages time-limited tokens for approval/rejection links."""

    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = ttl_seconds
        self._tokens: dict[str, dict] = {}  # token → {created, incident_id, ...}
        self._lock = threading.Lock()

    def create(self, incident_id: str, extra: dict = None) -> str:
        """Create a time-limited token."""
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[token] = {
                "created": time.time(),
                "incident_id": incident_id,
                **(extra or {}),
            }
        return token

    def validate(self, token: str) -> dict | None:
        """Validate token. Returns data if valid, None if expired/invalid."""
        with self._lock:
            data = self._tokens.get(token)
        if not data:
            return None
        if time.time() - data["created"] > self.ttl:
            # Expired — remove it
            with self._lock:
                self._tokens.pop(token, None)
            return None
        return data

    def consume(self, token: str) -> dict | None:
        """Validate and consume (single-use) a token."""
        with self._lock:
            data = self._tokens.pop(token, None)
        if not data:
            return None
        if time.time() - data["created"] > self.ttl:
            return None
        return data

    def cleanup(self):
        cutoff = time.time() - self.ttl
        with self._lock:
            self._tokens = {k: v for k, v in self._tokens.items()
                           if v["created"] > cutoff}


# ══════════════════════════════════════════════════
# 8. Agent integrity checksum
# ══════════════════════════════════════════════════

def compute_agent_checksum(agent_path: str) -> str:
    """Compute SHA-256 checksum of the agent script."""
    with open(agent_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def generate_agent_manifest(agent_path: str, secret: str) -> dict:
    """
    Generate a signed manifest for the agent script.
    Admin can verify agent integrity on workstations.
    """
    checksum = compute_agent_checksum(agent_path)
    sig = _hmac.new(secret.encode(), checksum.encode(), hashlib.sha256).hexdigest()
    return {
        "filename": os.path.basename(agent_path),
        "sha256": checksum,
        "signature": sig,
        "generated_at": datetime.now().isoformat(),
        "verify_command": f'echo "{checksum}  cgs-agent.py" | sha256sum -c -',
    }


# ══════════════════════════════════════════════════
# 9. Secure file permissions
# ══════════════════════════════════════════════════

def harden_permissions():
    """Set restrictive permissions on sensitive files and directories."""
    paths = {
        "/etc/cgs": 0o750,
        "/etc/cgs/config.yaml": 0o640,
        "/var/lib/cgs/data": 0o750,
        "/var/log/cgs": 0o750,
        "/var/log/cgs/snapshots": 0o700,
        "/var/log/cgs/forensics": 0o700,
    }
    for path, mode in paths.items():
        try:
            if os.path.exists(path):
                os.chmod(path, mode)
        except OSError:
            pass


# ══════════════════════════════════════════════════
# 10. Privilege dropping
# ══════════════════════════════════════════════════

def drop_privileges(uid_name: str = "cgs"):
    """
    Drop root privileges after binding raw sockets.
    The capture socket is opened as root, then we drop to a service user.
    """
    if os.getuid() != 0:
        return  # Already non-root

    try:
        import pwd
        pw = pwd.getpwnam(uid_name)
        # Set supplementary groups
        os.setgroups([])
        # Set GID then UID (order matters)
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)
        logger.info("Dropped privileges to user '%s' (uid=%d, gid=%d)",
                    uid_name, pw.pw_uid, pw.pw_gid)
    except KeyError:
        logger.warning("User '%s' not found — running as root (not recommended)", uid_name)
    except OSError as e:
        logger.warning("Cannot drop privileges: %s", e)
