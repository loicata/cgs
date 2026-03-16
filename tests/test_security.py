"""Tests for core/security.py — encryption, anti-replay, rate limiting, CSRF, validation, log sanitization, tokens."""
import os
import sys
import time
import tempfile
import hashlib
import hmac
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.security import (
    SecretsVault,
    AntiReplay,
    RateLimiter,
    CSRFProtection,
    InputValidator,
    LogSanitizer,
    SanitizedFormatter,
    TokenManager,
    compute_agent_checksum,
    generate_agent_manifest,
    harden_permissions,
    drop_privileges,
)


# ══════════════════════════════════════════════════
# 1. SecretsVault
# ══════════════════════════════════════════════════

class TestSecretsVault:

    def test_encrypt_and_decrypt_round_trip(self, tmp_path):
        """Encrypting then decrypting a value returns the original plaintext."""
        salt_file = str(tmp_path / ".vault_salt")
        SecretsVault.SALT_FILE = salt_file
        vault = SecretsVault(passphrase="test-passphrase-123")
        if vault._fernet is None:
            pytest.skip("cryptography package not installed")
        encrypted = vault.encrypt("my-secret-password")
        assert encrypted.startswith("ENC:")
        assert vault.decrypt(encrypted) == "my-secret-password"

    def test_encrypt_empty_string_returns_empty(self, tmp_path):
        """Encrypting an empty string returns it unchanged."""
        salt_file = str(tmp_path / ".vault_salt")
        SecretsVault.SALT_FILE = salt_file
        vault = SecretsVault(passphrase="test")
        assert vault.encrypt("") == ""

    def test_decrypt_plain_text_returns_as_is(self, tmp_path):
        """Decrypting a non-encrypted value returns it unchanged."""
        salt_file = str(tmp_path / ".vault_salt")
        SecretsVault.SALT_FILE = salt_file
        vault = SecretsVault(passphrase="test")
        assert vault.decrypt("plain-value") == "plain-value"

    def test_decrypt_without_passphrase_returns_empty(self):
        """Decrypting without a passphrase returns empty string."""
        vault = SecretsVault()
        result = vault.decrypt("ENC:some-fake-encrypted-data")
        assert result == ""

    def test_is_encrypted_detects_prefix(self):
        """is_encrypted returns True for values with ENC: prefix."""
        vault = SecretsVault()
        assert vault.is_encrypted("ENC:abc123") is True
        assert vault.is_encrypted("plain-text") is False
        assert vault.is_encrypted("") is False
        assert vault.is_encrypted(None) is False

    def test_wrong_passphrase_fails_to_decrypt(self, tmp_path):
        """Decrypting with a different passphrase fails gracefully."""
        salt_file = str(tmp_path / ".vault_salt")
        SecretsVault.SALT_FILE = salt_file
        vault1 = SecretsVault(passphrase="correct-password")
        if vault1._fernet is None:
            pytest.skip("cryptography package not installed")
        encrypted = vault1.encrypt("secret-data")
        vault2 = SecretsVault(passphrase="wrong-password")
        result = vault2.decrypt(encrypted)
        assert result == ""

    def test_salt_is_persisted_and_reused(self, tmp_path):
        """Salt file is created on first use and reused on subsequent initializations."""
        salt_file = str(tmp_path / ".vault_salt")
        SecretsVault.SALT_FILE = salt_file
        vault1 = SecretsVault(passphrase="test")
        assert os.path.exists(salt_file)
        vault2 = SecretsVault(passphrase="test")
        if vault1._fernet and vault2._fernet:
            encrypted = vault1.encrypt("data")
            assert vault2.decrypt(encrypted) == "data"

    def test_sensitive_fields_list_is_not_empty(self):
        """SENSITIVE_FIELDS contains the expected config fields."""
        assert len(SecretsVault.SENSITIVE_FIELDS) > 0
        assert "email.smtp_password" in SecretsVault.SENSITIVE_FIELDS


# ══════════════════════════════════════════════════
# 2. AntiReplay
# ══════════════════════════════════════════════════

class TestAntiReplay:

    def test_valid_timestamp_is_accepted(self):
        """A current timestamp is accepted."""
        ar = AntiReplay(window_seconds=60)
        valid, reason = ar.check(str(int(time.time())))
        assert valid is True
        assert reason == "ok"

    def test_expired_timestamp_is_rejected(self):
        """A timestamp older than the window is rejected."""
        ar = AntiReplay(window_seconds=30)
        old_ts = str(int(time.time()) - 60)
        valid, reason = ar.check(old_ts)
        assert valid is False
        assert "too old" in reason

    def test_future_timestamp_is_rejected(self):
        """A timestamp too far in the future is rejected."""
        ar = AntiReplay(window_seconds=30)
        future_ts = str(int(time.time()) + 60)
        valid, reason = ar.check(future_ts)
        assert valid is False
        assert "too old" in reason

    def test_invalid_timestamp_is_rejected(self):
        """A non-numeric timestamp is rejected."""
        ar = AntiReplay(window_seconds=60)
        valid, reason = ar.check("not-a-number")
        assert valid is False
        assert "invalid" in reason

    def test_nonce_reuse_is_detected(self):
        """Reusing the same nonce is detected as replay."""
        ar = AntiReplay(window_seconds=60)
        ts = str(int(time.time()))
        valid1, _ = ar.check(ts, nonce="unique-nonce-1")
        assert valid1 is True
        valid2, reason = ar.check(ts, nonce="unique-nonce-1")
        assert valid2 is False
        assert "replay" in reason

    def test_different_nonces_are_accepted(self):
        """Different nonces are accepted."""
        ar = AntiReplay(window_seconds=60)
        ts = str(int(time.time()))
        valid1, _ = ar.check(ts, nonce="nonce-a")
        valid2, _ = ar.check(ts, nonce="nonce-b")
        assert valid1 is True
        assert valid2 is True

    def test_none_timestamp_is_rejected(self):
        """None as timestamp is rejected."""
        ar = AntiReplay(window_seconds=60)
        valid, reason = ar.check(None)
        assert valid is False


# ══════════════════════════════════════════════════
# 3. RateLimiter
# ══════════════════════════════════════════════════

class TestRateLimiter:

    def test_requests_within_limit_are_allowed(self):
        """Requests under the rate limit are allowed."""
        rl = RateLimiter()
        allowed, remaining = rl.check("10.0.0.1", limit=5, window=60)
        assert allowed is True
        assert remaining == 4

    def test_requests_exceeding_limit_are_blocked(self):
        """Requests exceeding the rate limit are blocked."""
        rl = RateLimiter()
        for _ in range(5):
            rl.check("10.0.0.2", limit=5, window=60)
        allowed, remaining = rl.check("10.0.0.2", limit=5, window=60)
        assert allowed is False
        assert remaining == 0

    def test_different_ips_have_separate_limits(self):
        """Rate limits are tracked per IP."""
        rl = RateLimiter()
        for _ in range(5):
            rl.check("10.0.0.3", limit=5, window=60)
        allowed, _ = rl.check("10.0.0.4", limit=5, window=60)
        assert allowed is True

    def test_expired_requests_are_not_counted(self):
        """Requests older than the window are not counted."""
        rl = RateLimiter()
        # Manually inject old timestamps
        with rl._lock:
            rl._windows["10.0.0.5"] = [time.time() - 120] * 10
        allowed, _ = rl.check("10.0.0.5", limit=5, window=60)
        assert allowed is True


# ══════════════════════════════════════════════════
# 4. CSRFProtection
# ══════════════════════════════════════════════════

class TestCSRFProtection:

    def test_generated_token_is_valid(self):
        """A generated CSRF token can be validated."""
        csrf = CSRFProtection(secret_key="test-secret")
        token = csrf.generate()
        assert csrf.validate(token) is True

    def test_token_is_consumed_after_validation(self):
        """A CSRF token cannot be reused after validation."""
        csrf = CSRFProtection(secret_key="test-secret")
        token = csrf.generate()
        assert csrf.validate(token) is True
        assert csrf.validate(token) is False

    def test_empty_token_is_rejected(self):
        """An empty token is rejected."""
        csrf = CSRFProtection()
        assert csrf.validate("") is False
        assert csrf.validate(None) is False

    def test_unknown_token_is_rejected(self):
        """A token that was never generated is rejected."""
        csrf = CSRFProtection()
        assert csrf.validate("fake-token-never-generated") is False

    def test_expired_token_is_rejected(self):
        """A token older than TTL is rejected."""
        csrf = CSRFProtection()
        csrf.token_ttl = 1  # 1 second
        token = csrf.generate()
        time.sleep(1.1)
        assert csrf.validate(token) is False

    def test_cleanup_removes_expired_tokens(self):
        """Cleanup removes expired tokens."""
        csrf = CSRFProtection()
        csrf.token_ttl = 0  # Expire immediately
        csrf.generate()
        csrf.generate()
        csrf.cleanup()
        assert len(csrf._tokens) == 0


# ══════════════════════════════════════════════════
# 5. InputValidator
# ══════════════════════════════════════════════════

class TestInputValidator:

    # IP validation
    def test_valid_ip_is_accepted(self):
        assert InputValidator.ip("192.168.1.1") is True

    def test_valid_ip_zero_is_accepted(self):
        assert InputValidator.ip("0.0.0.0") is True

    def test_valid_ip_broadcast_is_accepted(self):
        assert InputValidator.ip("255.255.255.255") is True

    def test_invalid_ip_octet_out_of_range(self):
        assert InputValidator.ip("256.1.1.1") is False

    def test_invalid_ip_format_letters(self):
        assert InputValidator.ip("abc.def.ghi.jkl") is False

    def test_invalid_ip_empty_string(self):
        assert InputValidator.ip("") is False

    def test_invalid_ip_too_many_octets(self):
        assert InputValidator.ip("1.2.3.4.5") is False

    # MAC validation
    def test_valid_mac_is_accepted(self):
        assert InputValidator.mac("aa:bb:cc:dd:ee:ff") is True

    def test_valid_mac_uppercase_is_accepted(self):
        assert InputValidator.mac("AA:BB:CC:DD:EE:FF") is True

    def test_invalid_mac_wrong_format(self):
        assert InputValidator.mac("aa-bb-cc-dd-ee-ff") is False

    def test_invalid_mac_too_short(self):
        assert InputValidator.mac("aa:bb:cc") is False

    # Incident ID validation
    def test_valid_incident_id_is_accepted(self):
        assert InputValidator.incident_id("INC-20240101-1") is True
        assert InputValidator.incident_id("INC-20241231-999") is True

    def test_invalid_incident_id_wrong_prefix(self):
        assert InputValidator.incident_id("ABC-20240101-1") is False

    def test_invalid_incident_id_empty(self):
        assert InputValidator.incident_id("") is False

    # Port validation
    def test_valid_port_is_accepted(self):
        assert InputValidator.port(80) is True
        assert InputValidator.port(443) is True
        assert InputValidator.port(1) is True
        assert InputValidator.port(65535) is True

    def test_invalid_port_zero(self):
        assert InputValidator.port(0) is False

    def test_invalid_port_too_high(self):
        assert InputValidator.port(65536) is False

    def test_invalid_port_negative(self):
        assert InputValidator.port(-1) is False

    def test_invalid_port_string(self):
        assert InputValidator.port("not-a-port") is False

    # safe_string
    def test_safe_string_strips_and_truncates(self):
        result = InputValidator.safe_string("  hello  ", max_length=5)
        assert result == "hello"

    def test_safe_string_removes_control_chars(self):
        result = InputValidator.safe_string("hello\x00world\x7f")
        assert result == "helloworld"

    def test_safe_string_preserves_newlines_and_tabs(self):
        result = InputValidator.safe_string("hello\nworld\ttab")
        assert result == "hello\nworld\ttab"

    def test_safe_string_non_string_returns_empty(self):
        assert InputValidator.safe_string(None) == ""
        assert InputValidator.safe_string(123) == ""

    # safe_path
    def test_safe_path_normal_path_is_accepted(self):
        assert InputValidator.safe_path("/opt/cgs/data/file.json") is True

    def test_safe_path_rejects_directory_traversal(self):
        assert InputValidator.safe_path("../../etc/passwd") is False

    def test_safe_path_rejects_tilde(self):
        assert InputValidator.safe_path("~/secret") is False

    def test_safe_path_rejects_pipe(self):
        assert InputValidator.safe_path("file | rm -rf /") is False

    def test_safe_path_rejects_semicolon(self):
        assert InputValidator.safe_path("file; rm -rf /") is False

    def test_safe_path_rejects_empty(self):
        assert InputValidator.safe_path("") is False


# ══════════════════════════════════════════════════
# 6. LogSanitizer
# ══════════════════════════════════════════════════

class TestLogSanitizer:

    def test_redact_email_addresses(self):
        """Email addresses are redacted from log messages."""
        msg = "User admin@company.com logged in"
        result = LogSanitizer.redact(msg)
        assert "admin@company.com" not in result
        assert "[email-redacted]" in result

    def test_redact_multiple_emails(self):
        """Multiple email addresses are all redacted."""
        msg = "From user@a.com to admin@b.org"
        result = LogSanitizer.redact(msg)
        assert "user@a.com" not in result
        assert "admin@b.org" not in result

    def test_redact_password_patterns(self):
        """Password-like patterns are redacted."""
        msg = "password=my-secret-pass"
        result = LogSanitizer.redact(msg)
        assert "my-secret-pass" not in result
        assert "REDACTED" in result

    def test_redact_api_key_patterns(self):
        """API key patterns are redacted."""
        msg = "api_key: abc123def456"
        result = LogSanitizer.redact(msg)
        assert "abc123def456" not in result

    def test_normal_message_unchanged(self):
        """Messages without sensitive data are not modified."""
        msg = "System started on port 8443"
        result = LogSanitizer.redact(msg)
        assert result == msg


class TestSanitizedFormatter:

    def test_formatter_redacts_sensitive_data(self):
        """SanitizedFormatter redacts sensitive data in log records."""
        import logging
        formatter = SanitizedFormatter("%(message)s")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Login from user@example.com", args=(), exc_info=None,
        )
        result = formatter.format(record)
        assert "user@example.com" not in result
        assert "[email-redacted]" in result


# ══════════════════════════════════════════════════
# 7. TokenManager
# ══════════════════════════════════════════════════

class TestTokenManager:

    def test_create_and_validate_token(self):
        """Created token is valid within TTL."""
        tm = TokenManager(ttl_seconds=60)
        token = tm.create("INC-20240101-1")
        data = tm.validate(token)
        assert data is not None
        assert data["incident_id"] == "INC-20240101-1"

    def test_validate_preserves_token(self):
        """Validate does not consume the token."""
        tm = TokenManager(ttl_seconds=60)
        token = tm.create("INC-20240101-1")
        assert tm.validate(token) is not None
        assert tm.validate(token) is not None

    def test_consume_removes_token(self):
        """Consume validates and removes the token."""
        tm = TokenManager(ttl_seconds=60)
        token = tm.create("INC-20240101-1")
        data = tm.consume(token)
        assert data is not None
        assert data["incident_id"] == "INC-20240101-1"
        assert tm.consume(token) is None

    def test_expired_token_is_rejected(self):
        """Expired tokens return None."""
        tm = TokenManager(ttl_seconds=1)
        token = tm.create("INC-20240101-1")
        time.sleep(1.1)
        assert tm.validate(token) is None

    def test_invalid_token_returns_none(self):
        """Unknown tokens return None."""
        tm = TokenManager()
        assert tm.validate("nonexistent-token") is None

    def test_extra_data_is_stored(self):
        """Extra data passed to create is stored and returned."""
        tm = TokenManager()
        token = tm.create("INC-1", extra={"action": "approve", "ip": "10.0.0.1"})
        data = tm.validate(token)
        assert data["action"] == "approve"
        assert data["ip"] == "10.0.0.1"

    def test_cleanup_removes_expired_tokens(self):
        """Cleanup purges expired tokens."""
        tm = TokenManager(ttl_seconds=0)
        tm.create("INC-1")
        tm.create("INC-2")
        time.sleep(0.1)
        tm.cleanup()
        assert len(tm._tokens) == 0


# ══════════════════════════════════════════════════
# 8. Agent integrity checksum
# ══════════════════════════════════════════════════

class TestAgentChecksum:

    def test_compute_agent_checksum_returns_sha256(self, tmp_path):
        """compute_agent_checksum returns a valid SHA-256 hex digest."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("print('hello')")
        result = compute_agent_checksum(str(agent_file))
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_checksum_changes_when_file_changes(self, tmp_path):
        """Checksum changes when the file content is modified."""
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("version 1")
        cs1 = compute_agent_checksum(str(agent_file))
        agent_file.write_text("version 2")
        cs2 = compute_agent_checksum(str(agent_file))
        assert cs1 != cs2

    def test_generate_agent_manifest_contains_expected_fields(self, tmp_path):
        """Manifest contains sha256, signature, filename, and verify_command."""
        agent_file = tmp_path / "cgs-agent.py"
        agent_file.write_text("agent code")
        manifest = generate_agent_manifest(str(agent_file), "my-secret")
        assert "sha256" in manifest
        assert "signature" in manifest
        assert "filename" in manifest
        assert manifest["filename"] == "cgs-agent.py"
        assert "generated_at" in manifest
        assert "verify_command" in manifest

    def test_manifest_signature_is_valid_hmac(self, tmp_path):
        """Manifest signature is a valid HMAC-SHA256 of the checksum."""
        agent_file = tmp_path / "cgs-agent.py"
        agent_file.write_text("agent code")
        secret = "test-secret"
        manifest = generate_agent_manifest(str(agent_file), secret)
        expected_sig = hmac.new(
            secret.encode(), manifest["sha256"].encode(), hashlib.sha256
        ).hexdigest()
        assert manifest["signature"] == expected_sig


# ══════════════════════════════════════════════════
# Integration tests
# ══════════════════════════════════════════════════

class TestSecurityIntegration:

    def test_vault_encrypt_decrypt_multiple_values(self, tmp_path):
        """Multiple values can be encrypted and decrypted independently."""
        salt_file = str(tmp_path / ".vault_salt")
        SecretsVault.SALT_FILE = salt_file
        vault = SecretsVault(passphrase="integration-test")
        if vault._fernet is None:
            pytest.skip("cryptography package not installed")
        values = ["password1", "api-key-abc", "webhook-url-secret"]
        encrypted = [vault.encrypt(v) for v in values]
        # All encrypted values are different
        assert len(set(encrypted)) == 3
        # All decrypt back correctly
        decrypted = [vault.decrypt(e) for e in encrypted]
        assert decrypted == values

    def test_rate_limiter_thread_safety(self):
        """RateLimiter handles concurrent requests correctly."""
        rl = RateLimiter()
        results = []

        def make_requests():
            for _ in range(10):
                allowed, _ = rl.check("10.0.0.99", limit=50, window=60)
                results.append(allowed)

        threads = [threading.Thread(target=make_requests) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 50 should be allowed, rest blocked
        allowed_count = sum(1 for r in results if r)
        assert allowed_count == 50

    def test_csrf_token_thread_safety(self):
        """CSRFProtection handles concurrent token generation and validation."""
        csrf = CSRFProtection()
        tokens = []

        def generate_tokens():
            for _ in range(10):
                tokens.append(csrf.generate())

        threads = [threading.Thread(target=generate_tokens) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 50 tokens should be unique
        assert len(set(tokens)) == 50
        # All should be valid
        for token in tokens:
            assert csrf.validate(token) is True

    def test_anti_replay_with_concurrent_nonces(self):
        """AntiReplay correctly detects replays under concurrent access."""
        ar = AntiReplay(window_seconds=60)
        ts = str(int(time.time()))
        results = []

        def check_nonce(nonce):
            valid, _ = ar.check(ts, nonce=nonce)
            results.append(valid)

        # 10 threads all try the same nonce
        threads = [threading.Thread(target=check_nonce, args=("same-nonce",)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly one should succeed
        assert sum(1 for r in results if r) == 1


# ══════════════════════════════════════════════════
# 9. SecretsVault salt fallback paths
# ══════════════════════════════════════════════════

class TestSecretsVaultSaltFallback:

    def test_salt_fallback_to_machine_id_on_oserror(self, monkeypatch):
        """When salt file cannot be written (OSError), fall back to /etc/machine-id."""
        import builtins

        vault = SecretsVault.__new__(SecretsVault)
        vault._fernet = None
        vault.SALT_FILE = "/nonexistent/readonly/dir/.vault_salt"

        fake_machine_id = b"fake-machine-id-1234"
        original_open = builtins.open

        def patched_open(path, *args, **kwargs):
            if str(path) == "/etc/machine-id":
                import io
                return io.BytesIO(fake_machine_id)
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", patched_open)

        salt = vault._get_or_create_salt()
        assert salt == fake_machine_id

    def test_salt_fallback_to_cgs_v2_when_no_machine_id(self, monkeypatch):
        """When both salt file and /etc/machine-id are unavailable, fall back to b'cgs-v2'."""
        vault = SecretsVault.__new__(SecretsVault)
        vault._fernet = None
        vault.SALT_FILE = "/nonexistent/readonly/dir/.vault_salt"

        # Also make /etc/machine-id unreadable
        import builtins
        original_open = builtins.open

        def no_machine_id_open(path, *args, **kwargs):
            if str(path) == "/etc/machine-id":
                raise FileNotFoundError("No machine-id")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", no_machine_id_open)
        salt = vault._get_or_create_salt()
        assert salt == b"cgs-v2"


# ══════════════════════════════════════════════════
# 10. _init_fernet ImportError path
# ══════════════════════════════════════════════════

class TestInitFernetImportError:

    def test_fernet_none_when_cryptography_not_installed(self, monkeypatch):
        """_init_fernet sets _fernet to None when cryptography is missing."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "cryptography.fernet" or name == "cryptography":
                raise ImportError("No module named 'cryptography'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        vault = SecretsVault.__new__(SecretsVault)
        vault._fernet = "placeholder"
        vault.SALT_FILE = "/tmp/test_salt_fernet"
        vault._init_fernet("some-passphrase")
        assert vault._fernet is None


# ══════════════════════════════════════════════════
# 11. AntiReplay cleanup logic
# ══════════════════════════════════════════════════

class _BreakLoop(Exception):
    """Sentinel exception to break out of infinite cleanup loops in tests."""
    pass


class TestAntiReplayCleanup:

    def test_cleanup_loop_removes_old_nonces(self, monkeypatch):
        """_cleanup_loop removes old nonces beyond 2x window."""
        ar = AntiReplay(window_seconds=60)
        now = time.time()
        with ar._lock:
            ar._nonces["old-nonce"] = now - 200  # Beyond 2*60=120
            ar._nonces["recent-nonce"] = now - 10

        call_count = [0]
        def fake_sleep(seconds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise _BreakLoop()

        monkeypatch.setattr(time, "sleep", fake_sleep)
        with pytest.raises(_BreakLoop):
            ar._cleanup_loop()

        assert "old-nonce" not in ar._nonces
        assert "recent-nonce" in ar._nonces

    def test_cleanup_loop_hard_limit_truncation(self, monkeypatch):
        """_cleanup_loop truncates nonces when exceeding max_nonces."""
        ar = AntiReplay(window_seconds=60, max_nonces=5)
        now = time.time()

        with ar._lock:
            for i in range(10):
                ar._nonces[f"nonce-{i}"] = now - (10 - i)

        call_count = [0]
        def fake_sleep(seconds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise _BreakLoop()

        monkeypatch.setattr(time, "sleep", fake_sleep)
        with pytest.raises(_BreakLoop):
            ar._cleanup_loop()

        assert len(ar._nonces) == 5
        for i in range(5, 10):
            assert f"nonce-{i}" in ar._nonces
        for i in range(5):
            assert f"nonce-{i}" not in ar._nonces


# ══════════════════════════════════════════════════
# 12. RateLimiter cleanup logic
# ══════════════════════════════════════════════════

class TestRateLimiterCleanup:

    def test_cleanup_loop_purges_expired_windows(self, monkeypatch):
        """_cleanup_loop purges expired IP windows."""
        rl = RateLimiter()
        now = time.time()

        with rl._lock:
            rl._windows["10.0.0.1"] = [now - 200, now - 180]  # All expired
            rl._windows["10.0.0.2"] = [now - 10, now - 5]  # Recent

        call_count = [0]
        def fake_sleep(seconds):
            call_count[0] += 1
            if call_count[0] > 1:
                raise _BreakLoop()

        monkeypatch.setattr(time, "sleep", fake_sleep)
        with pytest.raises(_BreakLoop):
            rl._cleanup_loop()

        assert "10.0.0.1" not in rl._windows
        assert "10.0.0.2" in rl._windows
        assert len(rl._windows["10.0.0.2"]) == 2


# ══════════════════════════════════════════════════
# 13. TokenManager.consume expired token
# ══════════════════════════════════════════════════

class TestTokenManagerConsumeExpired:

    def test_consume_expired_token_returns_none(self):
        """Consuming an expired token returns None (line 395)."""
        tm = TokenManager(ttl_seconds=0)
        token = tm.create("INC-20240101-1")
        time.sleep(0.05)
        result = tm.consume(token)
        assert result is None


# ══════════════════════════════════════════════════
# 14. harden_permissions function
# ══════════════════════════════════════════════════

class TestHardenPermissions:

    def test_harden_permissions_calls_chmod(self, monkeypatch):
        """harden_permissions calls os.chmod on existing paths."""
        from core.security import harden_permissions

        chmod_calls = {}

        def mock_exists(path):
            return True

        def mock_chmod(path, mode):
            chmod_calls[path] = mode

        monkeypatch.setattr(os.path, "exists", mock_exists)
        monkeypatch.setattr(os, "chmod", mock_chmod)

        harden_permissions()

        assert "/etc/cgs" in chmod_calls
        assert chmod_calls["/etc/cgs"] == 0o750
        assert "/etc/cgs/config.yaml" in chmod_calls
        assert chmod_calls["/etc/cgs/config.yaml"] == 0o640
        assert "/var/log/cgs/snapshots" in chmod_calls
        assert chmod_calls["/var/log/cgs/snapshots"] == 0o700

    def test_harden_permissions_handles_oserror(self, monkeypatch):
        """harden_permissions silently handles OSError on chmod."""
        from core.security import harden_permissions

        def mock_exists(path):
            return True

        def mock_chmod(path, mode):
            raise OSError("Permission denied")

        monkeypatch.setattr(os.path, "exists", mock_exists)
        monkeypatch.setattr(os, "chmod", mock_chmod)

        # Should not raise
        harden_permissions()

    def test_harden_permissions_skips_nonexistent_paths(self, monkeypatch):
        """harden_permissions skips paths that do not exist."""
        from core.security import harden_permissions

        chmod_calls = []

        def mock_exists(path):
            return False

        def mock_chmod(path, mode):
            chmod_calls.append(path)

        monkeypatch.setattr(os.path, "exists", mock_exists)
        monkeypatch.setattr(os, "chmod", mock_chmod)

        harden_permissions()
        assert len(chmod_calls) == 0


# ══════════════════════════════════════════════════
# 15. drop_privileges function
# ══════════════════════════════════════════════════

class TestDropPrivileges:

    def test_drop_privileges_non_root_returns_immediately(self, monkeypatch):
        """drop_privileges returns immediately when not root (uid != 0)."""
        from core.security import drop_privileges

        monkeypatch.setattr(os, "getuid", lambda: 1000)

        # Should return without doing anything
        drop_privileges()

    def test_drop_privileges_root_calls_setuid_setgid(self, monkeypatch):
        """drop_privileges calls setgid then setuid when running as root."""
        from core.security import drop_privileges
        import pwd

        class FakePwEntry:
            pw_uid = 1001
            pw_gid = 1001

        monkeypatch.setattr(os, "getuid", lambda: 0)
        monkeypatch.setattr(pwd, "getpwnam", lambda name: FakePwEntry())

        calls = []
        monkeypatch.setattr(os, "setgroups", lambda groups: calls.append(("setgroups", groups)))
        monkeypatch.setattr(os, "setgid", lambda gid: calls.append(("setgid", gid)))
        monkeypatch.setattr(os, "setuid", lambda uid: calls.append(("setuid", uid)))

        drop_privileges("cgs")

        assert ("setgroups", []) in calls
        assert ("setgid", 1001) in calls
        assert ("setuid", 1001) in calls
        # setgid must come before setuid
        gid_idx = next(i for i, c in enumerate(calls) if c[0] == "setgid")
        uid_idx = next(i for i, c in enumerate(calls) if c[0] == "setuid")
        assert gid_idx < uid_idx

    def test_drop_privileges_user_not_found(self, monkeypatch):
        """drop_privileges handles KeyError when user doesn't exist."""
        from core.security import drop_privileges
        import pwd

        monkeypatch.setattr(os, "getuid", lambda: 0)
        monkeypatch.setattr(pwd, "getpwnam", lambda name: (_ for _ in ()).throw(KeyError(name)))

        # Should not raise
        drop_privileges("nonexistent-user")

    def test_drop_privileges_oserror_on_setuid(self, monkeypatch):
        """drop_privileges handles OSError during privilege drop."""
        from core.security import drop_privileges
        import pwd

        class FakePwEntry:
            pw_uid = 1001
            pw_gid = 1001

        monkeypatch.setattr(os, "getuid", lambda: 0)
        monkeypatch.setattr(pwd, "getpwnam", lambda name: FakePwEntry())
        monkeypatch.setattr(os, "setgroups", lambda groups: None)
        monkeypatch.setattr(os, "setgid", lambda gid: (_ for _ in ()).throw(OSError("Operation not permitted")))

        # Should not raise
        drop_privileges("cgs")
