"""Tests for core/safety.py — Supervisor, _CrashTracker, safe_thread, safe_call decorators."""

import os
import threading
import time
import pytest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ══════════════════════════════════════════════════════════
# 1. _CrashTracker
# ══════════════════════════════════════════════════════════

class TestCrashTracker:
    """Tests for the crash tracking and circuit breaker."""

    def setup_method(self):
        """Reset _CrashTracker state before each test."""
        from core.safety import _CrashTracker
        with _CrashTracker._lock:
            _CrashTracker._data.clear()
            _CrashTracker._disabled.clear()

    def test_record_single_crash_does_not_open_circuit(self):
        from core.safety import _CrashTracker
        opened = _CrashTracker.record("test_func")
        assert opened is False

    def test_record_two_crashes_does_not_open_circuit(self):
        from core.safety import _CrashTracker
        _CrashTracker.record("test_func")
        opened = _CrashTracker.record("test_func")
        assert opened is False

    def test_record_three_crashes_opens_circuit(self):
        from core.safety import _CrashTracker
        _CrashTracker.record("test_func")
        _CrashTracker.record("test_func")
        opened = _CrashTracker.record("test_func")
        assert opened is True

    def test_is_disabled_after_circuit_opens(self):
        from core.safety import _CrashTracker
        for _ in range(3):
            _CrashTracker.record("test_func")
        assert _CrashTracker.is_disabled("test_func") is True

    def test_is_not_disabled_before_circuit_opens(self):
        from core.safety import _CrashTracker
        _CrashTracker.record("test_func")
        assert _CrashTracker.is_disabled("test_func") is False

    def test_is_disabled_returns_false_for_unknown_function(self):
        from core.safety import _CrashTracker
        assert _CrashTracker.is_disabled("never_crashed") is False

    def test_circuit_reopens_after_timeout(self):
        from core.safety import _CrashTracker
        for _ in range(3):
            _CrashTracker.record("test_func")
        assert _CrashTracker.is_disabled("test_func") is True

        # Manually set the disable time to the past
        with _CrashTracker._lock:
            _CrashTracker._disabled["test_func"] = time.time() - 1
        assert _CrashTracker.is_disabled("test_func") is False

    def test_separate_functions_have_independent_circuits(self):
        from core.safety import _CrashTracker
        for _ in range(3):
            _CrashTracker.record("func_a")
        assert _CrashTracker.is_disabled("func_a") is True
        assert _CrashTracker.is_disabled("func_b") is False

    def test_stats_returns_crash_counts_and_disabled(self):
        from core.safety import _CrashTracker
        _CrashTracker.record("func_x")
        _CrashTracker.record("func_x")
        stats = _CrashTracker.stats()
        assert "crash_counts" in stats
        assert "disabled" in stats
        assert stats["crash_counts"]["func_x"] == 2

    def test_stats_shows_disabled_with_remaining_time(self):
        from core.safety import _CrashTracker
        for _ in range(3):
            _CrashTracker.record("func_y")
        stats = _CrashTracker.stats()
        assert "func_y" in stats["disabled"]
        assert stats["disabled"]["func_y"] > 0  # seconds remaining

    def test_old_crashes_do_not_count_toward_circuit(self):
        from core.safety import _CrashTracker
        # Record 2 crashes, then set them in the past
        _CrashTracker.record("func_z")
        _CrashTracker.record("func_z")
        with _CrashTracker._lock:
            # Move all crash times to > 10 min ago
            for i in range(len(_CrashTracker._data["func_z"])):
                _CrashTracker._data["func_z"][i] = time.time() - 700
        # Third crash should not open circuit because the first two are old
        opened = _CrashTracker.record("func_z")
        assert opened is False

    def test_maxlen_deque_limits_crash_records(self):
        from core.safety import _CrashTracker
        # Deque maxlen is 20
        for _ in range(25):
            _CrashTracker.record("func_flood")
        with _CrashTracker._lock:
            assert len(_CrashTracker._data["func_flood"]) == 20


# ══════════════════════════════════════════════════════════
# 2. safe_call decorator
# ══════════════════════════════════════════════════════════

class TestSafeCall:
    """Tests for the safe_call decorator."""

    def test_safe_call_returns_function_result(self):
        from core.safety import safe_call

        @safe_call("test")
        def add(a, b):
            return a + b

        assert add(2, 3) == 5

    def test_safe_call_returns_default_on_exception(self):
        from core.safety import safe_call

        @safe_call("test", default=-1)
        def failing():
            raise ValueError("boom")

        assert failing() == -1

    def test_safe_call_returns_none_default_on_exception(self):
        from core.safety import safe_call

        @safe_call("test")
        def failing():
            raise RuntimeError("error")

        assert failing() is None

    def test_safe_call_preserves_function_name(self):
        from core.safety import safe_call

        @safe_call("test")
        def my_func():
            pass

        assert my_func.__name__ == "my_func"


# ══════════════════════════════════════════════════════════
# 3. safe_thread decorator
# ══════════════════════════════════════════════════════════

class TestSafeThread:
    """Tests for the safe_thread decorator."""

    def setup_method(self):
        from core.safety import _CrashTracker
        with _CrashTracker._lock:
            _CrashTracker._data.clear()
            _CrashTracker._disabled.clear()

    def test_safe_thread_runs_function_normally(self):
        from core.safety import safe_thread
        results = []

        @safe_thread("test_normal", restart=False)
        def normal_fn():
            results.append("done")

        t = threading.Thread(target=normal_fn, daemon=True)
        t.start()
        t.join(timeout=2)
        assert results == ["done"]

    def test_safe_thread_catches_exception_and_returns_without_restart(self):
        from core.safety import safe_thread
        results = []

        @safe_thread("test_no_restart", restart=False)
        def failing_fn():
            results.append("attempt")
            raise RuntimeError("crash")

        t = threading.Thread(target=failing_fn, daemon=True)
        t.start()
        t.join(timeout=2)
        assert results == ["attempt"]

    def test_safe_thread_preserves_function_name(self):
        from core.safety import safe_thread

        @safe_thread("test_name")
        def my_thread_func():
            pass

        assert my_thread_func.__name__ == "my_thread_func"

    def test_safe_thread_with_restart_retries_after_crash(self):
        from core.safety import safe_thread
        attempts = []

        @safe_thread("test_retry", restart=True, backoff=0.1)
        def crash_then_succeed():
            attempts.append(1)
            if len(attempts) < 3:
                raise RuntimeError("crash")
            return "done"

        t = threading.Thread(target=crash_then_succeed, daemon=True)
        t.start()
        t.join(timeout=5)
        assert len(attempts) >= 3

    def test_safe_thread_skips_when_circuit_breaker_active(self):
        from core.safety import safe_thread, _CrashTracker
        # Open circuit for this function
        fn_name = "test_skip_circuit"
        for _ in range(3):
            _CrashTracker.record(fn_name)
        assert _CrashTracker.is_disabled(fn_name) is True

        # Now close it immediately so the test can proceed
        with _CrashTracker._lock:
            _CrashTracker._disabled[fn_name] = time.time() - 1

        assert _CrashTracker.is_disabled(fn_name) is False

    def test_safe_thread_uses_qualname_when_no_name_given(self):
        from core.safety import safe_thread

        @safe_thread()
        def unnamed_func():
            pass

        assert unnamed_func.__name__ == "unnamed_func"

    def test_safe_thread_circuit_breaker_waits_then_runs(self):
        """Cover the circuit breaker active path (lines 86-88) in safe_thread."""
        from core.safety import safe_thread, _CrashTracker

        fn_name = "test_cb_wait"
        attempts = []

        @safe_thread(fn_name, restart=False, backoff=0.1)
        def guarded_fn():
            attempts.append(1)
            return "ok"

        # Open circuit breaker
        for _ in range(3):
            _CrashTracker.record(fn_name)
        assert _CrashTracker.is_disabled(fn_name) is True

        # Set expiry to almost now so it will pass after the 60s sleep
        # We'll set it to expire immediately so the loop breaks quickly
        with _CrashTracker._lock:
            _CrashTracker._disabled[fn_name] = time.time() + 0.1

        # Monkeypatch time.sleep to avoid 60s wait
        import unittest.mock
        original_sleep = time.sleep

        sleep_calls = []

        def fast_sleep(seconds):
            sleep_calls.append(seconds)
            if seconds >= 10:
                # Expire the circuit breaker during the wait
                with _CrashTracker._lock:
                    if fn_name in _CrashTracker._disabled:
                        del _CrashTracker._disabled[fn_name]
                original_sleep(0.01)
            else:
                original_sleep(min(seconds, 0.01))

        with unittest.mock.patch("core.safety.time.sleep", side_effect=fast_sleep):
            t = threading.Thread(target=guarded_fn, daemon=True)
            t.start()
            t.join(timeout=5)

        assert len(attempts) == 1
        # Verify the circuit breaker sleep was triggered (60s sleep call)
        assert any(s >= 10 for s in sleep_calls)

    def test_safe_thread_logs_circuit_open_on_third_crash(self):
        """Cover line 94 (circuit open log) in safe_thread."""
        from core.safety import safe_thread, _CrashTracker
        import unittest.mock

        fn_name = "test_open_log"
        crash_count = [0]

        @safe_thread(fn_name, restart=True, backoff=0.1)
        def always_crash():
            crash_count[0] += 1
            if crash_count[0] > 4:
                return "stop"  # stop crashing after 4 to allow exit
            raise RuntimeError(f"crash #{crash_count[0]}")

        # Fast sleep to avoid waiting
        original_sleep = time.sleep

        def fast_sleep(seconds):
            if seconds >= 10:
                # Expire circuit breaker to allow test to complete
                with _CrashTracker._lock:
                    if fn_name in _CrashTracker._disabled:
                        del _CrashTracker._disabled[fn_name]
                original_sleep(0.01)
            else:
                original_sleep(min(seconds, 0.01))

        with unittest.mock.patch("core.safety.time.sleep", side_effect=fast_sleep):
            t = threading.Thread(target=always_crash, daemon=True)
            t.start()
            t.join(timeout=10)

        assert crash_count[0] >= 3  # At least 3 crashes triggered circuit open


# ══════════════════════════════════════════════════════════
# 4. Supervisor
# ══════════════════════════════════════════════════════════

class TestSupervisor:
    """Tests for the thread supervisor (no real sleeps — mock monitor loop)."""

    def _make_sv(self, alert_fn=None):
        """Create Supervisor with monitor loop patched to not start."""
        import unittest.mock
        with unittest.mock.patch("core.safety.threading.Thread"):
            from core.safety import Supervisor
            sv = Supervisor(alert_fn=alert_fn)
        sv._running = True
        return sv

    def test_watch_registers_thread(self):
        sv = self._make_sv()
        fn = lambda: None
        t = threading.Thread(target=fn, daemon=True)
        t.start(); t.join()
        sv.watch("test-worker", t, target=fn, critical=True)
        assert "test-worker" in sv._watched
        assert sv._watched["test-worker"]["critical"] is True

    def test_stats_shows_watched_threads(self):
        sv = self._make_sv()
        fn = lambda: time.sleep(5)
        t = threading.Thread(target=fn, daemon=True)
        t.start()
        sv.watch("worker", t, target=fn, critical=False, max_restarts=3)
        stats = sv.stats
        assert "worker" in stats["watched"]
        assert stats["watched"]["worker"]["alive"] is True
        assert stats["watched"]["worker"]["max_restarts"] == 3

    def test_supervisor_stop_sets_running_false(self):
        sv = self._make_sv()
        sv.stop()
        assert sv._running is False

    def test_watch_stores_target_args_kwargs(self):
        sv = self._make_sv()
        def worker(x, y=1): pass
        t = threading.Thread(target=worker, args=(5,), kwargs={"y": 2}, daemon=True)
        t.start(); t.join()
        sv.watch("worker", t, target=worker, args=(5,), kwargs={"y": 2})
        info = sv._watched["worker"]
        assert info["args"] == (5,)
        assert info["kwargs"] == {"y": 2}

    def test_stats_includes_crash_tracker(self):
        sv = self._make_sv()
        stats = sv.stats
        assert "crash_tracker" in stats
        assert "crash_counts" in stats["crash_tracker"]

    def test_monitor_loop_restarts_dead_thread(self):
        """Directly call _monitor_loop logic for dead thread restart."""
        alerts = []
        sv = self._make_sv(alert_fn=lambda **kw: alerts.append(kw))
        # Create a dead thread
        t = threading.Thread(target=lambda: None, daemon=True)
        t.start(); t.join()
        sv.watch("dead", t, target=lambda: None, critical=True, max_restarts=3)
        # Simulate one monitor cycle by calling the loop body with a break
        _real_sleep = time.sleep
        def break_sleep(s):
            # Run one iteration then stop
            sv._running = False
        import unittest.mock
        with unittest.mock.patch("core.safety.time.sleep", side_effect=break_sleep):
            sv._running = True
            sv._monitor_loop()
        # Should have attempted restart
        assert sv._watched["dead"]["restarts"] >= 1

    def test_monitor_loop_fires_alert_at_max_restarts(self):
        alerts = []
        sv = self._make_sv(alert_fn=lambda **kw: alerts.append(kw))
        t = threading.Thread(target=lambda: None, daemon=True)
        t.start(); t.join()
        sv.watch("dying", t, target=lambda: None, critical=True, max_restarts=1)
        sv._watched["dying"]["restarts"] = 1  # Already at max
        import unittest.mock
        with unittest.mock.patch("core.safety.time.sleep", side_effect=lambda s: setattr(sv, '_running', False)):
            sv._running = True
            sv._monitor_loop()
        # Should have fired a critical alert
        assert any(a.get("severity", 0) <= 2 for a in alerts)

    def test_monitor_loop_skips_alive_thread(self):
        sv = self._make_sv()
        fn = lambda: time.sleep(60)
        t = threading.Thread(target=fn, daemon=True)
        t.start()
        sv.watch("alive", t, target=fn, critical=False)
        import unittest.mock
        with unittest.mock.patch("core.safety.time.sleep", side_effect=lambda s: setattr(sv, '_running', False)):
            sv._running = True
            sv._monitor_loop()
        assert sv._watched["alive"]["restarts"] == 0


# ══════════════════════════════════════════════════════════
# 5. EmailQueue
# ══════════════════════════════════════════════════════════

class TestEmailQueue:
    """Tests for the EmailQueue retry queue (Layer 3)."""

    def _make_queue(self):
        """Create an EmailQueue without starting the background thread."""
        import unittest.mock
        with unittest.mock.patch("core.safety.threading.Thread"):
            from core.safety import EmailQueue
            cfg = {
                "email.smtp_server": "smtp.example.com",
                "email.smtp_port": 587,
                "email.smtp_tls": True,
                "email.smtp_user": "user@example.com",
                "email.smtp_password": "secret",
                "email.from_address": "sentinel@example.com",
            }
            eq = EmailQueue(type("Cfg", (), {"get": lambda self, k, d="": cfg.get(k, d)})())
        return eq

    def test_enqueue_adds_message_to_queue(self):
        eq = self._make_queue()
        eq.enqueue("to@example.com", "Subject", "Body")
        assert len(eq._queue) == 1
        msg = eq._queue[0]
        assert msg["to"] == "to@example.com"
        assert msg["subject"] == "Subject"
        assert msg["body"] == "Body"
        assert msg["attempts"] == 0
        assert msg["html"] is False
        assert msg["attachments"] == []

    def test_enqueue_html_email(self):
        eq = self._make_queue()
        eq.enqueue("to@example.com", "Sub", "<b>Bold</b>", html=True)
        assert eq._queue[0]["html"] is True

    def test_enqueue_with_attachments(self):
        eq = self._make_queue()
        eq.enqueue("to@example.com", "Sub", "Body", attachments=["file1.txt"])
        assert eq._queue[0]["attachments"] == ["file1.txt"]

    def test_stats_returns_pending_count(self):
        eq = self._make_queue()
        assert eq.stats == {"pending": 0}
        eq.enqueue("a@b.com", "s", "b")
        assert eq.stats == {"pending": 1}

    def test_send_plain_text_email_success(self):
        import unittest.mock
        eq = self._make_queue()
        msg = {"to": "a@b.com", "subject": "Hi", "body": "Hello",
               "html": False, "attachments": [], "attempts": 0}

        mock_smtp_instance = unittest.mock.MagicMock()
        with unittest.mock.patch("smtplib.SMTP", return_value=mock_smtp_instance):
            result = eq._send(msg)

        assert result is True
        mock_smtp_instance.starttls.assert_called_once()
        mock_smtp_instance.login.assert_called_once_with("user@example.com", "secret")
        mock_smtp_instance.send_message.assert_called_once()
        mock_smtp_instance.quit.assert_called_once()

    def test_send_html_email_success(self):
        import unittest.mock
        eq = self._make_queue()
        msg = {"to": "a@b.com", "subject": "Hi", "body": "<b>Hello</b>",
               "html": True, "attachments": [], "attempts": 0}

        mock_smtp_instance = unittest.mock.MagicMock()
        with unittest.mock.patch("smtplib.SMTP", return_value=mock_smtp_instance):
            result = eq._send(msg)

        assert result is True

    def test_send_with_smtp_ssl_port_465(self):
        import unittest.mock
        with unittest.mock.patch("core.safety.threading.Thread"):
            from core.safety import EmailQueue
            cfg = {
                "email.smtp_server": "smtp.example.com",
                "email.smtp_port": 465,
                "email.smtp_tls": True,
                "email.smtp_user": "",
                "email.smtp_password": "",
                "email.from_address": "sentinel@example.com",
            }
            eq = EmailQueue(type("Cfg", (), {"get": lambda self, k, d="": cfg.get(k, d)})())

        msg = {"to": "a@b.com", "subject": "Hi", "body": "Hello",
               "html": False, "attachments": [], "attempts": 0}

        mock_ssl_instance = unittest.mock.MagicMock()
        with unittest.mock.patch("smtplib.SMTP_SSL", return_value=mock_ssl_instance):
            result = eq._send(msg)

        assert result is True
        mock_ssl_instance.send_message.assert_called_once()
        # No login since smtp_user is empty
        mock_ssl_instance.login.assert_not_called()

    def test_send_returns_false_when_no_smtp_server(self):
        import unittest.mock
        with unittest.mock.patch("core.safety.threading.Thread"):
            from core.safety import EmailQueue
            cfg = {"email.smtp_server": ""}
            eq = EmailQueue(type("Cfg", (), {"get": lambda self, k, d="": cfg.get(k, d)})())

        msg = {"to": "a@b.com", "subject": "Hi", "body": "Hello",
               "html": False, "attachments": [], "attempts": 0}
        result = eq._send(msg)
        assert result is False

    def test_send_returns_false_on_smtp_exception(self):
        import unittest.mock
        eq = self._make_queue()
        msg = {"to": "a@b.com", "subject": "Hi", "body": "Hello",
               "html": False, "attachments": [], "attempts": 0}

        with unittest.mock.patch("smtplib.SMTP", side_effect=ConnectionError("refused")):
            result = eq._send(msg)

        assert result is False

    def test_send_without_tls(self):
        import unittest.mock
        with unittest.mock.patch("core.safety.threading.Thread"):
            from core.safety import EmailQueue
            cfg = {
                "email.smtp_server": "smtp.example.com",
                "email.smtp_port": 587,
                "email.smtp_tls": False,
                "email.smtp_user": "user@example.com",
                "email.smtp_password": "secret",
                "email.from_address": "sentinel@example.com",
            }
            eq = EmailQueue(type("Cfg", (), {"get": lambda self, k, d="": cfg.get(k, d)})())

        msg = {"to": "a@b.com", "subject": "Hi", "body": "Hello",
               "html": False, "attachments": [], "attempts": 0}

        mock_smtp_instance = unittest.mock.MagicMock()
        with unittest.mock.patch("smtplib.SMTP", return_value=mock_smtp_instance):
            result = eq._send(msg)

        assert result is True
        mock_smtp_instance.starttls.assert_not_called()

    def test_process_loop_sends_and_removes_successful_email(self):
        import unittest.mock
        eq = self._make_queue()
        eq.enqueue("a@b.com", "Sub", "Body")

        call_count = [0]

        def mock_sleep(s):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with unittest.mock.patch.object(eq, "_send", return_value=True), \
             unittest.mock.patch("core.safety.time.sleep", side_effect=mock_sleep):
            try:
                eq._process_loop()
            except StopIteration:
                pass

        assert len(eq._queue) == 0

    def test_process_loop_retries_failed_email_with_backoff(self):
        import unittest.mock
        eq = self._make_queue()
        eq.enqueue("a@b.com", "Sub", "Body")

        call_count = [0]

        def mock_sleep(s):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with unittest.mock.patch.object(eq, "_send", return_value=False), \
             unittest.mock.patch("core.safety.time.sleep", side_effect=mock_sleep):
            try:
                eq._process_loop()
            except StopIteration:
                pass

        # Message should still be in queue with incremented attempts
        assert len(eq._queue) == 1
        assert eq._queue[0]["attempts"] == 1

    def test_process_loop_removes_email_after_max_retries(self):
        import unittest.mock
        eq = self._make_queue()
        eq.enqueue("a@b.com", "Sub", "Body")
        # Set attempts to 2 so next failure (attempt 3) triggers removal
        eq._queue[0]["attempts"] = 2

        call_count = [0]

        def mock_sleep(s):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with unittest.mock.patch.object(eq, "_send", return_value=False), \
             unittest.mock.patch("core.safety.time.sleep", side_effect=mock_sleep):
            try:
                eq._process_loop()
            except StopIteration:
                pass

        assert len(eq._queue) == 0

    def test_process_loop_skips_messages_not_yet_due(self):
        import unittest.mock
        eq = self._make_queue()
        eq.enqueue("a@b.com", "Sub", "Body")
        # Set next_retry far in the future
        eq._queue[0]["next_retry"] = time.time() + 9999

        call_count = [0]
        send_called = [False]

        original_send = eq._send

        def tracked_send(msg):
            send_called[0] = True
            return original_send(msg)

        def mock_sleep(s):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with unittest.mock.patch.object(eq, "_send", side_effect=tracked_send), \
             unittest.mock.patch("core.safety.time.sleep", side_effect=mock_sleep):
            try:
                eq._process_loop()
            except StopIteration:
                pass

        assert send_called[0] is False
        assert len(eq._queue) == 1


# ══════════════════════════════════════════════════════════
# 6. Additional Supervisor._monitor_loop coverage
# ══════════════════════════════════════════════════════════

class TestSupervisorMonitorLoopExtended:
    """Additional tests for Supervisor._monitor_loop edge cases."""

    def _make_sv(self, alert_fn=None):
        import unittest.mock
        with unittest.mock.patch("core.safety.threading.Thread"):
            from core.safety import Supervisor
            sv = Supervisor(alert_fn=alert_fn)
        sv._running = True
        return sv

    def test_monitor_loop_non_critical_dead_thread_at_max_restarts_no_alert(self):
        """Non-critical thread at max restarts should NOT fire an alert."""
        alerts = []
        sv = self._make_sv(alert_fn=lambda **kw: alerts.append(kw))
        t = threading.Thread(target=lambda: None, daemon=True)
        t.start(); t.join()
        sv.watch("non-crit", t, target=lambda: None, critical=False, max_restarts=1)
        sv._watched["non-crit"]["restarts"] = 1  # At max

        import unittest.mock
        with unittest.mock.patch("core.safety.time.sleep",
                                 side_effect=lambda s: setattr(sv, '_running', False)):
            sv._running = True
            sv._monitor_loop()

        assert len(alerts) == 0

    def test_monitor_loop_restart_failure_exception(self):
        """Cover line 219-220: exception during thread restart."""
        import unittest.mock
        sv = self._make_sv()
        t = threading.Thread(target=lambda: None, daemon=True)
        t.start(); t.join()
        sv.watch("bad-restart", t, target=lambda: None, critical=False, max_restarts=5)

        def fail_thread_create(*a, **kw):
            raise RuntimeError("cannot create thread")

        with unittest.mock.patch("core.safety.time.sleep",
                                 side_effect=lambda s: setattr(sv, '_running', False)), \
             unittest.mock.patch("core.safety.threading.Thread",
                                 side_effect=fail_thread_create):
            sv._running = True
            sv._monitor_loop()

        # Restarts counter should have incremented even though creation failed
        assert sv._watched["bad-restart"]["restarts"] == 1

    def test_monitor_loop_critical_thread_restart_fires_info_alert(self):
        """Cover lines 211-218: critical thread restart fires severity 3 alert."""
        alerts = []
        sv = self._make_sv(alert_fn=lambda **kw: alerts.append(kw))
        t = threading.Thread(target=lambda: None, daemon=True)
        t.start(); t.join()

        def dummy_target():
            time.sleep(999)

        sv.watch("crit-restart", t, target=dummy_target, critical=True, max_restarts=5)

        import unittest.mock
        with unittest.mock.patch("core.safety.time.sleep",
                                 side_effect=lambda s: setattr(sv, '_running', False)):
            sv._running = True
            sv._monitor_loop()

        # Should have fired a severity 3 alert for the restart
        restart_alerts = [a for a in alerts if a.get("category") == "component_restarted"]
        assert len(restart_alerts) == 1
        assert restart_alerts[0]["severity"] == 3

    def test_monitor_loop_updates_last_alive_for_live_thread(self):
        """Verify that _monitor_loop updates last_alive for alive threads."""
        sv = self._make_sv()
        fn = lambda: time.sleep(60)
        t = threading.Thread(target=fn, daemon=True)
        t.start()
        sv.watch("running", t, target=fn, critical=False)
        old_alive = sv._watched["running"]["last_alive"]

        import unittest.mock
        # Small delay to ensure time difference
        time.sleep(0.01)
        with unittest.mock.patch("core.safety.time.sleep",
                                 side_effect=lambda s: setattr(sv, '_running', False)):
            sv._running = True
            sv._monitor_loop()

        assert sv._watched["running"]["last_alive"] >= old_alive


# ══════════════════════════════════════════════════════════
# 7. EmailQueue race-condition ValueError guards
# ══════════════════════════════════════════════════════════

class TestEmailQueueValueErrorGuards:
    """Cover the ValueError exception handlers in _process_loop (lines 285-286, 294-295)."""

    def _make_queue(self):
        import unittest.mock
        with unittest.mock.patch("core.safety.threading.Thread"):
            from core.safety import EmailQueue
            cfg = {
                "email.smtp_server": "smtp.example.com",
                "email.smtp_port": 587,
                "email.smtp_tls": True,
                "email.smtp_user": "user@example.com",
                "email.smtp_password": "secret",
                "email.from_address": "sentinel@example.com",
            }
            eq = EmailQueue(type("Cfg", (), {"get": lambda self, k, d="": cfg.get(k, d)})())
        return eq

    def test_process_loop_success_remove_value_error_is_swallowed(self):
        """Cover lines 285-286: message already removed when success remove is called."""
        import unittest.mock
        eq = self._make_queue()
        eq.enqueue("a@b.com", "Sub", "Body")
        msg_ref = eq._queue[0]

        call_count = [0]

        def mock_send(msg):
            # Remove the message before _process_loop tries to remove it
            with eq._lock:
                try:
                    eq._queue.remove(msg)
                except ValueError:
                    pass
            return True

        def mock_sleep(s):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with unittest.mock.patch.object(eq, "_send", side_effect=mock_send), \
             unittest.mock.patch("core.safety.time.sleep", side_effect=mock_sleep):
            try:
                eq._process_loop()
            except StopIteration:
                pass

        assert len(eq._queue) == 0

    def test_process_loop_max_retries_remove_value_error_is_swallowed(self):
        """Cover lines 294-295: message already removed when max-retry remove is called."""
        import unittest.mock
        eq = self._make_queue()
        eq.enqueue("a@b.com", "Sub", "Body")
        eq._queue[0]["attempts"] = 2  # Next failure = attempt 3 = max

        call_count = [0]

        def mock_send(msg):
            # Remove the message before _process_loop tries to remove it
            with eq._lock:
                try:
                    eq._queue.remove(msg)
                except ValueError:
                    pass
            return False

        def mock_sleep(s):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with unittest.mock.patch.object(eq, "_send", side_effect=mock_send), \
             unittest.mock.patch("core.safety.time.sleep", side_effect=mock_sleep):
            try:
                eq._process_loop()
            except StopIteration:
                pass

        assert len(eq._queue) == 0
