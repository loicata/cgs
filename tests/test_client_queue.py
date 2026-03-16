"""Tests for core/client_queue.py — ClientNotificationQueue."""

import json
import os
import sys
import time
import hashlib
import hmac as _hmac
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.client_queue import ClientMessage, ClientNotificationQueue


class FakeConfig:
    def __init__(self, overrides=None):
        self._data = {
            "client_agent.enabled": True,
            "client_agent.message_ttl_minutes": 120,
            "email.security_contact": "security@test.com",
            "client_agent.shared_secret": "test-secret-key",
            "client_agent.ack_timeout_seconds": 2,
        }
        if overrides:
            self._data.update(overrides)

    def get(self, key, default=None):
        return self._data.get(key, default)


@pytest.fixture
def queue():
    """Create a ClientNotificationQueue with test config."""
    with patch("core.security.AntiReplay") as MockAR:
        mock_ar = MagicMock()
        mock_ar.check.return_value = (True, "ok")
        MockAR.return_value = mock_ar
        q = ClientNotificationQueue(FakeConfig())
    return q


@pytest.fixture
def queue_no_secret():
    """Queue without shared_secret (auth disabled)."""
    with patch("core.security.AntiReplay") as MockAR:
        MockAR.return_value = MagicMock()
        q = ClientNotificationQueue(FakeConfig({"client_agent.shared_secret": ""}))
    return q


# ── ClientMessage ──

class TestClientMessage:
    def test_message_creation(self):
        msg = ClientMessage("shutdown", "INC-001", {"key": "val"})
        assert msg.msg_type == "shutdown"
        assert msg.incident_id == "INC-001"
        assert msg.payload == {"key": "val"}
        assert msg.acked is False
        assert msg.created_at > 0

    def test_message_id_format(self):
        msg = ClientMessage("shutdown", "INC-001")
        assert msg.id.startswith("shutdown-INC-001-")

    def test_message_to_dict(self):
        msg = ClientMessage("shutdown", "INC-001", {"action": "shutdown"})
        d = msg.to_dict()
        assert d["type"] == "shutdown"
        assert d["incident_id"] == "INC-001"
        assert d["payload"]["action"] == "shutdown"
        assert d["acked"] is False
        assert "created_at" in d
        assert "created_iso" in d

    def test_message_default_payload(self):
        msg = ClientMessage("test", "INC-002")
        assert msg.payload == {}


# ── Enqueue ──

class TestEnqueue:
    def test_enqueue_shutdown(self, queue):
        msg_id = queue.enqueue_shutdown("192.168.1.10", "INC-001",
                                         threat_type="scan", detail="port scan")
        assert msg_id is not None
        pending, _ = queue.get_pending("192.168.1.10")
        assert len(pending) == 1
        assert pending[0]["type"] == "shutdown"
        assert "SECURITY ALERT" in pending[0]["payload"]["title"]

    def test_enqueue_all_clear_resolved(self, queue):
        msg_id = queue.enqueue_all_clear("192.168.1.10", "INC-001", resolved=True)
        pending, _ = queue.get_pending("192.168.1.10")
        assert len(pending) == 1
        assert pending[0]["type"] == "all_clear"
        assert "restart" in pending[0]["payload"]["title"].lower()

    def test_enqueue_all_clear_not_resolved(self, queue):
        msg_id = queue.enqueue_all_clear("192.168.1.10", "INC-001",
                                          resolved=False, risk_detail="malware active")
        pending, _ = queue.get_pending("192.168.1.10")
        assert len(pending) == 1
        assert pending[0]["type"] == "risk_warning"
        assert "Do NOT" in pending[0]["payload"]["message"]

    def test_enqueue_collect_forensic(self, queue):
        msg_id = queue.enqueue_collect_forensic("192.168.1.10", "INC-001")
        pending, _ = queue.get_pending("192.168.1.10")
        assert len(pending) == 1
        assert pending[0]["type"] == "collect_forensic"

    def test_enqueue_multiple_messages(self, queue):
        queue.enqueue_shutdown("192.168.1.10", "INC-001")
        queue.enqueue_collect_forensic("192.168.1.10", "INC-001")
        pending, _ = queue.get_pending("192.168.1.10")
        assert len(pending) == 2

    def test_enqueue_different_ips(self, queue):
        queue.enqueue_shutdown("192.168.1.10", "INC-001")
        queue.enqueue_shutdown("192.168.1.20", "INC-002")
        p1, _ = queue.get_pending("192.168.1.10")
        p2, _ = queue.get_pending("192.168.1.20")
        assert len(p1) == 1
        assert len(p2) == 1

    def test_shutdown_detail_truncated_to_500(self, queue):
        long_detail = "x" * 1000
        queue.enqueue_shutdown("192.168.1.10", "INC-001", detail=long_detail)
        pending, _ = queue.get_pending("192.168.1.10")
        assert len(pending[0]["payload"]["detail"]) == 500


# ── Get Pending / Poll ──

class TestGetPending:
    def test_no_pending_returns_empty(self, queue):
        pending, interval = queue.get_pending("1.2.3.4")
        assert pending == []
        assert interval == 60  # slow poll

    def test_with_pending_returns_fast_interval(self, queue):
        queue.enqueue_shutdown("1.2.3.4", "INC-001")
        pending, interval = queue.get_pending("1.2.3.4")
        assert len(pending) == 1
        assert interval == 5  # fast poll

    def test_acked_messages_not_in_pending(self, queue):
        msg_id = queue.enqueue_shutdown("1.2.3.4", "INC-001")
        queue.acknowledge("1.2.3.4", msg_id)
        pending, interval = queue.get_pending("1.2.3.4")
        assert len(pending) == 0
        assert interval == 60

    def test_polling_tracks_active_agent(self, queue):
        assert queue.has_active_agent("1.2.3.4") is False
        queue.get_pending("1.2.3.4")
        assert queue.has_active_agent("1.2.3.4") is True


# ── Acknowledge ──

class TestAcknowledge:
    def test_acknowledge_success(self, queue):
        msg_id = queue.enqueue_shutdown("1.2.3.4", "INC-001")
        result = queue.acknowledge("1.2.3.4", msg_id, hostname="pc-01", user="alice")
        assert result is True

    def test_acknowledge_wrong_id(self, queue):
        queue.enqueue_shutdown("1.2.3.4", "INC-001")
        result = queue.acknowledge("1.2.3.4", "wrong-id")
        assert result is False

    def test_acknowledge_wrong_ip(self, queue):
        msg_id = queue.enqueue_shutdown("1.2.3.4", "INC-001")
        result = queue.acknowledge("9.9.9.9", msg_id)
        assert result is False

    def test_double_acknowledge_fails(self, queue):
        msg_id = queue.enqueue_shutdown("1.2.3.4", "INC-001")
        assert queue.acknowledge("1.2.3.4", msg_id) is True
        assert queue.acknowledge("1.2.3.4", msg_id) is False

    def test_acknowledge_sets_acked_by(self, queue):
        msg_id = queue.enqueue_shutdown("1.2.3.4", "INC-001")
        queue.acknowledge("1.2.3.4", msg_id, hostname="pc-01", user="alice")
        # Verify internal state
        with queue._lock:
            msg = queue._queue["1.2.3.4"][0]
        assert msg.acked is True
        assert msg.acked_by == "alice@pc-01"

    def test_acknowledge_without_user(self, queue):
        msg_id = queue.enqueue_shutdown("1.2.3.4", "INC-001")
        queue.acknowledge("1.2.3.4", msg_id, hostname="pc-01")
        with queue._lock:
            msg = queue._queue["1.2.3.4"][0]
        assert msg.acked_by == "pc-01"


# ── HMAC Authentication ──

class TestHMACAuth:
    def test_hmac_sign(self, queue):
        sig = queue._hmac_sign("test-payload")
        expected = _hmac.new(
            b"test-secret-key", b"test-payload", hashlib.sha256
        ).hexdigest()
        assert sig == expected

    def test_verify_client_valid(self, queue):
        ts = str(int(time.time()))
        hostname = "pc-01"
        sig = queue._hmac_sign(f"check:{hostname}:{ts}")
        assert queue.verify_client(hostname, ts, sig) is True

    def test_verify_client_wrong_sig(self, queue):
        ts = str(int(time.time()))
        assert queue.verify_client("pc-01", ts, "badsig") is False

    def test_verify_client_no_secret_accepts_all(self, queue_no_secret):
        assert queue_no_secret.verify_client("pc-01", "123", "anything") is True

    def test_verify_client_anti_replay_rejects(self, queue):
        queue._anti_replay.check.return_value = (False, "replay detected")
        ts = str(int(time.time()))
        sig = queue._hmac_sign(f"check:pc-01:{ts}")
        assert queue.verify_client("pc-01", ts, sig) is False

    def test_verify_client_ack_valid(self, queue):
        data = {"msg_id": "test-123", "hostname": "pc-01"}
        sig = queue._hmac_sign(json.dumps(data, sort_keys=True))
        data["_sig"] = sig
        assert queue.verify_client_ack(data) is True

    def test_verify_client_ack_invalid(self, queue):
        data = {"msg_id": "test-123", "hostname": "pc-01", "_sig": "badsig"}
        assert queue.verify_client_ack(data) is False

    def test_verify_client_ack_no_secret(self, queue_no_secret):
        data = {"msg_id": "test", "_sig": "whatever"}
        assert queue_no_secret.verify_client_ack(data) is True

    def test_sign_response(self, queue):
        data = {"status": "ok", "messages": []}
        signed = queue.sign_response(data.copy())
        assert "_sig" in signed
        # Verify the signature
        sig = signed.pop("_sig")
        expected = queue._hmac_sign(json.dumps(data, sort_keys=True))
        assert sig == expected

    def test_sign_response_no_secret(self, queue_no_secret):
        data = {"status": "ok"}
        result = queue_no_secret.sign_response(data)
        assert "_sig" not in result


# ── has_active_agent ──

class TestHasActiveAgent:
    def test_not_active_by_default(self, queue):
        assert queue.has_active_agent("1.2.3.4") is False

    def test_active_after_poll(self, queue):
        queue.get_pending("1.2.3.4")
        assert queue.has_active_agent("1.2.3.4") is True

    def test_inactive_after_timeout(self, queue):
        queue._active_agents["1.2.3.4"] = time.time() - 200
        assert queue.has_active_agent("1.2.3.4") is False


# ── wait_for_ack ──

class TestWaitForAck:
    def test_wait_for_ack_timeout(self, queue):
        """With ack_timeout=2s, should return False quickly."""
        msg_id = queue.enqueue_shutdown("1.2.3.4", "INC-001")
        # Override timeout to be very short
        queue.ack_timeout = 0.1
        result = queue.wait_for_ack(msg_id, "1.2.3.4")
        assert result is False

    def test_wait_for_ack_success(self, queue):
        import threading
        msg_id = queue.enqueue_shutdown("1.2.3.4", "INC-001")
        queue.ack_timeout = 5

        def ack_later():
            time.sleep(0.1)
            queue.acknowledge("1.2.3.4", msg_id)

        t = threading.Thread(target=ack_later)
        t.start()
        result = queue.wait_for_ack(msg_id, "1.2.3.4")
        t.join()
        assert result is True


# ── Stats ──

class TestStats:
    def test_stats_empty(self, queue):
        s = queue.stats
        assert s["enabled"] is True
        assert s["total_messages"] == 0
        assert s["pending"] == 0
        assert s["hosts_with_messages"] == 0

    def test_stats_with_messages(self, queue):
        queue.enqueue_shutdown("1.2.3.4", "INC-001")
        queue.enqueue_shutdown("5.6.7.8", "INC-002")
        s = queue.stats
        assert s["total_messages"] == 2
        assert s["pending"] == 2
        assert s["hosts_with_messages"] == 2

    def test_stats_after_ack(self, queue):
        msg_id = queue.enqueue_shutdown("1.2.3.4", "INC-001")
        queue.acknowledge("1.2.3.4", msg_id)
        s = queue.stats
        assert s["total_messages"] == 1
        assert s["pending"] == 0

    def test_stats_active_agents(self, queue):
        queue.get_pending("1.2.3.4")
        s = queue.stats
        assert s["active_agents"] == 1
        assert "1.2.3.4" in s["known_agent_ips"]


# ── Message TTL (cleanup) ──

class TestMessageTTL:
    def test_expired_messages_concept(self, queue):
        """Verify that messages with old created_at would be cleaned up."""
        msg_id = queue.enqueue_shutdown("1.2.3.4", "INC-001")
        # Artificially age the message
        with queue._lock:
            queue._queue["1.2.3.4"][0].created_at = time.time() - 99999

        # Simulate cleanup logic
        ttl = queue.message_ttl * 60
        now = time.time()
        with queue._lock:
            for ip in list(queue._queue.keys()):
                queue._queue[ip] = [
                    m for m in queue._queue[ip]
                    if now - m.created_at < ttl
                ]
                if not queue._queue[ip]:
                    del queue._queue[ip]

        pending, _ = queue.get_pending("1.2.3.4")
        assert len(pending) == 0
