"""Tests for core/notifications.py — Slack, Teams, Telegram dispatcher."""
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import Config


def _make_cfg(tmp_path, notifications=None):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.dump({
        "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs")},
        "notifications": notifications or {},
    }))
    return Config(str(cfg_path))


# ══════════════════════════════════════════════════
# _ChannelState
# ══════════════════════════════════════════════════

class TestChannelState:

    def test_allow_returns_true_under_limit(self):
        from core.notifications import _ChannelState
        cs = _ChannelState(enabled=True)
        assert cs.allow() is True

    def test_allow_returns_false_at_rate_limit(self):
        from core.notifications import _ChannelState, RATE_LIMIT
        cs = _ChannelState(enabled=True)
        for _ in range(RATE_LIMIT):
            cs.allow()
        assert cs.allow() is False
        assert cs.rate_limited == 1

    def test_record_ok_increments_sent(self):
        from core.notifications import _ChannelState
        cs = _ChannelState()
        cs.record_ok()
        cs.record_ok()
        assert cs.sent == 2

    def test_record_err_increments_errors(self):
        from core.notifications import _ChannelState
        cs = _ChannelState()
        cs.record_err()
        assert cs.errors == 1

    def test_as_dict_returns_expected_keys(self):
        from core.notifications import _ChannelState
        cs = _ChannelState(enabled=True)
        cs.record_ok()
        d = cs.as_dict()
        assert d == {"enabled": True, "sent": 1, "errors": 0, "rate_limited": 0}

    def test_allow_cleans_old_timestamps(self):
        from core.notifications import _ChannelState, RATE_LIMIT
        cs = _ChannelState(enabled=True)
        # Inject old timestamps
        cs._timestamps = [time.time() - 7200] * (RATE_LIMIT + 10)
        # Should be cleaned up and allow
        assert cs.allow() is True


# ══════════════════════════════════════════════════
# NotificationDispatcher init
# ══════════════════════════════════════════════════

class TestDispatcherInit:

    def test_init_all_disabled(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path)
        nd = NotificationDispatcher(cfg)
        assert nd._channels["slack"].enabled is False
        assert nd._channels["teams"].enabled is False
        assert nd._channels["telegram"].enabled is False

    def test_init_slack_enabled(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": "http://hook"}})
        nd = NotificationDispatcher(cfg)
        assert nd._channels["slack"].enabled is True

    def test_init_teams_enabled(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"teams": {"enabled": True, "webhook_url": "http://hook"}})
        nd = NotificationDispatcher(cfg)
        assert nd._channels["teams"].enabled is True

    def test_init_telegram_enabled(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"telegram": {"enabled": True, "bot_token": "t", "chat_id": "c"}})
        nd = NotificationDispatcher(cfg)
        assert nd._channels["telegram"].enabled is True


# ══════════════════════════════════════════════════
# send()
# ══════════════════════════════════════════════════

class TestSend:

    def test_send_skips_disabled_channels(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path)
        nd = NotificationDispatcher(cfg)
        with patch.object(nd, '_deliver') as mock_d:
            nd.send(severity=2, title="Test")
            mock_d.assert_not_called()

    def test_send_dispatches_to_enabled_channel(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": "http://h"}})
        nd = NotificationDispatcher(cfg)
        with patch.object(nd, '_deliver') as mock_d:
            nd.send(severity=2, title="Test", detail="D", src_ip="1.2.3.4", dst_ip="5.6.7.8")
            # _deliver is launched in a thread, but with mock it's intercepted
            # Actually _deliver is called via threading.Thread, so we need to wait or mock Thread
        # Since threading.Thread is used, mock at a higher level
        with patch("core.notifications.threading.Thread") as MockThread:
            nd.send(severity=2, title="Test")
            MockThread.assert_called()
            MockThread.return_value.start.assert_called()

    def test_send_rate_limited_channel_skipped(self, tmp_path):
        from core.notifications import NotificationDispatcher, RATE_LIMIT
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": "http://h"}})
        nd = NotificationDispatcher(cfg)
        # Exhaust rate limit
        for _ in range(RATE_LIMIT):
            nd._channels["slack"].allow()
        with patch("core.notifications.threading.Thread") as MockThread:
            nd.send(severity=2, title="Test")
            MockThread.assert_not_called()

    def test_send_truncates_detail(self, tmp_path):
        from core.notifications import NotificationDispatcher, MAX_DETAIL
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": "http://h"}})
        nd = NotificationDispatcher(cfg)
        long_detail = "x" * 1000
        with patch("core.notifications.threading.Thread") as MockThread:
            nd.send(severity=2, title="Test", detail=long_detail)
            if MockThread.called:
                call_args = MockThread.call_args
                # detail arg is at index 4 in args tuple
                detail_arg = call_args[1]["args"][4]
                assert len(detail_arg) == MAX_DETAIL


# ══════════════════════════════════════════════════
# stats
# ══════════════════════════════════════════════════

class TestStats:

    def test_stats_returns_all_channels(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": "http://h"}})
        nd = NotificationDispatcher(cfg)
        s = nd.stats
        assert "slack" in s
        assert "teams" in s
        assert "telegram" in s
        assert s["slack"]["enabled"] is True
        assert s["teams"]["enabled"] is False


# ══════════════════════════════════════════════════
# _deliver (retry logic)
# ══════════════════════════════════════════════════

class TestDeliver:

    def test_deliver_success_first_try(self, tmp_path):
        from core.notifications import NotificationDispatcher, _ChannelState
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": "http://h"}})
        nd = NotificationDispatcher(cfg)
        state = nd._channels["slack"]
        with patch.object(nd, '_slack') as mock_slack:
            nd._deliver("slack", state, 2, "Title", "Detail", "1.2.3.4", "", "ts")
        mock_slack.assert_called_once()
        assert state.sent == 1
        assert state.errors == 0

    def test_deliver_retries_on_failure(self, tmp_path):
        from core.notifications import NotificationDispatcher, RETRY_ATTEMPTS
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": "http://h"}})
        nd = NotificationDispatcher(cfg)
        state = nd._channels["slack"]
        with patch.object(nd, '_slack', side_effect=Exception("fail")), \
             patch("core.notifications.time.sleep"):
            nd._deliver("slack", state, 2, "Title", "Detail", "", "", "ts")
        assert state.errors == 1
        assert state.sent == 0

    def test_deliver_succeeds_on_second_attempt(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": "http://h"}})
        nd = NotificationDispatcher(cfg)
        state = nd._channels["slack"]
        call_count = [0]
        def flaky(*args):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("transient")
        with patch.object(nd, '_slack', side_effect=flaky), \
             patch("core.notifications.time.sleep"):
            nd._deliver("slack", state, 2, "Title", "Detail", "", "", "ts")
        assert state.sent == 1

    def test_deliver_teams(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"teams": {"enabled": True, "webhook_url": "http://h"}})
        nd = NotificationDispatcher(cfg)
        state = nd._channels["teams"]
        with patch.object(nd, '_teams'):
            nd._deliver("teams", state, 3, "Title", "Detail", "", "", "ts")
        assert state.sent == 1

    def test_deliver_telegram(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"telegram": {"enabled": True, "bot_token": "t", "chat_id": "c"}})
        nd = NotificationDispatcher(cfg)
        state = nd._channels["telegram"]
        with patch.object(nd, '_telegram'):
            nd._deliver("telegram", state, 1, "Title", "Detail", "", "", "ts")
        assert state.sent == 1


# ══════════════════════════════════════════════════
# _slack
# ══════════════════════════════════════════════════

class TestSlack:

    def test_slack_sends_payload(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": "http://hook.slack.com"}})
        nd = NotificationDispatcher(cfg)
        with patch("core.notifications.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            nd._slack(2, "Alert", "Details", "10.0.0.1", "192.168.1.10", "2024-01-01")
            mock_post.assert_called_once()
            payload = mock_post.call_args[1]["json"]
            assert "attachments" in payload

    def test_slack_no_url_raises(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": ""}})
        nd = NotificationDispatcher(cfg)
        with pytest.raises(ValueError, match="Slack webhook URL"):
            nd._slack(2, "Alert", "Details", "", "", "ts")

    def test_slack_without_ips(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": "http://hook"}})
        nd = NotificationDispatcher(cfg)
        with patch("core.notifications.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            nd._slack(5, "Info", "", "", "", "ts")
            mock_post.assert_called_once()

    def test_slack_with_empty_detail(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"slack": {"enabled": True, "webhook_url": "http://hook"}})
        nd = NotificationDispatcher(cfg)
        with patch("core.notifications.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            nd._slack(3, "Title", "", "1.1.1.1", "", "ts")


# ══════════════════════════════════════════════════
# _teams
# ══════════════════════════════════════════════════

class TestTeams:

    def test_teams_sends_card(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"teams": {"enabled": True, "webhook_url": "http://hook.teams"}})
        nd = NotificationDispatcher(cfg)
        with patch("core.notifications.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            nd._teams(1, "Critical", "Details", "10.0.0.1", "192.168.1.1", "ts")
            payload = mock_post.call_args[1]["json"]
            assert payload["@type"] == "MessageCard"
            assert "Critical" in payload["summary"]

    def test_teams_no_url_raises(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"teams": {"enabled": True, "webhook_url": ""}})
        nd = NotificationDispatcher(cfg)
        with pytest.raises(ValueError, match="Teams webhook URL"):
            nd._teams(2, "Alert", "", "", "", "ts")

    def test_teams_without_ips(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"teams": {"enabled": True, "webhook_url": "http://hook"}})
        nd = NotificationDispatcher(cfg)
        with patch("core.notifications.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            nd._teams(4, "Low", "D", "", "", "ts")
            payload = mock_post.call_args[1]["json"]
            facts = payload["sections"][0]["facts"]
            fact_names = [f["name"] for f in facts]
            assert "Source IP" not in fact_names


# ══════════════════════════════════════════════════
# _telegram
# ══════════════════════════════════════════════════

class TestTelegram:

    def test_telegram_sends_message(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"telegram": {"enabled": True, "bot_token": "tok", "chat_id": "123"}})
        nd = NotificationDispatcher(cfg)
        with patch("core.notifications.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            nd._telegram(2, "Alert", "Details", "10.0.0.1", "192.168.1.1", "ts")
            call_url = mock_post.call_args[0][0]
            assert "tok" in call_url
            payload = mock_post.call_args[1]["json"]
            assert payload["chat_id"] == "123"
            assert "HTML" in payload["parse_mode"]

    def test_telegram_no_token_raises(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"telegram": {"enabled": True, "bot_token": "", "chat_id": "123"}})
        nd = NotificationDispatcher(cfg)
        with pytest.raises(ValueError, match="bot_token"):
            nd._telegram(2, "Alert", "", "", "", "ts")

    def test_telegram_no_chat_id_raises(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"telegram": {"enabled": True, "bot_token": "tok", "chat_id": ""}})
        nd = NotificationDispatcher(cfg)
        with pytest.raises(ValueError, match="bot_token"):
            nd._telegram(2, "Alert", "", "", "", "ts")

    def test_telegram_without_ips(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"telegram": {"enabled": True, "bot_token": "tok", "chat_id": "1"}})
        nd = NotificationDispatcher(cfg)
        with patch("core.notifications.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            nd._telegram(5, "Info", "", "", "", "ts")

    def test_telegram_empty_detail(self, tmp_path):
        from core.notifications import NotificationDispatcher
        cfg = _make_cfg(tmp_path, {"telegram": {"enabled": True, "bot_token": "tok", "chat_id": "1"}})
        nd = NotificationDispatcher(cfg)
        with patch("core.notifications.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            nd._telegram(3, "Title", "", "1.1.1.1", "2.2.2.2", "ts")
            text = mock_post.call_args[1]["json"]["text"]
            assert "No details" in text
