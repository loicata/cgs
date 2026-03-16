"""Tests for core/alerts.py — AlertEngine: fire, cooldown, dispatch, email, webhook, syslog."""
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.database import db, init_db, Alert
from core.config import Config


def _make_cfg(tmp_path, extra=None):
    cfg_path = tmp_path / "config.yaml"
    base = {
        "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs")},
        "alerts": {
            "cooldown_seconds": 300, "max_per_hour": 120,
            "email": {"enabled": False},
            "webhook": {"enabled": False},
            "syslog": {"enabled": False},
        },
        "notifications": {},
    }
    if extra:
        for k, v in extra.items():
            if isinstance(v, dict) and k in base:
                base[k].update(v)
            else:
                base[k] = v
    cfg_path.write_text(yaml.dump(base))
    return Config(str(cfg_path))


@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    if not db.is_closed():
        db.close()
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    init_db(data_dir)
    yield tmp_path
    if not db.is_closed():
        db.close()


# ══════════════════════════════════════════════════
# AlertEngine init
# ══════════════════════════════════════════════════

class TestAlertEngineInit:

    def test_init_with_defaults(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        assert engine.cooldown == 300
        assert engine.max_h == 120
        assert engine._notifier is None

    def test_init_with_notification_dispatcher(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db, {"notifications": {"slack": {"enabled": True, "webhook_url": "http://x"}}})
        with patch("core.notifications.NotificationDispatcher") as MockND:
            engine = AlertEngine(cfg)
            assert engine._notifier is not None

    def test_init_notification_dispatcher_import_error(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db, {"notifications": {"slack": {"enabled": True, "webhook_url": "http://x"}}})
        with patch("core.notifications.NotificationDispatcher", side_effect=Exception("import error")):
            engine = AlertEngine(cfg)
            assert engine._notifier is None


# ══════════════════════════════════════════════════
# fire()
# ══════════════════════════════════════════════════

class TestFire:

    def test_fire_creates_alert_in_db(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        a = engine.fire(severity=2, source="test", title="Test alert", src_ip="10.0.0.1")
        assert a is not None
        assert a.id > 0
        assert Alert.select().count() == 1

    def test_fire_returns_none_on_cooldown(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        engine.fire(severity=3, source="s", category="c", title="t", src_ip="1.2.3.4")
        result = engine.fire(severity=3, source="s", category="c", title="t", src_ip="1.2.3.4")
        assert result is None
        assert Alert.select().count() == 1

    def test_fire_different_keys_not_deduplicated(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        engine.fire(severity=3, source="s1", title="t1")
        engine.fire(severity=3, source="s2", title="t2")
        assert Alert.select().count() == 2

    def test_fire_returns_none_when_max_per_hour_reached(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        engine.max_h = 2
        engine.fire(severity=3, source="a", title="t1")
        engine.fire(severity=3, source="b", title="t2")
        result = engine.fire(severity=3, source="c", title="t3")
        assert result is None

    def test_fire_resets_hour_counter_after_3600s(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        engine.max_h = 1
        engine.fire(severity=3, source="a", title="t1")
        # Simulate hour passed
        engine._hstart = time.time() - 3601
        result = engine.fire(severity=3, source="b", title="t2")
        assert result is not None

    def test_fire_calls_websocket_callback(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        cb = MagicMock()
        engine._ws_cb = cb
        engine.fire(severity=3, source="test", title="WS test")
        cb.assert_called_once()

    def test_fire_websocket_callback_exception_handled(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        engine._ws_cb = MagicMock(side_effect=Exception("ws error"))
        a = engine.fire(severity=3, source="test", title="WS error test")
        assert a is not None  # Should not crash

    def test_fire_dispatches_for_severity_le_3(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        with patch.object(engine, '_dispatch') as mock_d:
            engine.fire(severity=2, source="test", title="Dispatch test", notify=True)
            mock_d.assert_called_once()

    def test_fire_does_not_dispatch_for_severity_gt_3(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        with patch.object(engine, '_dispatch') as mock_d:
            engine.fire(severity=5, source="test", title="Info", notify=True)
            mock_d.assert_not_called()

    def test_fire_does_not_dispatch_when_notify_false(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        with patch.object(engine, '_dispatch') as mock_d:
            engine.fire(severity=1, source="test", title="Silent", notify=False)
            mock_d.assert_not_called()

    def test_fire_severity_1_logs_critical(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        a = engine.fire(severity=1, source="test", title="Critical", notify=False)
        assert a.severity == 1

    def test_fire_with_all_fields(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        a = engine.fire(severity=2, source="sniffer", category="portscan",
                        title="Port scan", detail="20 ports scanned",
                        src_ip="10.0.0.1", dst_ip="192.168.1.10", ioc="evil.com")
        assert a.category == "portscan"
        assert a.detail == "20 ports scanned"
        assert a.ioc == "evil.com"


# ══════════════════════════════════════════════════
# _dispatch
# ══════════════════════════════════════════════════

class TestDispatch:

    def test_dispatch_email(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db, {"alerts": {
            "email": {"enabled": True, "from": "cgs@t.com", "to": "a@t.com",
                       "server": "smtp.t.com"},
            "webhook": {"enabled": False}, "syslog": {"enabled": False},
        }})
        engine = AlertEngine(cfg)
        with patch.object(engine, '_email') as mock_email:
            a = Alert.create(severity=2, source="test", title="T")
            engine._dispatch(a)
            time.sleep(0.1)
            # _email is called in a thread, but we patched it

    def test_dispatch_webhook(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db, {"alerts": {
            "email": {"enabled": False},
            "webhook": {"enabled": True, "url": "http://hook"},
            "syslog": {"enabled": False},
        }})
        engine = AlertEngine(cfg)
        with patch.object(engine, '_webhook') as mock_wh:
            a = Alert.create(severity=2, source="test", title="T")
            engine._dispatch(a)
            time.sleep(0.1)

    def test_dispatch_syslog(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db, {"alerts": {
            "email": {"enabled": False},
            "webhook": {"enabled": False},
            "syslog": {"enabled": True},
        }})
        engine = AlertEngine(cfg)
        with patch.object(engine, '_syslog') as mock_sys:
            a = Alert.create(severity=2, source="test", title="T")
            engine._dispatch(a)
            mock_sys.assert_called_once()

    def test_dispatch_notifier(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        engine._notifier = MagicMock()
        a = Alert.create(severity=2, source="test", title="T", src_ip="1.2.3.4")
        engine._dispatch(a)
        engine._notifier.send.assert_called_once()

    def test_dispatch_notifier_exception(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        engine._notifier = MagicMock()
        engine._notifier.send.side_effect = Exception("notif error")
        a = Alert.create(severity=2, source="test", title="T")
        engine._dispatch(a)  # Should not crash

    def test_dispatch_notifier_skipped_for_low_severity(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        engine._notifier = MagicMock()
        a = Alert.create(severity=5, source="test", title="Info")
        engine._dispatch(a)
        engine._notifier.send.assert_not_called()


# ══════════════════════════════════════════════════
# _email
# ══════════════════════════════════════════════════

class TestEmail:

    def test_email_success(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db, {"alerts": {
            "email": {"enabled": True, "from": "cgs@t.com", "to": "a@t.com",
                       "server": "smtp.t.com", "port": 587, "tls": True,
                       "user": "u", "password": "p"},
        }})
        engine = AlertEngine(cfg)
        a = Alert.create(severity=2, source="test", title="T", detail="D",
                         src_ip="1.2.3.4", dst_ip="5.6.7.8")
        with patch("core.alerts.smtplib.SMTP") as MockSMTP:
            mock_srv = MagicMock()
            MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_srv)
            MockSMTP.return_value.__exit__ = MagicMock(return_value=False)
            engine._email(a)

    def test_email_exception_handled(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db, {"alerts": {"email": {"enabled": True, "server": "bad"}}})
        engine = AlertEngine(cfg)
        a = Alert.create(severity=2, source="test", title="T")
        engine._email(a)  # Should not crash


# ══════════════════════════════════════════════════
# _webhook
# ══════════════════════════════════════════════════

class TestWebhook:

    def test_webhook_success(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db, {"alerts": {"webhook": {"enabled": True, "url": "http://hook"}}})
        engine = AlertEngine(cfg)
        a = Alert.create(severity=2, source="test", title="T", detail="D")
        with patch("core.alerts.requests.post") as mock_post:
            engine._webhook(a)
            mock_post.assert_called_once()

    def test_webhook_exception_handled(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db, {"alerts": {"webhook": {"enabled": True, "url": "http://hook"}}})
        engine = AlertEngine(cfg)
        a = Alert.create(severity=2, source="test", title="T")
        with patch("core.alerts.requests.post", side_effect=Exception("timeout")):
            engine._webhook(a)  # Should not crash


# ══════════════════════════════════════════════════
# _syslog
# ══════════════════════════════════════════════════

class TestSyslog:

    def test_syslog_success(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        a = Alert.create(severity=1, source="test", title="Critical alert")
        with patch("core.alerts.syslog") as mock_syslog:
            engine._syslog(a)
            mock_syslog.openlog.assert_called_once()
            mock_syslog.syslog.assert_called_once()
            mock_syslog.closelog.assert_called_once()

    def test_syslog_various_severities(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        for sev in [1, 2, 3, 4, 5]:
            a = Alert.create(severity=sev, source="test", title=f"Sev {sev}")
            with patch("core.alerts.syslog"):
                engine._syslog(a)

    def test_syslog_exception_handled(self, fresh_db):
        from core.alerts import AlertEngine
        cfg = _make_cfg(fresh_db)
        engine = AlertEngine(cfg)
        a = Alert.create(severity=2, source="test", title="T")
        with patch("core.alerts.syslog.openlog", side_effect=Exception("syslog error")):
            engine._syslog(a)  # Should not crash


# ══════════════════════════════════════════════════
# _ser and get_recent
# ══════════════════════════════════════════════════

class TestSerAndGetRecent:

    def test_ser_returns_dict_with_expected_keys(self, fresh_db):
        from core.alerts import AlertEngine
        a = Alert.create(severity=2, source="test", title="T", category="cat",
                         detail="D", src_ip="1.1.1.1", dst_ip="2.2.2.2", ioc="evil.com")
        result = AlertEngine._ser(a)
        assert result["severity"] == 2
        assert result["source"] == "test"
        assert result["title"] == "T"
        assert result["ioc"] == "evil.com"
        assert "ts" in result
        assert "severity_label" in result

    def test_get_recent_returns_alerts(self, fresh_db):
        from core.alerts import AlertEngine
        Alert.create(severity=1, source="test", title="A1")
        Alert.create(severity=5, source="test", title="A2")
        result = AlertEngine.get_recent(limit=10, max_sev=5)
        assert len(result) == 2

    def test_get_recent_filters_by_severity(self, fresh_db):
        from core.alerts import AlertEngine
        Alert.create(severity=1, source="test", title="Critical")
        Alert.create(severity=5, source="test", title="Info")
        result = AlertEngine.get_recent(limit=10, max_sev=2)
        assert len(result) == 1
        assert result[0]["title"] == "Critical"

    def test_get_recent_respects_limit(self, fresh_db):
        from core.alerts import AlertEngine
        for i in range(10):
            Alert.create(severity=3, source="test", title=f"Alert {i}")
        result = AlertEngine.get_recent(limit=5)
        assert len(result) == 5
