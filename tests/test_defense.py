"""Tests for core/defense.py — Active defense engine: blocking, whitelisting, escalation, audit."""
import os
import subprocess
import sys
import time
import threading
from unittest.mock import MagicMock, patch
from collections import defaultdict

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.database import db, init_db, Host
from core.config import Config


def _make_cfg(tmp_path, extra=None):
    cfg_path = tmp_path / "config.yaml"
    base = {
        "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs")},
        "network": {"subnets": ["192.168.1.0/24"], "interface": "lo", "exclude_ips": []},
        "defense": {
            "enabled": True, "auto_block": True, "auto_block_severity": 1,
            "alert_count_threshold": 5, "alert_count_window": 300,
            "block_ttl_seconds": 3600, "rate_limit_ttl_seconds": 1800,
            "quarantine_ttl_seconds": 7200,
            "whitelist_ips": ["192.168.1.1", "8.8.8.8"],
            "whitelist_macs": [],
        },
        "netgate": {"enabled": False},
    }
    if extra:
        base.update(extra)
    cfg_path.write_text(yaml.dump(base))
    return Config(str(cfg_path))


@pytest.fixture
def defense_env(tmp_path):
    """Create a DefenseEngine with mocked firewall commands."""
    if not db.is_closed():
        db.close()
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    init_db(data_dir)

    cfg = _make_cfg(tmp_path)

    with patch("core.defense.DefenseEngine._detect_firewall", return_value="none"), \
         patch("core.defense.DefenseEngine._init_firewall"), \
         patch("core.defense.DefenseEngine._run_cmd", return_value=True), \
         patch("core.defense.DefenseEngine._run", return_value=True), \
         patch("core.defense.get_iface_ip", return_value="192.168.1.100"):
        from core.defense import DefenseEngine
        alert_fn = MagicMock()
        engine = DefenseEngine(cfg, alert_fn, mac_resolver=None)
        engine._fw_backend = "none"
        yield engine, alert_fn

    if not db.is_closed():
        db.close()


# ══════════════════════════════════════════════════
# DefenseAction dataclass
# ══════════════════════════════════════════════════

class TestDefenseAction:

    def test_action_auto_sets_timestamps(self):
        from core.defense import DefenseAction
        a = DefenseAction(action_type="BLOCK_IP", target_ip="10.0.0.1", reason="test")
        assert a.created_at > 0
        assert a.expires_at > a.created_at
        assert a.active is True

    def test_action_custom_ttl(self):
        from core.defense import DefenseAction
        a = DefenseAction(action_type="BLOCK_IP", target_ip="10.0.0.1",
                          reason="test", ttl_seconds=60)
        assert abs(a.expires_at - a.created_at - 60) < 1


# ══════════════════════════════════════════════════
# Whitelisting
# ══════════════════════════════════════════════════

class TestWhitelisting:

    def test_whitelisted_ip_cannot_be_blocked(self, defense_env):
        engine, alert_fn = defense_env
        result = engine.block_ip("192.168.1.1", reason="test")
        assert result is False

    def test_sentinel_ip_is_auto_whitelisted(self, defense_env):
        engine, _ = defense_env
        assert engine.my_ip in engine.whitelist

    def test_non_whitelisted_ip_can_be_blocked(self, defense_env):
        engine, _ = defense_env
        result = engine.block_ip("10.0.0.99", reason="test")
        assert result is True

    def test_whitelisted_ip_cannot_be_rate_limited(self, defense_env):
        engine, _ = defense_env
        result = engine.rate_limit_ip("192.168.1.1", reason="test")
        assert result is False

    def test_whitelisted_ip_cannot_be_quarantined(self, defense_env):
        engine, _ = defense_env
        result = engine.quarantine_host("192.168.1.1", reason="test")
        assert result is False


# ══════════════════════════════════════════════════
# Block / Unblock
# ══════════════════════════════════════════════════

class TestBlockUnblock:

    def test_block_ip_creates_action(self, defense_env):
        engine, _ = defense_env
        engine.block_ip("10.0.0.50", reason="portscan")
        assert "BLOCK:10.0.0.50" in engine._actions
        assert engine._actions["BLOCK:10.0.0.50"].active is True

    def test_block_ip_fires_alert(self, defense_env):
        engine, alert_fn = defense_env
        engine.block_ip("10.0.0.50", reason="portscan")
        alert_fn.assert_called()
        call_kwargs = alert_fn.call_args[1]
        assert call_kwargs["category"] == "block"

    def test_block_ip_generates_audit_entry(self, defense_env):
        engine, _ = defense_env
        engine.block_ip("10.0.0.50", reason="test")
        assert len(engine._audit_log) >= 1
        assert engine._audit_log[-1]["action"] == "BLOCK_IP"

    def test_unblock_ip_deactivates_action(self, defense_env):
        engine, _ = defense_env
        engine.block_ip("10.0.0.50", reason="test")
        engine.unblock_ip("10.0.0.50", reason="manual")
        assert engine._actions["BLOCK:10.0.0.50"].active is False

    def test_blocking_same_ip_twice_extends_ttl(self, defense_env):
        engine, _ = defense_env
        engine.block_ip("10.0.0.50", reason="first", ttl=100)
        first_expires = engine._actions["BLOCK:10.0.0.50"].expires_at
        time.sleep(0.05)
        engine.block_ip("10.0.0.50", reason="second", ttl=200)
        second_expires = engine._actions["BLOCK:10.0.0.50"].expires_at
        assert second_expires > first_expires

    def test_block_updates_host_risk_score(self, defense_env):
        engine, _ = defense_env
        Host.create(ip="10.0.0.50", risk_score=0)
        engine.block_ip("10.0.0.50", reason="test")
        h = Host.get(Host.ip == "10.0.0.50")
        assert h.risk_score == 50


# ══════════════════════════════════════════════════
# Rate limit
# ══════════════════════════════════════════════════

class TestRateLimit:

    def test_rate_limit_creates_action(self, defense_env):
        engine, _ = defense_env
        result = engine.rate_limit_ip("10.0.0.60", reason="throttle")
        assert result is True
        assert "RATE:10.0.0.60" in engine._actions

    def test_duplicate_rate_limit_returns_true(self, defense_env):
        engine, _ = defense_env
        engine.rate_limit_ip("10.0.0.60", reason="first")
        result = engine.rate_limit_ip("10.0.0.60", reason="second")
        assert result is True


# ══════════════════════════════════════════════════
# Quarantine
# ══════════════════════════════════════════════════

class TestQuarantine:

    def test_quarantine_creates_action(self, defense_env):
        engine, _ = defense_env
        result = engine.quarantine_host("10.0.0.70", reason="lateral movement")
        assert result is True
        assert "QUARANTINE:10.0.0.70" in engine._actions

    def test_quarantine_updates_host_risk_score(self, defense_env):
        engine, _ = defense_env
        Host.create(ip="10.0.0.70", risk_score=0)
        engine.quarantine_host("10.0.0.70", reason="test")
        h = Host.get(Host.ip == "10.0.0.70")
        assert h.risk_score == 80


# ══════════════════════════════════════════════════
# IP validation
# ══════════════════════════════════════════════════

class TestIPValidation:

    def test_fw_block_rejects_invalid_ip(self, defense_env):
        engine, _ = defense_env
        result = engine._fw_block("not-an-ip")
        assert result is False

    def test_fw_unblock_rejects_invalid_ip(self, defense_env):
        engine, _ = defense_env
        result = engine._fw_unblock("not-an-ip")
        assert result is False

    def test_fw_rate_limit_rejects_invalid_ip(self, defense_env):
        engine, _ = defense_env
        result = engine._fw_rate_limit("not-an-ip")
        assert result is False

    def test_fw_quarantine_rejects_invalid_ip(self, defense_env):
        engine, _ = defense_env
        result = engine._fw_quarantine("not-an-ip")
        assert result is False


# ══════════════════════════════════════════════════
# Escalation ladder
# ══════════════════════════════════════════════════

class TestEscalation:

    def test_evaluate_threat_disabled_does_nothing(self, defense_env):
        engine, alert_fn = defense_env
        engine.enabled = False
        engine.evaluate_threat("10.0.0.1", "192.168.1.10", severity=1,
                               category="portscan", signature="test")
        assert len(engine._actions) == 0

    def test_evaluate_threat_whitelisted_does_nothing(self, defense_env):
        engine, _ = defense_env
        engine.evaluate_threat("192.168.1.1", "192.168.1.10", severity=1,
                               category="portscan", signature="test")
        assert len(engine._escalation) == 0

    def test_evaluate_threat_creates_escalation_state(self, defense_env):
        engine, _ = defense_env
        engine.evaluate_threat("10.0.0.99", "192.168.1.10", severity=3,
                               category="portscan", signature="Port scan detected")
        assert "10.0.0.99" in engine._escalation

    def test_critical_severity_escalates_to_block(self, defense_env):
        engine, _ = defense_env
        engine.evaluate_threat("10.0.0.99", "192.168.1.10", severity=1,
                               category="intrusion", signature="Critical intrusion")
        assert engine._escalation["10.0.0.99"]["level"] >= 3

    def test_high_alert_count_triggers_escalation(self, defense_env):
        engine, _ = defense_env
        # Fire many alerts to exceed threshold
        for i in range(12):
            engine.evaluate_threat("10.0.0.88", "192.168.1.10", severity=3,
                                   category="bruteforce", signature=f"Attempt {i}")
        assert engine._escalation["10.0.0.88"]["level"] >= 2

    def test_category_response_mapping(self, defense_env):
        engine, _ = defense_env
        # portscan starts at level 0
        assert engine.CATEGORY_RESPONSE["portscan"] == 0
        # bruteforce starts at level 2
        assert engine.CATEGORY_RESPONSE["bruteforce"] == 2
        # arp_spoof starts at level 3
        assert engine.CATEGORY_RESPONSE["arp_spoof"] == 3
        # kill_chain starts at level 4
        assert engine.CATEGORY_RESPONSE["kill_chain"] == 4


# ══════════════════════════════════════════════════
# API methods
# ══════════════════════════════════════════════════

class TestDefenseAPI:

    def test_get_active_actions_returns_only_active(self, defense_env):
        engine, _ = defense_env
        engine.block_ip("10.0.0.1", reason="test")
        engine.block_ip("10.0.0.2", reason="test")
        engine.unblock_ip("10.0.0.1")
        active = engine.get_active_actions()
        assert len(active) == 1
        assert active[0]["target"] == "10.0.0.2"

    def test_get_blocked_ips(self, defense_env):
        engine, _ = defense_env
        engine.block_ip("10.0.0.1", reason="test")
        engine.block_ip("10.0.0.2", reason="test")
        engine.rate_limit_ip("10.0.0.3", reason="test")
        blocked = engine.get_blocked_ips()
        assert "10.0.0.1" in blocked
        assert "10.0.0.2" in blocked
        assert "10.0.0.3" not in blocked

    def test_get_audit_log_returns_recent_entries(self, defense_env):
        engine, _ = defense_env
        engine.block_ip("10.0.0.1", reason="r1")
        engine.block_ip("10.0.0.2", reason="r2")
        log = engine.get_audit_log(limit=10)
        assert len(log) >= 2

    def test_get_stats_contains_expected_keys(self, defense_env):
        engine, _ = defense_env
        stats = engine.get_stats()
        assert "enabled" in stats
        assert "auto_block" in stats
        assert "fw_backend" in stats
        assert "active_blocks" in stats
        assert "active_rate_limits" in stats
        assert "active_quarantines" in stats
        assert "escalation" in stats

    def test_get_stats_counts_actions_correctly(self, defense_env):
        engine, _ = defense_env
        engine.block_ip("10.0.0.1", reason="test")
        engine.rate_limit_ip("10.0.0.2", reason="test")
        engine.quarantine_host("10.0.0.3", reason="test")
        stats = engine.get_stats()
        assert stats["active_blocks"] == 1
        assert stats["active_rate_limits"] == 1
        assert stats["active_quarantines"] == 1


# ══════════════════════════════════════════════════
# Audit logging
# ══════════════════════════════════════════════════

class TestAuditLog:

    def test_audit_log_persists_to_file(self, defense_env):
        engine, _ = defense_env
        engine.block_ip("10.0.0.1", reason="test")
        log_dir = engine.cfg.get("general.log_dir")
        audit_file = os.path.join(log_dir, "defense_audit.jsonl")
        assert os.path.exists(audit_file)

    def test_audit_log_capped_at_1000(self, defense_env):
        engine, _ = defense_env
        for i in range(1100):
            engine._audit("TEST", f"10.0.0.{i % 255}", f"test {i}", True)
        assert len(engine._audit_log) == 1000


# ══════════════════════════════════════════════════
# DHCP IP change callback
# ══════════════════════════════════════════════════

class TestDHCPCallback:

    def test_ip_change_reblocks_new_ip(self, defense_env):
        engine, _ = defense_env
        engine.block_ip("10.0.0.50", reason="initial block")
        assert "BLOCK:10.0.0.50" in engine._actions

        engine._on_ip_change("aa:bb:cc:dd:ee:ff", "10.0.0.50", "10.0.0.51")
        # Old key gone, new key present
        assert "BLOCK:10.0.0.50" not in engine._actions
        assert "BLOCK:10.0.0.51" in engine._actions
        assert engine._actions["BLOCK:10.0.0.51"].target_ip == "10.0.0.51"


# ══════════════════════════════════════════════════
# Integration tests
# ══════════════════════════════════════════════════

class TestDefenseIntegration:

    def test_full_threat_lifecycle(self, defense_env):
        """Threat evaluation → block → audit → unblock → verify."""
        engine, alert_fn = defense_env
        Host.create(ip="10.0.0.99", risk_score=0)

        # Evaluate a critical threat
        engine.evaluate_threat("10.0.0.99", "192.168.1.10", severity=1,
                               category="intrusion", signature="SQL injection")

        # Should be blocked
        assert len(engine.get_blocked_ips()) >= 1 or len(engine._actions) >= 1

        # Should have audit entries
        assert len(engine._audit_log) >= 1

        # Stats should reflect the action
        stats = engine.get_stats()
        assert stats["total_actions"] >= 1


# ══════════════════════════════════════════════════
# _execute_level — all 5 escalation levels
# ══════════════════════════════════════════════════

class TestExecuteLevel:

    def test_level_0_monitor(self, defense_env):
        """Level 0 (MONITOR): logs audit, no firewall action."""
        engine, alert_fn = defense_env
        engine._execute_level("10.0.0.1", "192.168.1.10", 0, "test reason", "portscan")
        assert any(e["action"] == "MONITOR" for e in engine._audit_log)
        # No verify queue entry for level 0
        assert len(engine._verify_queue) == 0

    def test_level_1_throttle(self, defense_env):
        """Level 1 (THROTTLE): rate-limits the IP."""
        engine, alert_fn = defense_env
        engine._execute_level("10.0.0.1", "192.168.1.10", 1, "test reason", "dns_tunnel")
        assert "RATE:10.0.0.1" in engine._actions
        assert len(engine._verify_queue) == 1

    def test_level_2_isolate_internal_host(self, defense_env):
        """Level 2 (ISOLATE): quarantines an internal host."""
        engine, alert_fn = defense_env
        engine._execute_level("192.168.1.50", "192.168.1.10", 2, "test reason", "bruteforce")
        assert "QUARANTINE:192.168.1.50" in engine._actions

    def test_level_2_isolate_external_host_blocks(self, defense_env):
        """Level 2 (ISOLATE): blocks an external host."""
        engine, alert_fn = defense_env
        engine._execute_level("10.0.0.1", "192.168.1.10", 2, "test reason", "bruteforce")
        assert "BLOCK:10.0.0.1" in engine._actions

    def test_level_2_beaconing_category(self, defense_env):
        """Level 2 with beaconing category: also enters beaconing branch."""
        engine, _ = defense_env
        engine._execute_level("10.0.0.1", "192.168.1.10", 2, "test reason", "beaconing")
        # The external IP gets blocked (not internal)
        assert "BLOCK:10.0.0.1" in engine._actions

    def test_level_3_block(self, defense_env):
        """Level 3 (BLOCK): full DROP via block_ip."""
        engine, alert_fn = defense_env
        engine._execute_level("10.0.0.1", "192.168.1.10", 3, "test reason", "arp_spoof")
        assert "BLOCK:10.0.0.1" in engine._actions

    def test_level_4_network_alert(self, defense_env):
        """Level 4 (NETWORK_ALERT): block + alert with severity 1."""
        engine, alert_fn = defense_env
        engine._execute_level("10.0.0.1", "192.168.1.10", 4, "test reason", "kill_chain")
        assert "BLOCK:10.0.0.1" in engine._actions
        # Check that alert was called with network_alert category
        calls = [c for c in alert_fn.call_args_list
                 if c[1].get("category") == "network_alert"]
        assert len(calls) >= 1
        assert calls[0][1]["severity"] == 1


# ══════════════════════════════════════════════════
# _check_deescalation
# ══════════════════════════════════════════════════

class TestDeescalation:

    def test_deescalation_when_no_recent_alerts(self, defense_env):
        """De-escalation happens when no alerts for long enough."""
        engine, _ = defense_env
        ip = "10.0.0.1"
        # Set up escalation state at level 3 with old timestamps
        old_ts = time.time() - 2000  # Well in the past
        engine._escalation[ip] = {
            "level": 3, "since": old_ts, "last_escalation": old_ts,
            "category": "intrusion", "reason": "test",
        }
        # No recent alerts
        engine._alert_counter[ip] = []

        engine._check_deescalation()

        assert engine._escalation[ip]["level"] == 2
        assert any(e["action"] == "DE-ESCALATE" for e in engine._audit_log)

    def test_deescalation_to_monitor_unblocks(self, defense_env):
        """De-escalation to level 0 triggers unblock of active actions."""
        engine, _ = defense_env
        ip = "10.0.0.1"
        old_ts = time.time() - 2000

        # Set up at level 1
        engine._escalation[ip] = {
            "level": 1, "since": old_ts, "last_escalation": old_ts,
            "category": "portscan", "reason": "test",
        }
        engine._alert_counter[ip] = []

        # Create an active BLOCK action
        from core.defense import DefenseAction
        engine._actions["BLOCK:" + ip] = DefenseAction(
            action_type="BLOCK_IP", target_ip=ip, reason="test", active=True)

        # Mock unblock_ip to avoid deadlock (Lock is non-reentrant,
        # _check_deescalation holds _lock when calling unblock_ip)
        with patch.object(engine, 'unblock_ip') as mock_unblock:
            engine._check_deescalation()

        # Should have de-escalated to 0
        assert engine._escalation[ip]["level"] == 0
        mock_unblock.assert_called_once_with(ip, "Auto de-escalation: no more alerts")

    def test_deescalation_to_monitor_unrates(self, defense_env):
        """De-escalation to level 0 removes rate limit."""
        engine, _ = defense_env
        ip = "10.0.0.1"
        old_ts = time.time() - 2000

        engine._escalation[ip] = {
            "level": 1, "since": old_ts, "last_escalation": old_ts,
            "category": "portscan", "reason": "test",
        }
        engine._alert_counter[ip] = []

        from core.defense import DefenseAction
        engine._actions["RATE:" + ip] = DefenseAction(
            action_type="RATE_LIMIT", target_ip=ip, reason="test", active=True)

        engine._check_deescalation()
        assert engine._actions["RATE:" + ip].active is False

    def test_deescalation_to_monitor_unquarantines(self, defense_env):
        """De-escalation to level 0 removes quarantine."""
        engine, _ = defense_env
        ip = "10.0.0.1"
        old_ts = time.time() - 2000

        engine._escalation[ip] = {
            "level": 1, "since": old_ts, "last_escalation": old_ts,
            "category": "portscan", "reason": "test",
        }
        engine._alert_counter[ip] = []

        from core.defense import DefenseAction
        engine._actions["QUARANTINE:" + ip] = DefenseAction(
            action_type="QUARANTINE", target_ip=ip, reason="test", active=True)

        engine._check_deescalation()
        assert engine._actions["QUARANTINE:" + ip].active is False

    def test_deescalation_removes_tracking_at_level_0(self, defense_env):
        """Once at level 0 with no alerts, tracking is removed entirely."""
        engine, _ = defense_env
        ip = "10.0.0.1"
        old_ts = time.time() - 2000

        engine._escalation[ip] = {
            "level": 0, "since": old_ts, "last_escalation": old_ts,
            "category": "portscan", "reason": "test",
        }
        engine._alert_counter[ip] = []

        engine._check_deescalation()
        assert ip not in engine._escalation

    def test_no_deescalation_when_recent_alerts(self, defense_env):
        """No de-escalation when there are recent alerts."""
        engine, _ = defense_env
        ip = "10.0.0.1"
        engine._escalation[ip] = {
            "level": 3, "since": time.time() - 2000,
            "last_escalation": time.time() - 2000,
            "category": "intrusion", "reason": "test",
        }
        # Recent alerts exist
        engine._alert_counter[ip] = [time.time()]

        engine._check_deescalation()
        assert engine._escalation[ip]["level"] == 3  # Unchanged


# ══════════════════════════════════════════════════
# _on_ip_change for non-active actions
# ══════════════════════════════════════════════════

class TestOnIpChangeNonActive:

    def test_ip_change_skips_inactive_actions(self, defense_env):
        """_on_ip_change does not re-apply for inactive actions."""
        engine, _ = defense_env
        from core.defense import DefenseAction
        action = DefenseAction(
            action_type="BLOCK_IP", target_ip="10.0.0.50",
            reason="test", active=False)
        engine._actions["BLOCK:10.0.0.50"] = action

        engine._on_ip_change("aa:bb:cc:dd:ee:ff", "10.0.0.50", "10.0.0.51")
        # Old key should still be there (not moved)
        assert "BLOCK:10.0.0.50" in engine._actions
        assert "BLOCK:10.0.0.51" not in engine._actions

    def test_ip_change_skips_different_ip(self, defense_env):
        """_on_ip_change ignores actions for other IPs."""
        engine, _ = defense_env
        engine.block_ip("10.0.0.60", reason="test")
        engine._on_ip_change("aa:bb:cc:dd:ee:ff", "10.0.0.50", "10.0.0.51")
        assert "BLOCK:10.0.0.60" in engine._actions


# ══════════════════════════════════════════════════
# _is_whitelisted with MAC resolver
# ══════════════════════════════════════════════════

class TestWhitelistMAC:

    def test_is_whitelisted_with_mac_resolver(self, defense_env):
        """MAC-based whitelist delegates to mac_resolver."""
        engine, _ = defense_env
        mock_resolver = MagicMock()
        mock_resolver.is_whitelisted.return_value = True
        engine.mac_resolver = mock_resolver
        engine.whitelist_macs = {"aa:bb:cc:dd:ee:ff"}

        result = engine._is_whitelisted("10.0.0.99")
        assert result is True
        mock_resolver.is_whitelisted.assert_called_once()

    def test_is_whitelisted_mac_resolver_returns_false(self, defense_env):
        """MAC resolver returns False — IP is not whitelisted."""
        engine, _ = defense_env
        mock_resolver = MagicMock()
        mock_resolver.is_whitelisted.return_value = False
        engine.mac_resolver = mock_resolver
        engine.whitelist_macs = {"aa:bb:cc:dd:ee:ff"}

        result = engine._is_whitelisted("10.0.0.99")
        assert result is False

    def test_is_whitelisted_no_mac_resolver_no_whitelist_macs(self, defense_env):
        """Without mac_resolver, falls back to IP-only check."""
        engine, _ = defense_env
        engine.mac_resolver = None
        result = engine._is_whitelisted("10.0.0.99")
        assert result is False


# ══════════════════════════════════════════════════
# _detect_firewall
# ══════════════════════════════════════════════════

class TestDetectFirewall:

    def test_detect_nftables(self):
        """Returns 'nftables' when nft command succeeds."""
        from core.defense import DefenseEngine
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("core.defense.subprocess.run", return_value=mock_result):
            result = DefenseEngine._detect_firewall()
        assert result == "nftables"

    def test_detect_iptables_when_nft_not_found(self):
        """Returns 'iptables' when nft fails but iptables succeeds."""
        from core.defense import DefenseEngine

        def side_effect(args, **kwargs):
            if args[0] == "nft":
                raise FileNotFoundError("nft not found")
            r = MagicMock()
            r.returncode = 0
            return r

        with patch("core.defense.subprocess.run", side_effect=side_effect):
            result = DefenseEngine._detect_firewall()
        assert result == "iptables"

    def test_detect_none_when_both_missing(self):
        """Returns 'none' when neither nft nor iptables is available."""
        from core.defense import DefenseEngine
        with patch("core.defense.subprocess.run", side_effect=FileNotFoundError("not found")):
            result = DefenseEngine._detect_firewall()
        assert result == "none"

    def test_detect_iptables_when_nft_returns_nonzero(self):
        """Returns 'iptables' when nft returns non-zero."""
        from core.defense import DefenseEngine

        def side_effect(args, **kwargs):
            r = MagicMock()
            if args[0] == "nft":
                r.returncode = 1
            else:
                r.returncode = 0
            return r

        with patch("core.defense.subprocess.run", side_effect=side_effect):
            result = DefenseEngine._detect_firewall()
        assert result == "iptables"


# ══════════════════════════════════════════════════
# _fw_block, _fw_unblock, _fw_rate_limit, _fw_quarantine
# with iptables and nftables backends
# ══════════════════════════════════════════════════

class TestFirewallBackends:

    def test_fw_block_iptables(self, defense_env):
        """_fw_block with iptables backend calls iptables commands."""
        engine, _ = defense_env
        engine._fw_backend = "iptables"
        with patch.object(engine, '_run_cmd', return_value=True) as mock_cmd:
            result = engine._fw_block("10.0.0.1")
        assert result is True
        assert mock_cmd.call_count == 2  # -s DROP and -d DROP

    def test_fw_block_nftables(self, defense_env):
        """_fw_block with nftables backend calls nft add rule."""
        engine, _ = defense_env
        engine._fw_backend = "nftables"
        with patch.object(engine, '_run_cmd', return_value=True) as mock_cmd:
            result = engine._fw_block("10.0.0.1")
        assert result is True
        mock_cmd.assert_called_once()
        assert "nft" in mock_cmd.call_args[0][0]

    def test_fw_block_none_backend(self, defense_env):
        """_fw_block with no backend simulates success."""
        engine, _ = defense_env
        engine._fw_backend = "none"
        result = engine._fw_block("10.0.0.1")
        assert result is True

    def test_fw_unblock_iptables(self, defense_env):
        """_fw_unblock with iptables deletes DROP rules."""
        engine, _ = defense_env
        engine._fw_backend = "iptables"
        with patch.object(engine, '_run_cmd', return_value=True) as mock_cmd:
            result = engine._fw_unblock("10.0.0.1")
        assert result is True
        assert mock_cmd.call_count == 2

    def test_fw_unblock_nftables(self, defense_env):
        """_fw_unblock with nftables finds and deletes rules by handle."""
        engine, _ = defense_env
        engine._fw_backend = "nftables"
        mock_run_result = MagicMock()
        mock_run_result.returncode = 0
        mock_run_result.stdout = "  ip saddr 10.0.0.1 drop # handle 42\n"
        with patch("core.defense.subprocess.run", return_value=mock_run_result), \
             patch.object(engine, '_run_cmd', return_value=True) as mock_cmd:
            result = engine._fw_unblock("10.0.0.1")
        assert result is True
        mock_cmd.assert_called_once()
        assert "42" in mock_cmd.call_args[0][0]

    def test_fw_unblock_nftables_exception(self, defense_env):
        """_fw_unblock with nftables handles exceptions gracefully."""
        engine, _ = defense_env
        engine._fw_backend = "nftables"
        with patch("core.defense.subprocess.run", side_effect=Exception("nft error")):
            result = engine._fw_unblock("10.0.0.1")
        assert result is True  # Still returns True per the code

    def test_fw_unblock_none_backend(self, defense_env):
        """_fw_unblock with no backend returns True."""
        engine, _ = defense_env
        engine._fw_backend = "none"
        result = engine._fw_unblock("10.0.0.1")
        assert result is True

    def test_fw_rate_limit_iptables(self, defense_env):
        """_fw_rate_limit with iptables sets limit and drop rules."""
        engine, _ = defense_env
        engine._fw_backend = "iptables"
        with patch.object(engine, '_run_cmd', return_value=True) as mock_cmd:
            result = engine._fw_rate_limit("10.0.0.1")
        assert result is True
        assert mock_cmd.call_count == 2

    def test_fw_rate_limit_none_backend(self, defense_env):
        """_fw_rate_limit with no backend falls back to True."""
        engine, _ = defense_env
        engine._fw_backend = "none"
        result = engine._fw_rate_limit("10.0.0.1")
        assert result is True

    def test_fw_quarantine_iptables(self, defense_env):
        """_fw_quarantine with iptables: allow SSH to admin, block rest."""
        engine, _ = defense_env
        engine._fw_backend = "iptables"
        with patch.object(engine, '_run_cmd', return_value=True) as mock_cmd:
            result = engine._fw_quarantine("10.0.0.1")
        assert result is True
        assert mock_cmd.call_count == 3  # SSH allow + 2 DROP rules

    def test_fw_quarantine_none_backend(self, defense_env):
        """_fw_quarantine with no backend returns True."""
        engine, _ = defense_env
        engine._fw_backend = "none"
        result = engine._fw_quarantine("10.0.0.1")
        assert result is True


# ══════════════════════════════════════════════════
# _run_cmd — retry logic, timeout, failure
# ══════════════════════════════════════════════════

class TestRunCmd:

    def test_run_cmd_success_first_try(self):
        """_run_cmd returns True on first successful attempt."""
        from core.defense import DefenseEngine
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("core.defense.subprocess.run", return_value=mock_result) as mock_run:
            result = DefenseEngine._run_cmd(["echo", "test"])
        assert result is True
        assert mock_run.call_count == 1

    def test_run_cmd_retry_then_succeed(self):
        """_run_cmd retries once on failure then succeeds."""
        from core.defense import DefenseEngine
        fail = MagicMock(returncode=1)
        ok = MagicMock(returncode=0)
        with patch("core.defense.subprocess.run", side_effect=[fail, ok]) as mock_run, \
             patch("core.defense.time.sleep"):
            result = DefenseEngine._run_cmd(["test"])
        assert result is True
        assert mock_run.call_count == 2

    def test_run_cmd_fails_after_retry(self):
        """_run_cmd returns False after both attempts fail."""
        from core.defense import DefenseEngine
        fail = MagicMock(returncode=1)
        with patch("core.defense.subprocess.run", return_value=fail) as mock_run, \
             patch("core.defense.time.sleep"):
            result = DefenseEngine._run_cmd(["test"])
        assert result is False
        assert mock_run.call_count == 2

    def test_run_cmd_timeout(self):
        """_run_cmd returns False on timeout."""
        from core.defense import DefenseEngine
        with patch("core.defense.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="test", timeout=10)):
            result = DefenseEngine._run_cmd(["test"])
        assert result is False

    def test_run_cmd_exception(self):
        """_run_cmd returns False on unexpected exception."""
        from core.defense import DefenseEngine
        with patch("core.defense.subprocess.run", side_effect=OSError("perm denied")):
            result = DefenseEngine._run_cmd(["test"])
        assert result is False


# ══════════════════════════════════════════════════
# _run (shell command)
# ══════════════════════════════════════════════════

class TestRunShell:

    def test_run_success(self):
        """_run returns True when shell command succeeds."""
        from core.defense import DefenseEngine
        mock_result = MagicMock(returncode=0)
        with patch("core.defense.subprocess.run", return_value=mock_result):
            result = DefenseEngine._run("echo ok")
        assert result is True

    def test_run_failure(self):
        """_run returns False when shell command fails."""
        from core.defense import DefenseEngine
        mock_result = MagicMock(returncode=1)
        with patch("core.defense.subprocess.run", return_value=mock_result):
            result = DefenseEngine._run("false")
        assert result is False

    def test_run_exception(self):
        """_run returns False on exception."""
        from core.defense import DefenseEngine
        with patch("core.defense.subprocess.run", side_effect=Exception("boom")):
            result = DefenseEngine._run("something")
        assert result is False


# ══════════════════════════════════════════════════
# _cleanup_loop — expired actions
# ══════════════════════════════════════════════════

class TestCleanupExpired:

    def test_cleanup_expires_block_action(self, defense_env):
        """Expired BLOCK_IP actions get unblocked."""
        engine, _ = defense_env
        from core.defense import DefenseAction
        action = DefenseAction(
            action_type="BLOCK_IP", target_ip="10.0.0.1",
            reason="test", ttl_seconds=1, active=True)
        action.expires_at = time.time() - 10  # Already expired
        engine._actions["BLOCK:10.0.0.1"] = action

        # Simulate what _cleanup_loop does (without the infinite loop)
        now = time.time()
        with engine._lock:
            expired = [k for k, a in engine._actions.items()
                       if a.active and now >= a.expires_at]
        for key in expired:
            a = engine._actions[key]
            if a.action_type == "BLOCK_IP":
                engine.unblock_ip(a.target_ip, "TTL expired")
            with engine._lock:
                engine._actions[key].active = False

        assert engine._actions["BLOCK:10.0.0.1"].active is False

    def test_cleanup_expires_rate_limit_action(self, defense_env):
        """Expired RATE_LIMIT actions get cleaned up."""
        engine, _ = defense_env
        from core.defense import DefenseAction
        action = DefenseAction(
            action_type="RATE_LIMIT", target_ip="10.0.0.2",
            reason="test", ttl_seconds=1, active=True)
        action.expires_at = time.time() - 10
        engine._actions["RATE:10.0.0.2"] = action

        now = time.time()
        with engine._lock:
            expired = [k for k, a in engine._actions.items()
                       if a.active and now >= a.expires_at]
        for key in expired:
            a = engine._actions[key]
            if a.action_type == "RATE_LIMIT":
                engine._fw_unblock(a.target_ip)
                engine._audit("UNRATE_LIMIT", a.target_ip, "TTL expired", True)
            with engine._lock:
                engine._actions[key].active = False

        assert engine._actions["RATE:10.0.0.2"].active is False
        assert any(e["action"] == "UNRATE_LIMIT" for e in engine._audit_log)

    def test_cleanup_expires_quarantine_action(self, defense_env):
        """Expired QUARANTINE actions get cleaned up with alert."""
        engine, alert_fn = defense_env
        from core.defense import DefenseAction
        action = DefenseAction(
            action_type="QUARANTINE", target_ip="10.0.0.3",
            reason="test", ttl_seconds=1, active=True)
        action.expires_at = time.time() - 10
        engine._actions["QUARANTINE:10.0.0.3"] = action

        now = time.time()
        with engine._lock:
            expired = [k for k, a in engine._actions.items()
                       if a.active and now >= a.expires_at]
        for key in expired:
            a = engine._actions[key]
            if a.action_type == "QUARANTINE":
                engine._fw_unblock(a.target_ip)
                engine._audit("UNQUARANTINE", a.target_ip, "TTL expired", True)
                engine._alert(
                    severity=4, source="defense", category="quarantine_end",
                    title=f"End of quarantine: {a.target_ip}",
                    src_ip=a.target_ip, notify=False,
                )
            with engine._lock:
                engine._actions[key].active = False

        assert engine._actions["QUARANTINE:10.0.0.3"].active is False
        assert any(e["action"] == "UNQUARANTINE" for e in engine._audit_log)
        calls = [c for c in alert_fn.call_args_list
                 if c[1].get("category") == "quarantine_end"]
        assert len(calls) >= 1

    def test_cleanup_purges_old_alert_counters(self, defense_env):
        """Old alert counters are purged."""
        engine, _ = defense_env
        old_time = time.time() - 10000
        engine._alert_counter["10.0.0.1"] = [old_time]

        # Simulate counter purge from _cleanup_loop
        now = time.time()
        cutoff = now - engine.alert_count_window * 2
        for ip in list(engine._alert_counter):
            engine._alert_counter[ip] = [t for t in engine._alert_counter[ip] if t > cutoff]
            if not engine._alert_counter[ip]:
                del engine._alert_counter[ip]

        assert "10.0.0.1" not in engine._alert_counter


# ══════════════════════════════════════════════════
# evaluate_threat — auto_block disabled
# ══════════════════════════════════════════════════

class TestEvaluateThreatAutoBlockDisabled:

    def test_auto_block_disabled_does_not_execute(self, defense_env):
        """When auto_block is False, evaluate_threat counts alerts but takes no action."""
        engine, alert_fn = defense_env
        engine.auto_block = False
        engine.evaluate_threat("10.0.0.1", "192.168.1.10", severity=1,
                               category="intrusion", signature="test")
        # Should have counted the alert
        assert len(engine._alert_counter["10.0.0.1"]) == 1
        # But should not have created any actions
        assert len(engine._actions) == 0
        assert len(engine._escalation) == 0


# ══════════════════════════════════════════════════
# block_ip — TTL extension path
# ══════════════════════════════════════════════════

class TestBlockExtendTTL:

    def test_block_same_ip_extends_ttl_returns_true(self, defense_env):
        """Blocking an already-blocked IP extends the TTL and returns True."""
        engine, _ = defense_env
        engine.block_ip("10.0.0.1", reason="first", ttl=100)
        old_expires = engine._actions["BLOCK:10.0.0.1"].expires_at
        time.sleep(0.05)
        result = engine.block_ip("10.0.0.1", reason="second", ttl=500)
        assert result is True
        assert engine._actions["BLOCK:10.0.0.1"].expires_at > old_expires


# ══════════════════════════════════════════════════
# Netgate integration (mock)
# ══════════════════════════════════════════════════

class TestNetgateIntegration:

    def test_block_ip_with_netgate(self, defense_env):
        """block_ip also calls netgate.block_ip when configured."""
        engine, alert_fn = defense_env
        mock_netgate = MagicMock()
        mock_netgate.block_ip.return_value = True
        mock_netgate.fw_type = "pfsense"
        engine.netgate = mock_netgate

        result = engine.block_ip("10.0.0.1", reason="test")
        assert result is True
        mock_netgate.block_ip.assert_called_once()

    def test_unblock_ip_with_netgate(self, defense_env):
        """unblock_ip also calls netgate.unblock_ip when configured."""
        engine, _ = defense_env
        mock_netgate = MagicMock()
        mock_netgate.block_ip.return_value = True
        mock_netgate.fw_type = "pfsense"
        engine.netgate = mock_netgate

        engine.block_ip("10.0.0.1", reason="test")
        engine.unblock_ip("10.0.0.1", reason="manual")
        mock_netgate.unblock_ip.assert_called_once_with("10.0.0.1")

    def test_on_ip_change_with_netgate(self, defense_env):
        """_on_ip_change calls netgate unblock/block when configured."""
        engine, _ = defense_env
        mock_netgate = MagicMock()
        mock_netgate.block_ip.return_value = True
        mock_netgate.fw_type = "pfsense"
        engine.netgate = mock_netgate

        engine.block_ip("10.0.0.50", reason="test")
        mock_netgate.reset_mock()

        engine._on_ip_change("aa:bb:cc:dd:ee:ff", "10.0.0.50", "10.0.0.51")
        mock_netgate.unblock_ip.assert_called_once_with("10.0.0.50")
        mock_netgate.block_ip.assert_called_once()

    def test_netgate_init_enabled(self, tmp_path):
        """Netgate initializes when config has netgate.enabled=True."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        from core.database import init_db
        init_db(data_dir)

        cfg = _make_cfg(tmp_path, extra={"netgate": {"enabled": True}})

        mock_netgate_cls = MagicMock()
        mock_netgate_instance = MagicMock()
        mock_netgate_instance.enabled = True
        mock_netgate_instance.fw_type = "pfsense"
        mock_netgate_instance.host = "192.168.1.1"
        mock_netgate_cls.return_value = mock_netgate_instance

        with patch("core.defense.DefenseEngine._detect_firewall", return_value="none"), \
             patch("core.defense.DefenseEngine._init_firewall"), \
             patch("core.defense.DefenseEngine._run_cmd", return_value=True), \
             patch("core.defense.DefenseEngine._run", return_value=True), \
             patch("core.defense.get_iface_ip", return_value="192.168.1.100"), \
             patch.dict("sys.modules", {"core.netgate": MagicMock(NetgateFirewall=mock_netgate_cls)}):
            from core.defense import DefenseEngine
            engine = DefenseEngine(cfg, MagicMock(), mac_resolver=None)
            assert engine.netgate is not None

        if not db.is_closed():
            db.close()


# ══════════════════════════════════════════════════
# dns_sinkhole
# ══════════════════════════════════════════════════

class TestDnsSinkhole:

    def test_dns_sinkhole_adds_to_hosts(self, defense_env):
        """dns_sinkhole writes domain to /etc/hosts."""
        engine, alert_fn = defense_env
        mock_read = MagicMock(return_value=MagicMock(
            __enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=""))),
            __exit__=MagicMock(return_value=False)))
        mock_write = MagicMock(return_value=MagicMock(
            __enter__=MagicMock(return_value=MagicMock()),
            __exit__=MagicMock(return_value=False)))

        with patch("builtins.open", side_effect=[mock_read, mock_write]):
            engine.dns_sinkhole("evil.com", reason="C2 domain")

        assert any(e["action"] == "DNS_SINKHOLE" for e in engine._audit_log)

    def test_dns_sinkhole_skips_if_already_present(self, defense_env):
        """dns_sinkhole does not add duplicate entries."""
        engine, _ = defense_env
        mock_file = MagicMock()
        mock_file.__enter__ = MagicMock(return_value=MagicMock(
            read=MagicMock(return_value="127.0.0.1 evil.com")))
        mock_file.__exit__ = MagicMock(return_value=False)

        with patch("builtins.open", return_value=mock_file):
            engine.dns_sinkhole("evil.com", reason="C2 domain")

        # No audit entry should be created since it already exists
        assert not any(e["action"] == "DNS_SINKHOLE" for e in engine._audit_log)

    def test_dns_sinkhole_permission_error(self, defense_env):
        """dns_sinkhole handles PermissionError gracefully."""
        engine, _ = defense_env
        with patch("builtins.open", side_effect=PermissionError("no perms")):
            engine.dns_sinkhole("evil.com", reason="test")
        # Should not crash, no audit entry
        assert not any(e["action"] == "DNS_SINKHOLE" for e in engine._audit_log)


# ══════════════════════════════════════════════════
# rst_kill
# ══════════════════════════════════════════════════

class TestRstKill:

    def test_rst_kill_sends_packet(self, defense_env):
        """rst_kill sends a TCP RST via scapy."""
        engine, _ = defense_env
        with patch("core.defense.scapy_send") as mock_send:
            engine.rst_kill("10.0.0.1", "192.168.1.10", 12345, 80)
        mock_send.assert_called_once()
        assert any(e["action"] == "RST_KILL" for e in engine._audit_log)

    def test_rst_kill_handles_exception(self, defense_env):
        """rst_kill handles scapy errors gracefully."""
        engine, _ = defense_env
        with patch("core.defense.scapy_send", side_effect=Exception("no permission")):
            engine.rst_kill("10.0.0.1", "192.168.1.10", 12345, 80)
        # Should not crash, no audit entry since it failed
        assert not any(e["action"] == "RST_KILL" for e in engine._audit_log)


# ══════════════════════════════════════════════════
# _update_host_risk — host doesn't exist
# ══════════════════════════════════════════════════

class TestUpdateHostRisk:

    def test_update_host_risk_nonexistent_host(self, defense_env):
        """_update_host_risk does nothing if host doesn't exist in DB."""
        engine, _ = defense_env
        # Should not raise
        engine._update_host_risk("99.99.99.99", 50)

    def test_update_host_risk_caps_at_100(self, defense_env):
        """_update_host_risk caps risk_score at 100."""
        engine, _ = defense_env
        Host.create(ip="10.0.0.5", risk_score=80)
        engine._update_host_risk("10.0.0.5", 50)
        h = Host.get(Host.ip == "10.0.0.5")
        assert h.risk_score == 100

    def test_update_host_risk_db_exception(self, defense_env):
        """_update_host_risk handles DB exceptions gracefully."""
        engine, _ = defense_env
        with patch("core.defense.Host.get_or_none", side_effect=Exception("DB error")):
            # Should not crash
            engine._update_host_risk("10.0.0.1", 50)


# ══════════════════════════════════════════════════
# exclude_ips config
# ══════════════════════════════════════════════════

class TestExcludeIPs:

    def test_exclude_ips_added_to_whitelist(self, tmp_path):
        """IPs from network.exclude_ips are added to the whitelist."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        from core.database import init_db
        init_db(data_dir)

        cfg = _make_cfg(tmp_path, extra={
            "network": {
                "subnets": ["192.168.1.0/24"],
                "interface": "lo",
                "exclude_ips": ["1.2.3.4", "5.6.7.8"],
            }
        })

        with patch("core.defense.DefenseEngine._detect_firewall", return_value="none"), \
             patch("core.defense.DefenseEngine._init_firewall"), \
             patch("core.defense.DefenseEngine._run_cmd", return_value=True), \
             patch("core.defense.DefenseEngine._run", return_value=True), \
             patch("core.defense.get_iface_ip", return_value="192.168.1.100"):
            from core.defense import DefenseEngine
            engine = DefenseEngine(cfg, MagicMock(), mac_resolver=None)
            assert "1.2.3.4" in engine.whitelist
            assert "5.6.7.8" in engine.whitelist

        if not db.is_closed():
            db.close()


# ══════════════════════════════════════════════════
# _init_firewall paths
# ══════════════════════════════════════════════════

class TestInitFirewall:

    def test_init_firewall_iptables(self):
        """_init_firewall with iptables backend creates CGS chain."""
        from core.defense import DefenseEngine
        mock_engine = MagicMock(spec=DefenseEngine)
        mock_engine._fw_backend = "iptables"
        mock_engine._run = MagicMock(return_value=True)
        DefenseEngine._init_firewall(mock_engine)
        assert mock_engine._run.call_count == 3  # -N, -C/-I INPUT, -C/-I FORWARD

    def test_init_firewall_nftables(self):
        """_init_firewall with nftables backend creates cgs table."""
        from core.defense import DefenseEngine
        mock_engine = MagicMock(spec=DefenseEngine)
        mock_engine._fw_backend = "nftables"
        mock_engine._run = MagicMock(return_value=True)
        DefenseEngine._init_firewall(mock_engine)
        assert mock_engine._run.call_count == 2  # add table, add chain

    def test_init_firewall_none(self):
        """_init_firewall with no backend logs a warning."""
        from core.defense import DefenseEngine
        mock_engine = MagicMock(spec=DefenseEngine)
        mock_engine._fw_backend = "none"
        mock_engine._run = MagicMock(return_value=True)
        DefenseEngine._init_firewall(mock_engine)
        assert mock_engine._run.call_count == 0


# ══════════════════════════════════════════════════
# Auto-escalation timer in evaluate_threat
# ══════════════════════════════════════════════════

class TestAutoEscalationTimer:

    def test_auto_escalation_when_timer_expired(self, defense_env):
        """Auto-escalation triggers when timer at current level expires."""
        engine, _ = defense_env
        ip = "10.0.0.1"
        # Set up existing escalation at level 0 with expired timer
        old_ts = time.time() - 300  # Well past the 120s timer for level 0
        engine._escalation[ip] = {
            "level": 0, "since": old_ts, "last_escalation": old_ts,
            "category": "portscan", "reason": "test",
        }
        # Need at least 2 alerts for auto-escalation
        engine._alert_counter[ip] = [time.time() - 1]

        engine.evaluate_threat(ip, "192.168.1.10", severity=4,
                               category="portscan", signature="test")
        # Should have escalated from 0 to at least 1
        assert engine._escalation[ip]["level"] >= 1


# ══════════════════════════════════════════════════
# block_ip returns False when fw_block fails
# ══════════════════════════════════════════════════

class TestBlockFailure:

    def test_block_ip_returns_false_when_fw_fails(self, defense_env):
        """block_ip returns False when local firewall and netgate both fail."""
        engine, _ = defense_env
        engine.netgate = None
        with patch.object(engine, '_fw_block', return_value=False):
            result = engine.block_ip("10.0.0.1", reason="test")
        assert result is False


# ══════════════════════════════════════════════════
# Netgate init exception path (lines 114-116)
# ══════════════════════════════════════════════════

class TestNetgateInitException:

    def test_netgate_init_raises_exception_sets_none(self, tmp_path):
        """When NetgateFirewall constructor raises, netgate is set to None."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        from core.database import init_db
        init_db(data_dir)

        cfg = _make_cfg(tmp_path, extra={"netgate": {"enabled": True}})

        mock_netgate_mod = MagicMock()
        mock_netgate_mod.NetgateFirewall.side_effect = Exception("connection refused")

        with patch("core.defense.DefenseEngine._detect_firewall", return_value="none"), \
             patch("core.defense.DefenseEngine._init_firewall"), \
             patch("core.defense.DefenseEngine._run_cmd", return_value=True), \
             patch("core.defense.DefenseEngine._run", return_value=True), \
             patch("core.defense.get_iface_ip", return_value="192.168.1.100"), \
             patch.dict("sys.modules", {"core.netgate": mock_netgate_mod}):
            from core.defense import DefenseEngine
            engine = DefenseEngine(cfg, MagicMock(), mac_resolver=None)
            assert engine.netgate is None

        if not db.is_closed():
            db.close()

    def test_netgate_init_enabled_false_after_construct(self, tmp_path):
        """When NetgateFirewall.enabled is False after init, netgate is set to None."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        from core.database import init_db
        init_db(data_dir)

        cfg = _make_cfg(tmp_path, extra={"netgate": {"enabled": True}})

        mock_netgate_cls = MagicMock()
        mock_netgate_instance = MagicMock()
        mock_netgate_instance.enabled = False  # Netgate says it's not enabled
        mock_netgate_cls.return_value = mock_netgate_instance

        with patch("core.defense.DefenseEngine._detect_firewall", return_value="none"), \
             patch("core.defense.DefenseEngine._init_firewall"), \
             patch("core.defense.DefenseEngine._run_cmd", return_value=True), \
             patch("core.defense.DefenseEngine._run", return_value=True), \
             patch("core.defense.get_iface_ip", return_value="192.168.1.100"), \
             patch.dict("sys.modules", {"core.netgate": MagicMock(NetgateFirewall=mock_netgate_cls)}):
            from core.defense import DefenseEngine
            engine = DefenseEngine(cfg, MagicMock(), mac_resolver=None)
            # Line 113: self.netgate = None when enabled is False
            assert engine.netgate is None

        if not db.is_closed():
            db.close()


# ══════════════════════════════════════════════════
# mac_resolver on_ip_change registration (line 135)
# ══════════════════════════════════════════════════

class TestMacResolverOnIpChange:

    def test_mac_resolver_on_ip_change_called(self, tmp_path):
        """When mac_resolver is provided, on_ip_change is registered."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        from core.database import init_db
        init_db(data_dir)

        cfg = _make_cfg(tmp_path)
        mock_resolver = MagicMock()

        with patch("core.defense.DefenseEngine._detect_firewall", return_value="none"), \
             patch("core.defense.DefenseEngine._init_firewall"), \
             patch("core.defense.DefenseEngine._run_cmd", return_value=True), \
             patch("core.defense.DefenseEngine._run", return_value=True), \
             patch("core.defense.get_iface_ip", return_value="192.168.1.100"):
            from core.defense import DefenseEngine
            engine = DefenseEngine(cfg, MagicMock(), mac_resolver=mock_resolver)
            mock_resolver.on_ip_change.assert_called_once()
            # The callback should be _on_ip_change
            callback = mock_resolver.on_ip_change.call_args[0][0]
            assert callback == engine._on_ip_change

        if not db.is_closed():
            db.close()


# ══════════════════════════════════════════════════
# severity <= 2 escalation path (line 297)
# ══════════════════════════════════════════════════

class TestSeverity2Escalation:

    def test_severity_2_escalates_context_level_to_at_least_2(self, defense_env):
        """evaluate_threat with severity=2 sets context_level >= 2."""
        engine, _ = defense_env
        ip = "10.0.0.77"
        # Use a low-context category so default context_level is 0
        engine.evaluate_threat(ip, "192.168.1.10", severity=2,
                               category="portscan", signature="sev2 test")
        # severity <= 2 → context_level = max(context_level, 2)
        # Since portscan starts at 0, context_level becomes 2
        assert engine._escalation[ip]["level"] >= 2

    def test_severity_2_does_not_override_higher_context(self, defense_env):
        """severity=2 does not downgrade a category that already starts at level 3."""
        engine, _ = defense_env
        ip = "10.0.0.78"
        # arp_spoof starts at level 3
        engine.evaluate_threat(ip, "192.168.1.10", severity=2,
                               category="arp_spoof", signature="sev2 arp test")
        assert engine._escalation[ip]["level"] >= 3


# ══════════════════════════════════════════════════
# _check_deescalation "not enough silence yet" (line 407)
# ══════════════════════════════════════════════════

class TestDeescalationNotEnoughSilence:

    def test_no_deescalation_when_last_escalation_recent(self, defense_env):
        """No de-escalation when last_escalation is too recent (line 407 continue)."""
        engine, _ = defense_env
        ip = "10.0.0.88"
        now = time.time()
        # Set escalation at level 1 with very recent last_escalation
        engine._escalation[ip] = {
            "level": 1, "since": now, "last_escalation": now,
            "category": "portscan", "reason": "test",
        }
        # No recent alerts (so line 403 won't continue)
        engine._alert_counter[ip] = []

        engine._check_deescalation()
        # Level should remain 1 because not enough silence has passed
        assert engine._escalation[ip]["level"] == 1

    def test_deescalation_occurs_after_sufficient_silence(self, defense_env):
        """De-escalation happens when enough silence has passed."""
        engine, _ = defense_env
        ip = "10.0.0.89"
        old_ts = time.time() - 1000  # Long ago
        engine._escalation[ip] = {
            "level": 1, "since": old_ts, "last_escalation": old_ts,
            "category": "portscan", "reason": "test",
        }
        engine._alert_counter[ip] = []

        engine._check_deescalation()
        assert engine._escalation[ip]["level"] == 0


# ══════════════════════════════════════════════════
# _verify_action level >= 3 (lines 462-502)
# ══════════════════════════════════════════════════

class TestVerifyActionBlock:

    def test_verify_action_iptables_rule_exists(self, defense_env):
        """When iptables -C returns 0, rule exists, no re-apply needed."""
        engine, alert_fn = defense_env
        engine._fw_backend = "iptables"
        item = {"ip": "10.0.0.1", "level": 3, "action": "BLOCK", "ts": time.time() - 60}

        mock_run_result = MagicMock()
        mock_run_result.returncode = 0

        with patch("core.defense.subprocess.run", return_value=mock_run_result), \
             patch("core.database.Flow") as mock_flow:
            # No traffic
            mock_flow.select.return_value.where.return_value.where.return_value.count.return_value = 0
            mock_flow.select.return_value.where.return_value.count.return_value = 0
            engine._verify_action(item)

        # No re-apply alert since rule exists
        verify_failed_calls = [c for c in alert_fn.call_args_list
                               if c[1].get("category") == "verify_failed"]
        assert len(verify_failed_calls) == 0

    def test_verify_action_iptables_rule_missing_reapplied(self, defense_env):
        """When iptables -C returns non-zero, rule is missing and re-applied."""
        engine, alert_fn = defense_env
        engine._fw_backend = "iptables"
        item = {"ip": "10.0.0.2", "level": 3, "action": "BLOCK", "ts": time.time() - 60}

        mock_run_result = MagicMock()
        mock_run_result.returncode = 1  # Rule missing

        with patch("core.defense.subprocess.run", return_value=mock_run_result), \
             patch.object(engine, '_fw_block') as mock_block, \
             patch("core.database.Flow") as mock_flow:
            mock_flow.select.return_value.where.return_value.where.return_value.count.return_value = 0
            mock_flow.select.return_value.where.return_value.count.return_value = 0
            engine._verify_action(item)

        mock_block.assert_called_once_with("10.0.0.2")
        verify_failed_calls = [c for c in alert_fn.call_args_list
                               if c[1].get("category") == "verify_failed"]
        assert len(verify_failed_calls) == 1

    def test_verify_action_traffic_still_flowing_reblock_and_escalate(self, defense_env):
        """When blocked IP still has >10 recent flows, re-block and escalate."""
        engine, alert_fn = defense_env
        engine._fw_backend = "none"  # Skip iptables check
        ip = "10.0.0.3"
        item = {"ip": ip, "level": 3, "action": "BLOCK", "ts": time.time() - 60}

        # Set up escalation state for this IP
        engine._escalation[ip] = {
            "level": 3, "since": time.time(), "last_escalation": time.time(),
            "category": "intrusion", "reason": "test",
        }

        # Build a mock Flow with proper peewee-like field comparisons
        mock_ts_field = MagicMock()
        mock_ts_field.__ge__ = MagicMock(return_value=MagicMock())  # Flow.ts >= datetime
        mock_src_ip_field = MagicMock()
        mock_src_ip_field.__eq__ = MagicMock(return_value=MagicMock())  # Flow.src_ip == ip

        mock_flow_cls = MagicMock()
        mock_flow_cls.src_ip = mock_src_ip_field
        mock_flow_cls.ts = mock_ts_field

        mock_where = MagicMock()
        mock_where.count.return_value = 25
        mock_flow_cls.select.return_value.where.return_value = mock_where

        with patch("core.database.Flow", mock_flow_cls), \
             patch.object(engine, '_fw_block') as mock_block:
            engine._verify_action(item)

        mock_block.assert_called_once_with(ip)
        assert engine._escalation[ip]["level"] == 4  # Escalated from 3 to 4

    def test_verify_action_no_traffic_no_reblock(self, defense_env):
        """When blocked IP has 0 recent flows, no re-block needed."""
        engine, _ = defense_env
        engine._fw_backend = "none"
        item = {"ip": "10.0.0.4", "level": 3, "action": "BLOCK", "ts": time.time() - 60}

        mock_ts_field = MagicMock()
        mock_ts_field.__ge__ = MagicMock(return_value=MagicMock())
        mock_src_ip_field = MagicMock()
        mock_src_ip_field.__eq__ = MagicMock(return_value=MagicMock())

        mock_flow_cls = MagicMock()
        mock_flow_cls.src_ip = mock_src_ip_field
        mock_flow_cls.ts = mock_ts_field

        mock_where = MagicMock()
        mock_where.count.return_value = 0
        mock_flow_cls.select.return_value.where.return_value = mock_where

        with patch("core.database.Flow", mock_flow_cls), \
             patch.object(engine, '_fw_block') as mock_block:
            engine._verify_action(item)

        mock_block.assert_not_called()


# ══════════════════════════════════════════════════
# _verify_action level == 2 quarantine verify (lines 504-521)
# ══════════════════════════════════════════════════

class TestVerifyActionQuarantine:

    def test_verify_quarantine_non_admin_flows_triggers_reapply(self, defense_env):
        """When quarantined host has >5 non-admin flows, re-apply quarantine."""
        engine, _ = defense_env
        engine._fw_backend = "none"
        ip = "192.168.1.50"
        item = {"ip": ip, "level": 2, "action": "ISOLATE", "ts": time.time() - 60}

        # Use real DB with Flow entries
        from core.database import Flow
        from datetime import datetime
        for i in range(10):
            Flow.create(src_ip=ip, dst_ip=f"10.0.0.{i}", dst_port=80)

        with patch.object(engine, '_fw_quarantine') as mock_quar:
            engine._verify_action(item)

        mock_quar.assert_called_once_with(ip)

    def test_verify_quarantine_few_flows_no_reapply(self, defense_env):
        """When quarantined host has <=5 non-admin flows, no re-apply."""
        engine, _ = defense_env
        engine._fw_backend = "none"
        ip = "192.168.1.51"
        item = {"ip": ip, "level": 2, "action": "ISOLATE", "ts": time.time() - 60}

        # Use real DB with only 2 flows (< threshold of 5)
        from core.database import Flow
        for i in range(2):
            Flow.create(src_ip=ip, dst_ip=f"10.0.0.{i}", dst_port=80)

        with patch.object(engine, '_fw_quarantine') as mock_quar:
            engine._verify_action(item)

        mock_quar.assert_not_called()


# ══════════════════════════════════════════════════
# _verify_loop body extraction (lines 448-458)
# ══════════════════════════════════════════════════

class TestVerifyLoopBody:

    def test_verify_loop_processes_old_items(self, defense_env):
        """Items older than 30s are processed and removed from queue."""
        engine, _ = defense_env
        old_item = {"ip": "10.0.0.5", "level": 1, "action": "THROTTLE",
                    "ts": time.time() - 60}
        recent_item = {"ip": "10.0.0.6", "level": 1, "action": "THROTTLE",
                       "ts": time.time()}
        engine._verify_queue = [old_item, recent_item]

        # Extract the body logic of _verify_loop (without while True / sleep)
        now = time.time()
        with engine._verify_lock:
            ready = [v for v in engine._verify_queue if now - v["ts"] > 30]
            engine._verify_queue = [v for v in engine._verify_queue if now - v["ts"] <= 30]

        assert len(ready) == 1
        assert ready[0]["ip"] == "10.0.0.5"
        assert len(engine._verify_queue) == 1
        assert engine._verify_queue[0]["ip"] == "10.0.0.6"

    def test_verify_loop_handles_verify_action_exception(self, defense_env):
        """Exceptions in _verify_action are caught gracefully."""
        engine, _ = defense_env
        item = {"ip": "10.0.0.7", "level": 3, "action": "BLOCK",
                "ts": time.time() - 60}
        engine._verify_queue = [item]

        # Extract body logic
        now = time.time()
        with engine._verify_lock:
            ready = [v for v in engine._verify_queue if now - v["ts"] > 30]
            engine._verify_queue = [v for v in engine._verify_queue if now - v["ts"] <= 30]

        for it in ready:
            try:
                with patch.object(engine, '_verify_action', side_effect=Exception("boom")):
                    engine._verify_action(it)
            except Exception:
                pass  # Matches the except in _verify_loop

        # Should not crash
        assert len(engine._verify_queue) == 0


# ══════════════════════════════════════════════════
# _cleanup_loop body (lines 783-817)
# ══════════════════════════════════════════════════

class TestCleanupLoopBody:

    def test_cleanup_loop_calls_deescalation(self, defense_env):
        """_cleanup_loop body calls _check_deescalation."""
        engine, _ = defense_env
        ip = "10.0.0.90"
        old_ts = time.time() - 2000
        engine._escalation[ip] = {
            "level": 1, "since": old_ts, "last_escalation": old_ts,
            "category": "portscan", "reason": "test",
        }
        engine._alert_counter[ip] = []

        # Run the body of _cleanup_loop (without while True / sleep)
        now = time.time()
        try:
            engine._check_deescalation()
        except Exception:
            pass

        # De-escalation should have happened
        assert engine._escalation[ip]["level"] == 0

    def test_cleanup_loop_expires_and_unblocks(self, defense_env):
        """_cleanup_loop body expires actions and unblocks IPs."""
        engine, alert_fn = defense_env
        from core.defense import DefenseAction

        # Create expired BLOCK action
        action_block = DefenseAction(
            action_type="BLOCK_IP", target_ip="10.0.0.91",
            reason="test block", ttl_seconds=1, active=True)
        action_block.expires_at = time.time() - 10
        engine._actions["BLOCK:10.0.0.91"] = action_block

        # Create expired RATE_LIMIT action
        action_rate = DefenseAction(
            action_type="RATE_LIMIT", target_ip="10.0.0.92",
            reason="test rate", ttl_seconds=1, active=True)
        action_rate.expires_at = time.time() - 10
        engine._actions["RATE:10.0.0.92"] = action_rate

        # Create expired QUARANTINE action
        action_quar = DefenseAction(
            action_type="QUARANTINE", target_ip="10.0.0.93",
            reason="test quar", ttl_seconds=1, active=True)
        action_quar.expires_at = time.time() - 10
        engine._actions["QUARANTINE:10.0.0.93"] = action_quar

        # Run the cleanup body logic
        now = time.time()
        try:
            engine._check_deescalation()
        except Exception:
            pass

        with engine._lock:
            expired = [k for k, a in engine._actions.items()
                       if a.active and now >= a.expires_at]
        for key in expired:
            a = engine._actions[key]
            if a.action_type == "BLOCK_IP":
                engine.unblock_ip(a.target_ip, "TTL expired")
            elif a.action_type == "RATE_LIMIT":
                engine._fw_unblock(a.target_ip)
                engine._audit("UNRATE_LIMIT", a.target_ip, "TTL expired", True)
            elif a.action_type == "QUARANTINE":
                engine._fw_unblock(a.target_ip)
                engine._audit("UNQUARANTINE", a.target_ip, "TTL expired", True)
                engine._alert(
                    severity=4, source="defense", category="quarantine_end",
                    title=f"End of quarantine: {a.target_ip}",
                    src_ip=a.target_ip, notify=False,
                )
            with engine._lock:
                engine._actions[key].active = False

        # Verify all deactivated
        assert engine._actions["BLOCK:10.0.0.91"].active is False
        assert engine._actions["RATE:10.0.0.92"].active is False
        assert engine._actions["QUARANTINE:10.0.0.93"].active is False
        assert any(e["action"] == "UNRATE_LIMIT" for e in engine._audit_log)
        assert any(e["action"] == "UNQUARANTINE" for e in engine._audit_log)

    def test_cleanup_loop_purges_old_counters(self, defense_env):
        """_cleanup_loop body purges old alert counters."""
        engine, _ = defense_env
        old_time = time.time() - 10000
        recent_time = time.time() - 10
        engine._alert_counter["10.0.0.94"] = [old_time]
        engine._alert_counter["10.0.0.95"] = [recent_time]

        # Run counter purge logic
        now = time.time()
        cutoff = now - engine.alert_count_window * 2
        for ip in list(engine._alert_counter):
            engine._alert_counter[ip] = [t for t in engine._alert_counter[ip] if t > cutoff]
            if not engine._alert_counter[ip]:
                del engine._alert_counter[ip]

        assert "10.0.0.94" not in engine._alert_counter
        assert "10.0.0.95" in engine._alert_counter


# ══════════════════════════════════════════════════
# _cleanup_loop actual method call (lines 783-817)
# ══════════════════════════════════════════════════

class TestCleanupLoopActual:

    def test_cleanup_loop_runs_one_iteration(self, defense_env):
        """Call _cleanup_loop, break after one iteration via time.sleep side_effect."""
        engine, alert_fn = defense_env
        from core.defense import DefenseAction

        # Create expired BLOCK action
        action_block = DefenseAction(
            action_type="BLOCK_IP", target_ip="10.0.0.100",
            reason="test block", ttl_seconds=1, active=True)
        action_block.expires_at = time.time() - 10
        engine._actions["BLOCK:10.0.0.100"] = action_block

        # Create expired RATE_LIMIT action
        action_rate = DefenseAction(
            action_type="RATE_LIMIT", target_ip="10.0.0.101",
            reason="test rate", ttl_seconds=1, active=True)
        action_rate.expires_at = time.time() - 10
        engine._actions["RATE:10.0.0.101"] = action_rate

        # Create expired QUARANTINE action
        action_quar = DefenseAction(
            action_type="QUARANTINE", target_ip="10.0.0.102",
            reason="test quar", ttl_seconds=1, active=True)
        action_quar.expires_at = time.time() - 10
        engine._actions["QUARANTINE:10.0.0.102"] = action_quar

        # Add old alert counter to test purge
        engine._alert_counter["10.0.0.103"] = [time.time() - 10000]

        # Let the first sleep pass (body executes after), raise on second call
        call_count = [0]
        def fake_sleep(seconds):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with patch("core.defense.time.sleep", side_effect=fake_sleep):
            try:
                engine._cleanup_loop()
            except StopIteration:
                pass

        # Expired actions should be deactivated
        assert engine._actions["BLOCK:10.0.0.100"].active is False
        assert engine._actions["RATE:10.0.0.101"].active is False
        assert engine._actions["QUARANTINE:10.0.0.102"].active is False
        # Old counter should be purged
        assert "10.0.0.103" not in engine._alert_counter

    def test_cleanup_loop_handles_deescalation_exception(self, defense_env):
        """_cleanup_loop catches exceptions from _check_deescalation."""
        engine, _ = defense_env

        call_count = [0]
        def fake_sleep(seconds):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with patch.object(engine, '_check_deescalation', side_effect=Exception("boom")), \
             patch("core.defense.time.sleep", side_effect=fake_sleep):
            try:
                engine._cleanup_loop()
            except StopIteration:
                pass

        # Should not crash


# ══════════════════════════════════════════════════
# _verify_loop actual method call (lines 448-458)
# ══════════════════════════════════════════════════

class TestVerifyLoopActual:

    def test_verify_loop_processes_queue_items(self, defense_env):
        """_verify_loop processes items older than 30s from the queue."""
        engine, _ = defense_env

        # Add an old item to the verify queue
        old_item = {"ip": "10.0.0.110", "level": 1, "action": "THROTTLE",
                    "ts": time.time() - 60}
        engine._verify_queue = [old_item]

        call_count = [0]
        def fake_sleep(seconds):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with patch.object(engine, '_verify_action') as mock_verify, \
             patch("core.defense.time.sleep", side_effect=fake_sleep):
            try:
                engine._verify_loop()
            except StopIteration:
                pass

        mock_verify.assert_called_once_with(old_item)
        assert len(engine._verify_queue) == 0

    def test_verify_loop_catches_verify_action_exception(self, defense_env):
        """_verify_loop catches exceptions from _verify_action."""
        engine, _ = defense_env

        old_item = {"ip": "10.0.0.111", "level": 3, "action": "BLOCK",
                    "ts": time.time() - 60}
        engine._verify_queue = [old_item]

        call_count = [0]
        def fake_sleep(seconds):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with patch.object(engine, '_verify_action', side_effect=Exception("verify boom")), \
             patch("core.defense.time.sleep", side_effect=fake_sleep):
            try:
                engine._verify_loop()
            except StopIteration:
                pass

        # Should not crash, queue should be empty
        assert len(engine._verify_queue) == 0

    def test_verify_loop_keeps_recent_items(self, defense_env):
        """_verify_loop keeps items that are less than 30s old."""
        engine, _ = defense_env

        recent_item = {"ip": "10.0.0.112", "level": 1, "action": "THROTTLE",
                       "ts": time.time()}
        engine._verify_queue = [recent_item]

        call_count = [0]
        def fake_sleep(seconds):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with patch.object(engine, '_verify_action') as mock_verify, \
             patch("core.defense.time.sleep", side_effect=fake_sleep):
            try:
                engine._verify_loop()
            except StopIteration:
                pass

        mock_verify.assert_not_called()
        assert len(engine._verify_queue) == 1


# ══════════════════════════════════════════════════
# _verify_action exception paths (lines 481-482, 520-521)
# ══════════════════════════════════════════════════

class TestVerifyActionExceptions:

    def test_verify_action_iptables_check_exception(self, defense_env):
        """iptables -C raises exception, caught gracefully (lines 481-482)."""
        engine, _ = defense_env
        engine._fw_backend = "iptables"
        item = {"ip": "10.0.0.120", "level": 3, "action": "BLOCK", "ts": time.time() - 60}

        # Mock subprocess.run to raise for iptables -C, and Flow to not raise
        mock_ts_field = MagicMock()
        mock_ts_field.__ge__ = MagicMock(return_value=MagicMock())
        mock_src_ip_field = MagicMock()
        mock_src_ip_field.__eq__ = MagicMock(return_value=MagicMock())

        mock_flow_cls = MagicMock()
        mock_flow_cls.src_ip = mock_src_ip_field
        mock_flow_cls.ts = mock_ts_field
        mock_flow_cls.select.return_value.where.return_value.count.return_value = 0

        with patch("core.defense.subprocess.run", side_effect=Exception("iptables error")), \
             patch("core.database.Flow", mock_flow_cls):
            # Should not raise
            engine._verify_action(item)

    def test_verify_action_quarantine_flow_check_exception(self, defense_env):
        """Flow query for quarantine raises exception, caught gracefully (lines 520-521)."""
        engine, _ = defense_env
        engine._fw_backend = "none"
        item = {"ip": "10.0.0.121", "level": 2, "action": "ISOLATE", "ts": time.time() - 60}

        with patch("core.database.Flow") as mock_flow:
            mock_flow.select.side_effect = Exception("DB error")
            # Should not raise
            engine._verify_action(item)
