"""Tests for core/mac_resolver.py — MacIpResolver."""

import os
import sys
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class FakeConfig:
    def __init__(self, overrides=None):
        self._data = overrides or {}

    def get(self, key, default=None):
        return self._data.get(key, default)


@pytest.fixture
def resolver(test_db):
    """Create a MacIpResolver with empty DB."""
    from core.mac_resolver import MacIpResolver
    alert_fn = MagicMock()
    cfg = FakeConfig({"email.user_directory": []})
    r = MacIpResolver(cfg, alert_fn)
    return r


@pytest.fixture
def resolver_with_directory(test_db):
    """Create a MacIpResolver with user directory."""
    from core.mac_resolver import MacIpResolver
    alert_fn = MagicMock()
    directory = [
        {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff", "email": "alice@test.com", "name": "Alice"},
        {"ip": "192.168.1.20", "mac": "11:22:33:44:55:66", "email": "bob@test.com", "name": "Bob"},
    ]
    cfg = FakeConfig({"email.user_directory": directory})
    r = MacIpResolver(cfg, alert_fn)
    return r


# ── Update (new MAC) ──

class TestUpdateNewMac:
    def test_new_mac_registered(self, resolver):
        result = resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10",
                                  hostname="pc-01", vendor="Dell")
        assert result["changed"] is False
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_new_mac_retrievable(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        assert resolver.ip_to_mac("192.168.1.10") == "aa:bb:cc:dd:ee:ff"
        assert resolver.mac_to_ip("aa:bb:cc:dd:ee:ff") == "192.168.1.10"

    def test_invalid_mac_ignored(self, resolver):
        result = resolver.update("", "192.168.1.10")
        assert result["changed"] is False

    def test_zero_mac_ignored(self, resolver):
        result = resolver.update("00:00:00:00:00:00", "192.168.1.10")
        assert result["changed"] is False

    def test_empty_ip_ignored(self, resolver):
        result = resolver.update("aa:bb:cc:dd:ee:ff", "")
        assert result["changed"] is False

    def test_mac_normalized_to_lowercase(self, resolver):
        resolver.update("AA:BB:CC:DD:EE:FF", "192.168.1.10")
        assert resolver.mac_to_ip("aa:bb:cc:dd:ee:ff") == "192.168.1.10"


# ── Update (IP change / DHCP) ──

class TestUpdateIPChange:
    def test_ip_change_detected(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        result = resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.20")
        assert result["changed"] is True
        assert result["old_ip"] == "192.168.1.10"
        assert result["new_ip"] == "192.168.1.20"

    def test_ip_change_updates_reverse_index(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.20")
        assert resolver.ip_to_mac("192.168.1.20") == "aa:bb:cc:dd:ee:ff"
        assert resolver.ip_to_mac("192.168.1.10") == ""

    def test_ip_change_creates_alert(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.20")
        resolver._alert.assert_called_once()
        call_kwargs = resolver._alert.call_args
        assert call_kwargs[1]["category"] == "ip_change"

    def test_same_ip_no_change(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        result = resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        assert result["changed"] is False

    def test_ip_change_updates_metadata(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10", hostname="old-name")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.20", hostname="new-name")
        with resolver._lock:
            entry = resolver._mac_table["aa:bb:cc:dd:ee:ff"]
        assert entry["hostname"] == "new-name"
        assert entry["ip"] == "192.168.1.20"

    def test_ip_conflict_clears_old_mac(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        resolver.update("11:22:33:44:55:66", "192.168.1.10")
        # Old MAC should have its IP cleared
        with resolver._lock:
            old_entry = resolver._mac_table["aa:bb:cc:dd:ee:ff"]
        assert old_entry["ip"] == ""


# ── on_ip_change callback ──

class TestOnIPChangeCallback:
    def test_callback_fired_on_change(self, resolver):
        cb = MagicMock()
        resolver.on_ip_change(cb)
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.20")
        cb.assert_called_once_with("aa:bb:cc:dd:ee:ff", "192.168.1.10", "192.168.1.20")

    def test_callback_not_fired_no_change(self, resolver):
        cb = MagicMock()
        resolver.on_ip_change(cb)
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        cb.assert_not_called()

    def test_callback_exception_handled(self, resolver):
        cb = MagicMock(side_effect=Exception("callback error"))
        resolver.on_ip_change(cb)
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        # Should not raise
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.20")

    def test_multiple_callbacks(self, resolver):
        cb1, cb2 = MagicMock(), MagicMock()
        resolver.on_ip_change(cb1)
        resolver.on_ip_change(cb2)
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.20")
        cb1.assert_called_once()
        cb2.assert_called_once()


# ── Resolution ──

class TestResolution:
    def test_mac_to_ip(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        assert resolver.mac_to_ip("aa:bb:cc:dd:ee:ff") == "192.168.1.10"

    def test_mac_to_ip_unknown(self, resolver):
        assert resolver.mac_to_ip("ff:ff:ff:ff:ff:ff") == ""

    def test_ip_to_mac(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        assert resolver.ip_to_mac("192.168.1.10") == "aa:bb:cc:dd:ee:ff"

    def test_ip_to_mac_unknown(self, resolver):
        assert resolver.ip_to_mac("99.99.99.99") == ""

    def test_resolve_target_by_mac(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10", hostname="pc-01")
        result = resolver.resolve_target("aa:bb:cc:dd:ee:ff")
        assert result["ip"] == "192.168.1.10"
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["hostname"] == "pc-01"

    def test_resolve_target_by_ip(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10", hostname="pc-01")
        result = resolver.resolve_target("192.168.1.10")
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["hostname"] == "pc-01"

    def test_resolve_target_unknown(self, resolver):
        result = resolver.resolve_target("99.99.99.99")
        assert result["ip"] == "99.99.99.99"
        assert result["mac"] == ""

    def test_resolve_target_case_insensitive(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        result = resolver.resolve_target("AA:BB:CC:DD:EE:FF")
        assert result["ip"] == "192.168.1.10"


# ── get_user_email ──

class TestGetUserEmail:
    def test_lookup_by_ip(self, resolver_with_directory):
        result = resolver_with_directory.get_user_email("192.168.1.10")
        assert result["email"] == "alice@test.com"

    def test_lookup_by_mac_after_dhcp_change(self, resolver_with_directory):
        # Register MAC with new IP
        resolver_with_directory.update("aa:bb:cc:dd:ee:ff", "192.168.1.99")
        result = resolver_with_directory.get_user_email("192.168.1.99")
        assert result["email"] == "alice@test.com"

    def test_lookup_unknown_ip(self, resolver_with_directory):
        result = resolver_with_directory.get_user_email("99.99.99.99")
        assert result == {}

    def test_lookup_unknown_mac(self, resolver):
        result = resolver.get_user_email("192.168.1.10")
        assert result == {}


# ── is_whitelisted ──

class TestIsWhitelisted:
    def test_ip_whitelisted(self, resolver):
        assert resolver.is_whitelisted("192.168.1.1", {"192.168.1.1"}) is True

    def test_ip_not_whitelisted(self, resolver):
        assert resolver.is_whitelisted("192.168.1.2", {"192.168.1.1"}) is False

    def test_mac_whitelisted(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        result = resolver.is_whitelisted(
            "192.168.1.10",
            set(),
            whitelist_macs={"aa:bb:cc:dd:ee:ff"},
        )
        assert result is True

    def test_mac_not_whitelisted(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        result = resolver.is_whitelisted(
            "192.168.1.10",
            set(),
            whitelist_macs={"11:22:33:44:55:66"},
        )
        assert result is False

    def test_no_mac_whitelist(self, resolver):
        assert resolver.is_whitelisted("1.2.3.4", set()) is False

    def test_ip_whitelist_takes_priority(self, resolver):
        assert resolver.is_whitelisted("1.2.3.4", {"1.2.3.4"}, whitelist_macs=set()) is True

    def test_mac_whitelisted_after_dhcp_change(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.20")
        result = resolver.is_whitelisted(
            "192.168.1.20",
            set(),
            whitelist_macs={"aa:bb:cc:dd:ee:ff"},
        )
        assert result is True


# ── DB integration ──

class TestDBIntegration:
    def test_handle_ip_change_updates_host(self, resolver, test_db):
        from core.database import Host
        Host.create(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", hostname="pc-01")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.20")
        host = Host.get_or_none(Host.mac == "aa:bb:cc:dd:ee:ff")
        assert host is not None
        assert host.ip == "192.168.1.20"

    def test_handle_ip_change_updates_ports(self, resolver, test_db):
        from core.database import Host, Port
        Host.create(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff")
        Port.create(host_ip="192.168.1.10", port=22, proto="tcp")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.20")
        port = Port.get_or_none(Port.port == 22)
        assert port is not None
        assert port.host_ip == "192.168.1.20"

    def test_handle_ip_change_db_error_handled(self, resolver, test_db):
        """When IP change creates a UNIQUE constraint conflict, it is handled gracefully."""
        from core.database import Host
        Host.create(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff")
        Host.create(ip="192.168.1.20", mac="11:22:33:44:55:66")
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10")
        # This triggers a UNIQUE constraint error in the DB handler
        # but the in-memory table is still updated correctly
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.20")
        assert resolver.ip_to_mac("192.168.1.20") == "aa:bb:cc:dd:ee:ff"

    def test_load_from_db(self, test_db):
        from core.database import Host
        from core.mac_resolver import MacIpResolver
        Host.create(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", hostname="pc-01")
        Host.create(ip="192.168.1.20", mac="11:22:33:44:55:66", hostname="pc-02")
        r = MacIpResolver(FakeConfig(), MagicMock())
        assert r.ip_to_mac("192.168.1.10") == "aa:bb:cc:dd:ee:ff"
        assert r.ip_to_mac("192.168.1.20") == "11:22:33:44:55:66"
        assert r.mac_to_ip("aa:bb:cc:dd:ee:ff") == "192.168.1.10"


# ── Stats ──

class TestStats:
    def test_stats_empty(self, resolver):
        s = resolver.stats
        assert s["total_macs"] == 0
        assert s["total_ips"] == 0
        assert s["table"] == []

    def test_stats_after_updates(self, resolver):
        resolver.update("aa:bb:cc:dd:ee:ff", "192.168.1.10", hostname="pc-01")
        resolver.update("11:22:33:44:55:66", "192.168.1.20", hostname="pc-02")
        s = resolver.stats
        assert s["total_macs"] == 2
        assert s["total_ips"] == 2
        assert len(s["table"]) == 2
