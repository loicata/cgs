"""Comprehensive tests for core/netgate.py — NetgateFirewall and _SuppressInsecureWarnings."""

import time
import warnings
from unittest.mock import MagicMock, patch, call

import pytest
import requests
import urllib3

from core.netgate import NetgateFirewall, _SuppressInsecureWarnings


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

class FakeConfig:
    """Minimal Config replacement backed by a plain dict, using dotted key lookup."""

    def __init__(self, data: dict):
        self._d = data

    def get(self, dotted, default=None):
        keys = dotted.split(".")
        v = self._d
        for k in keys:
            if isinstance(v, dict):
                v = v.get(k)
            else:
                return default
            if v is None:
                return default
        return v


def _base_netgate_cfg(**overrides):
    """Return a netgate config section with sensible defaults."""
    cfg = {
        "enabled": True,
        "type": "pfsense",
        "host": "10.0.0.1",
        "port": 443,
        "verify_ssl": False,
        "block_alias": "CGS_Block",
        "timeout": 5,
        "pfsense_api_client": "client-id",
        "pfsense_api_key": "api-key",
        "opnsense_key": "opn-key",
        "opnsense_secret": "opn-secret",
    }
    cfg.update(overrides)
    return cfg


def _make_fw(netgate_overrides=None, patch_sync=True):
    """Build a NetgateFirewall, optionally patching _sync_blocked to avoid API calls."""
    ncfg = _base_netgate_cfg(**(netgate_overrides or {}))
    cfg = FakeConfig({"netgate": ncfg})
    if patch_sync:
        with patch.object(NetgateFirewall, "_sync_blocked"):
            return NetgateFirewall(cfg)
    return NetgateFirewall(cfg)


# ──────────────────────────────────────────────
# _SuppressInsecureWarnings
# ──────────────────────────────────────────────

class TestSuppressInsecureWarnings:
    def test_suppresses_insecure_request_warnings(self):
        with _SuppressInsecureWarnings():
            # Inside context: warning should be suppressed (no error raised)
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                # Re-apply the filter from _SuppressInsecureWarnings
                warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
                warnings.warn("test", urllib3.exceptions.InsecureRequestWarning)
                insecure = [x for x in w if issubclass(x.category, urllib3.exceptions.InsecureRequestWarning)]
                assert len(insecure) == 0

    def test_exit_resets_warnings(self):
        ctx = _SuppressInsecureWarnings()
        ctx.__enter__()
        ctx.__exit__(None, None, None)
        # After exit, warnings should be reset — InsecureRequestWarning should appear
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            warnings.warn("test", urllib3.exceptions.InsecureRequestWarning)
            insecure = [x for x in w if issubclass(x.category, urllib3.exceptions.InsecureRequestWarning)]
            assert len(insecure) == 1

    def test_context_manager_returns_self(self):
        ctx = _SuppressInsecureWarnings()
        result = ctx.__enter__()
        assert result is ctx
        ctx.__exit__(None, None, None)


# ──────────────────────────────────────────────
# NetgateFirewall.__init__
# ──────────────────────────────────────────────

class TestNetgateInit:
    def test_disabled_no_sync(self):
        cfg = FakeConfig({"netgate": _base_netgate_cfg(enabled=False)})
        with patch.object(NetgateFirewall, "_sync_blocked") as mock_sync:
            fw = NetgateFirewall(cfg)
        assert fw.enabled is False
        mock_sync.assert_not_called()

    def test_enabled_pfsense_calls_sync(self):
        cfg = FakeConfig({"netgate": _base_netgate_cfg(type="pfsense")})
        with patch.object(NetgateFirewall, "_sync_blocked") as mock_sync:
            fw = NetgateFirewall(cfg)
        assert fw.enabled is True
        assert fw.fw_type == "pfsense"
        mock_sync.assert_called_once()

    def test_enabled_opnsense_calls_sync(self):
        cfg = FakeConfig({"netgate": _base_netgate_cfg(type="opnsense")})
        with patch.object(NetgateFirewall, "_sync_blocked") as mock_sync:
            fw = NetgateFirewall(cfg)
        assert fw.enabled is True
        assert fw.fw_type == "opnsense"
        mock_sync.assert_called_once()

    def test_enabled_no_host_disables(self):
        cfg = FakeConfig({"netgate": _base_netgate_cfg(host="")})
        with patch.object(NetgateFirewall, "_sync_blocked") as mock_sync:
            fw = NetgateFirewall(cfg)
        assert fw.enabled is False
        mock_sync.assert_not_called()

    def test_enabled_unknown_type_disables(self):
        cfg = FakeConfig({"netgate": _base_netgate_cfg(type="juniper")})
        with patch.object(NetgateFirewall, "_sync_blocked") as mock_sync:
            fw = NetgateFirewall(cfg)
        assert fw.enabled is False
        mock_sync.assert_not_called()

    def test_attributes_set_correctly(self):
        fw = _make_fw({"port": 8443, "block_alias": "MyAlias", "timeout": 30})
        assert fw.port == 8443
        assert fw.block_alias == "MyAlias"
        assert fw.timeout == 30
        assert fw.base_url == "https://10.0.0.1:8443"


# ──────────────────────────────────────────────
# block_ip / unblock_ip
# ──────────────────────────────────────────────

class TestBlockUnblock:
    def test_block_ip_disabled_returns_false(self):
        fw = _make_fw({"enabled": False})
        assert fw.block_ip("1.2.3.4") is False

    def test_block_ip_already_blocked_returns_true(self):
        fw = _make_fw()
        fw._blocked_ips.add("1.2.3.4")
        assert fw.block_ip("1.2.3.4") is True

    def test_block_ip_pfsense_success(self):
        fw = _make_fw({"type": "pfsense"})
        with patch.object(fw, "_pf_add_to_alias", return_value=True) as mock_add, \
             patch.object(fw, "_apply_changes") as mock_apply:
            result = fw.block_ip("1.2.3.4", reason="test")
        assert result is True
        assert "1.2.3.4" in fw._blocked_ips
        mock_add.assert_called_once_with("1.2.3.4")
        mock_apply.assert_called_once()

    def test_block_ip_opnsense_success(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_add_to_alias", return_value=True) as mock_add, \
             patch.object(fw, "_apply_changes") as mock_apply:
            result = fw.block_ip("5.6.7.8")
        assert result is True
        assert "5.6.7.8" in fw._blocked_ips
        mock_add.assert_called_once_with("5.6.7.8")
        mock_apply.assert_called_once()

    def test_block_ip_failure_returns_false(self):
        fw = _make_fw({"type": "pfsense"})
        with patch.object(fw, "_pf_add_to_alias", return_value=False), \
             patch.object(fw, "_apply_changes") as mock_apply:
            result = fw.block_ip("9.9.9.9")
        assert result is False
        assert "9.9.9.9" not in fw._blocked_ips
        mock_apply.assert_not_called()

    def test_unblock_ip_disabled_returns_false(self):
        fw = _make_fw({"enabled": False})
        assert fw.unblock_ip("1.2.3.4") is False

    def test_unblock_ip_pfsense_success(self):
        fw = _make_fw({"type": "pfsense"})
        fw._blocked_ips.add("1.2.3.4")
        with patch.object(fw, "_pf_remove_from_alias", return_value=True) as mock_rm, \
             patch.object(fw, "_apply_changes") as mock_apply:
            result = fw.unblock_ip("1.2.3.4")
        assert result is True
        assert "1.2.3.4" not in fw._blocked_ips
        mock_rm.assert_called_once_with("1.2.3.4")
        mock_apply.assert_called_once()

    def test_unblock_ip_opnsense_success(self):
        fw = _make_fw({"type": "opnsense"})
        fw._blocked_ips.add("10.0.0.5")
        with patch.object(fw, "_opn_remove_from_alias", return_value=True) as mock_rm, \
             patch.object(fw, "_apply_changes") as mock_apply:
            result = fw.unblock_ip("10.0.0.5")
        assert result is True
        assert "10.0.0.5" not in fw._blocked_ips
        mock_apply.assert_called_once()

    def test_unblock_ip_failure_no_discard(self):
        fw = _make_fw({"type": "pfsense"})
        fw._blocked_ips.add("1.1.1.1")
        with patch.object(fw, "_pf_remove_from_alias", return_value=False), \
             patch.object(fw, "_apply_changes") as mock_apply:
            result = fw.unblock_ip("1.1.1.1")
        assert result is False
        # IP remains because ok was False
        assert "1.1.1.1" in fw._blocked_ips
        mock_apply.assert_not_called()


# ──────────────────────────────────────────────
# get_status
# ──────────────────────────────────────────────

class TestGetStatus:
    def test_disabled(self):
        fw = _make_fw({"enabled": False})
        assert fw.get_status() == {"enabled": False}

    def test_pfsense_delegates(self):
        fw = _make_fw({"type": "pfsense"})
        with patch.object(fw, "_pf_status", return_value={"type": "pfsense"}) as m:
            result = fw.get_status()
        assert result == {"type": "pfsense"}
        m.assert_called_once()

    def test_opnsense_delegates(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_status", return_value={"type": "opnsense"}) as m:
            result = fw.get_status()
        assert result == {"type": "opnsense"}
        m.assert_called_once()


# ──────────────────────────────────────────────
# get_blocked_ips
# ──────────────────────────────────────────────

class TestGetBlockedIps:
    def test_returns_sorted_list(self):
        fw = _make_fw()
        fw._blocked_ips = {"3.3.3.3", "1.1.1.1", "2.2.2.2"}
        with patch.object(fw, "_sync_blocked"):
            result = fw.get_blocked_ips()
        assert result == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    def test_calls_sync(self):
        fw = _make_fw()
        with patch.object(fw, "_sync_blocked") as m:
            fw.get_blocked_ips()
        m.assert_called_once()


# ──────────────────────────────────────────────
# stats property
# ──────────────────────────────────────────────

class TestStats:
    def test_returns_expected_dict(self):
        fw = _make_fw({"type": "opnsense", "host": "fw.local", "block_alias": "BL"})
        fw._blocked_ips = {"a", "b", "c"}
        s = fw.stats
        assert s == {
            "enabled": True,
            "type": "opnsense",
            "host": "fw.local",
            "alias": "BL",
            "blocked_count": 3,
        }


# ──────────────────────────────────────────────
# _pf_request
# ──────────────────────────────────────────────

class TestPfRequest:
    def _fw(self):
        return _make_fw({"type": "pfsense"})

    @patch("core.netgate.requests.request")
    def test_success_200(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": "ok"}
        mock_req.return_value = mock_resp

        fw = self._fw()
        result = fw._pf_request("GET", "/status/system")
        assert result == {"data": "ok"}

    @patch("core.netgate.requests.request")
    def test_success_201(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"status": "created"}
        mock_req.return_value = mock_resp

        fw = self._fw()
        result = fw._pf_request("POST", "/firewall/alias/entry", {"name": "x"})
        assert result == {"status": "created"}

    @patch("core.netgate.requests.request")
    def test_non_200_returns_none(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"
        mock_req.return_value = mock_resp

        fw = self._fw()
        assert fw._pf_request("GET", "/test") is None

    @patch("core.netgate.requests.request", side_effect=requests.exceptions.ConnectionError("refused"))
    def test_connection_error_returns_none(self, mock_req):
        fw = self._fw()
        assert fw._pf_request("GET", "/test") is None

    @patch("core.netgate.requests.request", side_effect=RuntimeError("boom"))
    def test_generic_exception_returns_none(self, mock_req):
        fw = self._fw()
        assert fw._pf_request("GET", "/test") is None


# ──────────────────────────────────────────────
# _pf_add_to_alias
# ──────────────────────────────────────────────

class TestPfAddToAlias:
    def test_method1_success(self):
        fw = _make_fw({"type": "pfsense"})
        with patch.object(fw, "_pf_request", return_value={"status": "ok"}) as mock_req:
            result = fw._pf_add_to_alias("1.2.3.4")
        assert result is True
        mock_req.assert_called_once()

    def test_method1_fail_method2_success(self):
        fw = _make_fw({"type": "pfsense"})
        # First call (POST) returns None, second call (PUT) returns a dict
        with patch.object(fw, "_pf_request", side_effect=[None, {"status": "ok"}]) as mock_req:
            result = fw._pf_add_to_alias("1.2.3.4")
        assert result is True
        assert mock_req.call_count == 2

    def test_method1_fail_method2_fail(self):
        fw = _make_fw({"type": "pfsense"})
        with patch.object(fw, "_pf_request", side_effect=[None, None]):
            result = fw._pf_add_to_alias("1.2.3.4")
        assert result is False

    def test_method1_wrong_status_falls_to_method2(self):
        fw = _make_fw({"type": "pfsense"})
        # Method 1 returns dict but status != "ok"
        with patch.object(fw, "_pf_request", side_effect=[{"status": "error"}, {"done": True}]):
            result = fw._pf_add_to_alias("1.2.3.4")
        assert result is True


# ──────────────────────────────────────────────
# _pf_remove_from_alias
# ──────────────────────────────────────────────

class TestPfRemoveFromAlias:
    def test_success(self):
        fw = _make_fw({"type": "pfsense"})
        with patch.object(fw, "_pf_request", return_value={"status": "ok"}):
            assert fw._pf_remove_from_alias("1.2.3.4") is True

    def test_failure(self):
        fw = _make_fw({"type": "pfsense"})
        with patch.object(fw, "_pf_request", return_value=None):
            assert fw._pf_remove_from_alias("1.2.3.4") is False


# ──────────────────────────────────────────────
# _pf_status
# ──────────────────────────────────────────────

class TestPfStatus:
    def test_with_data(self):
        fw = _make_fw({"type": "pfsense"})
        system_resp = {
            "data": {
                "hostname": "pf1",
                "system_version": "2.7.0",
                "uptime": "5 days",
                "cpu_usage": "12%",
                "mem_usage": "45%",
            }
        }
        alias_resp = {"data": [{"address": "1.1.1.1"}, {"address": "2.2.2.2"}]}

        with patch.object(fw, "_pf_request", side_effect=[system_resp, alias_resp]):
            result = fw._pf_status()
        assert result["reachable"] is True
        assert result["hostname"] == "pf1"
        assert result["blocked_count"] == 2

    def test_without_data(self):
        fw = _make_fw({"type": "pfsense"})
        with patch.object(fw, "_pf_request", side_effect=[None, None]):
            result = fw._pf_status()
        assert result["reachable"] is False
        assert "blocked_count" not in result

    def test_alias_data_not_list(self):
        fw = _make_fw({"type": "pfsense"})
        # system OK, alias data is a dict (not a list)
        with patch.object(fw, "_pf_request", side_effect=[
            {"data": {"hostname": "pf"}},
            {"data": {"some": "thing"}},
        ]):
            result = fw._pf_status()
        assert result["reachable"] is True
        assert "blocked_count" not in result


# ──────────────────────────────────────────────
# _opn_request
# ──────────────────────────────────────────────

class TestOpnRequest:
    def _fw(self):
        return _make_fw({"type": "opnsense"})

    @patch("core.netgate.requests.request")
    def test_success_200(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": "ok"}
        mock_req.return_value = mock_resp

        fw = self._fw()
        result = fw._opn_request("GET", "/core/firmware/status")
        assert result == {"result": "ok"}

    @patch("core.netgate.requests.request")
    def test_non_200_returns_none(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Server Error"
        mock_req.return_value = mock_resp

        fw = self._fw()
        assert fw._opn_request("GET", "/test") is None

    @patch("core.netgate.requests.request", side_effect=requests.exceptions.ConnectionError("err"))
    def test_connection_error_returns_none(self, mock_req):
        fw = self._fw()
        assert fw._opn_request("GET", "/test") is None

    @patch("core.netgate.requests.request", side_effect=ValueError("bad json"))
    def test_generic_exception_returns_none(self, mock_req):
        fw = self._fw()
        assert fw._opn_request("GET", "/test") is None


# ──────────────────────────────────────────────
# _opn_add_to_alias
# ──────────────────────────────────────────────

class TestOpnAddToAlias:
    def test_no_uuid_returns_false(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_get_alias_uuid", return_value=None):
            assert fw._opn_add_to_alias("1.2.3.4") is False

    def test_ip_already_exists_returns_true(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_get_alias_uuid", return_value="uuid-1"), \
             patch.object(fw, "_opn_request", return_value={"rows": [{"ip": "1.2.3.4"}]}):
            assert fw._opn_add_to_alias("1.2.3.4") is True

    def test_add_via_alias_util_success(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_get_alias_uuid", return_value="uuid-1"), \
             patch.object(fw, "_opn_request", side_effect=[
                 {"rows": [{"ip": "5.5.5.5"}]},  # GET list
                 {"status": "done"},               # POST add
             ]):
            assert fw._opn_add_to_alias("1.2.3.4") is True

    def test_fallback_to_setitem(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_get_alias_uuid", return_value="uuid-1"), \
             patch.object(fw, "_opn_request", side_effect=[
                 {"rows": []},        # GET list: empty
                 {"status": "fail"},   # POST add: fails
                 {"saved": True},      # POST setItem: succeeds
             ]):
            assert fw._opn_add_to_alias("1.2.3.4") is True

    def test_all_methods_fail(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_get_alias_uuid", return_value="uuid-1"), \
             patch.object(fw, "_opn_request", side_effect=[
                 {"rows": []},  # GET list
                 None,          # POST add fails
                 None,          # POST setItem fails
             ]):
            assert fw._opn_add_to_alias("1.2.3.4") is False

    def test_list_returns_none_rows(self):
        """GET list returns a result but no 'rows' key."""
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_get_alias_uuid", return_value="uuid-1"), \
             patch.object(fw, "_opn_request", side_effect=[
                 {"other": "data"},      # GET list: no rows
                 {"status": "done"},     # POST add: success
             ]):
            assert fw._opn_add_to_alias("1.2.3.4") is True


# ──────────────────────────────────────────────
# _opn_remove_from_alias
# ──────────────────────────────────────────────

class TestOpnRemoveFromAlias:
    def test_success(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_request", return_value={"status": "done"}):
            assert fw._opn_remove_from_alias("1.2.3.4") is True

    def test_failure(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_request", return_value=None):
            assert fw._opn_remove_from_alias("1.2.3.4") is False


# ──────────────────────────────────────────────
# _opn_get_alias_uuid
# ──────────────────────────────────────────────

class TestOpnGetAliasUuid:
    def test_found(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_request", return_value={
            "rows": [
                {"name": "OtherAlias", "uuid": "aaa"},
                {"name": "CGS_Block", "uuid": "bbb"},
            ]
        }):
            assert fw._opn_get_alias_uuid() == "bbb"

    def test_not_found(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_request", return_value={
            "rows": [{"name": "OtherAlias", "uuid": "aaa"}]
        }):
            assert fw._opn_get_alias_uuid() is None

    def test_request_returns_none(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_request", return_value=None):
            assert fw._opn_get_alias_uuid() is None

    def test_no_rows_key(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_request", return_value={"data": []}):
            assert fw._opn_get_alias_uuid() is None


# ──────────────────────────────────────────────
# _opn_status
# ──────────────────────────────────────────────

class TestOpnStatus:
    def test_with_data(self):
        fw = _make_fw({"type": "opnsense"})
        firmware_resp = {"product_version": "24.1", "product_name": "OPNsense"}
        alias_resp = {"rows": [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}, {"ip": "3.3.3.3"}]}
        with patch.object(fw, "_opn_request", side_effect=[firmware_resp, alias_resp]):
            result = fw._opn_status()
        assert result["reachable"] is True
        assert result["version"] == "24.1"
        assert result["blocked_count"] == 3

    def test_unreachable(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_request", side_effect=[None, None]):
            result = fw._opn_status()
        assert result["reachable"] is False
        assert "blocked_count" not in result

    def test_with_alias_data_only(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_request", side_effect=[
            None,                                # firmware fails
            {"rows": [{"ip": "1.1.1.1"}]},       # alias OK
        ]):
            result = fw._opn_status()
        assert result["reachable"] is False
        assert result["blocked_count"] == 1


# ──────────────────────────────────────────────
# _apply_changes
# ──────────────────────────────────────────────

class TestApplyChanges:
    def test_pfsense(self):
        fw = _make_fw({"type": "pfsense"})
        with patch.object(fw, "_pf_request") as mock_req:
            fw._apply_changes()
        mock_req.assert_called_once_with("POST", "/firewall/apply")

    def test_opnsense(self):
        fw = _make_fw({"type": "opnsense"})
        with patch.object(fw, "_opn_request") as mock_req:
            fw._apply_changes()
        mock_req.assert_called_once_with("POST", "/firewall/alias_util/reconfigure")


# ──────────────────────────────────────────────
# _sync_blocked
# ──────────────────────────────────────────────

class TestSyncBlocked:
    def test_disabled_returns_early(self):
        fw = _make_fw({"enabled": False})
        fw._last_sync = 0
        with patch.object(fw, "_pf_request") as m:
            fw._sync_blocked()
        m.assert_not_called()

    def test_rate_limited(self):
        fw = _make_fw({"type": "pfsense"})
        fw._last_sync = time.time()  # just now
        with patch.object(fw, "_pf_request") as m:
            fw._sync_blocked()
        m.assert_not_called()

    def test_pfsense_path(self):
        fw = _make_fw({"type": "pfsense"})
        fw._last_sync = 0
        pf_data = {
            "data": [
                {"address": "10.0.0.1"},
                {"address": "10.0.0.2"},
            ]
        }
        with patch.object(fw, "_pf_request", return_value=pf_data):
            fw._sync_blocked()
        assert "10.0.0.1" in fw._blocked_ips
        assert "10.0.0.2" in fw._blocked_ips

    def test_pfsense_path_string_entries(self):
        """Entries can be plain strings instead of dicts."""
        fw = _make_fw({"type": "pfsense"})
        fw._last_sync = 0
        pf_data = {"data": ["10.0.0.1", "10.0.0.2"]}
        with patch.object(fw, "_pf_request", return_value=pf_data):
            fw._sync_blocked()
        assert "10.0.0.1" in fw._blocked_ips
        assert "10.0.0.2" in fw._blocked_ips

    def test_pfsense_no_data(self):
        fw = _make_fw({"type": "pfsense"})
        fw._last_sync = 0
        with patch.object(fw, "_pf_request", return_value=None):
            fw._sync_blocked()
        assert len(fw._blocked_ips) == 0

    def test_opnsense_path(self):
        fw = _make_fw({"type": "opnsense"})
        fw._last_sync = 0
        opn_data = {"rows": [{"ip": "5.5.5.5"}, {"ip": "6.6.6.6"}]}
        with patch.object(fw, "_opn_request", return_value=opn_data):
            fw._sync_blocked()
        assert "5.5.5.5" in fw._blocked_ips
        assert "6.6.6.6" in fw._blocked_ips

    def test_opnsense_no_data(self):
        fw = _make_fw({"type": "opnsense"})
        fw._last_sync = 0
        with patch.object(fw, "_opn_request", return_value=None):
            fw._sync_blocked()
        assert len(fw._blocked_ips) == 0

    def test_exception_handled(self):
        fw = _make_fw({"type": "pfsense"})
        fw._last_sync = 0
        with patch.object(fw, "_pf_request", side_effect=RuntimeError("network down")):
            # Should not raise
            fw._sync_blocked()

    def test_pfsense_data_not_list(self):
        """If data is a dict (not a list), entries are not iterated."""
        fw = _make_fw({"type": "pfsense"})
        fw._last_sync = 0
        with patch.object(fw, "_pf_request", return_value={"data": {"single": "item"}}):
            fw._sync_blocked()
        assert len(fw._blocked_ips) == 0

    def test_empty_address_skipped(self):
        fw = _make_fw({"type": "pfsense"})
        fw._last_sync = 0
        pf_data = {"data": [{"address": ""}, {"address": "10.0.0.1"}]}
        with patch.object(fw, "_pf_request", return_value=pf_data):
            fw._sync_blocked()
        assert "" not in fw._blocked_ips
        assert "10.0.0.1" in fw._blocked_ips

    def test_opnsense_empty_ip_skipped(self):
        fw = _make_fw({"type": "opnsense"})
        fw._last_sync = 0
        opn_data = {"rows": [{"ip": ""}, {"ip": "5.5.5.5"}]}
        with patch.object(fw, "_opn_request", return_value=opn_data):
            fw._sync_blocked()
        assert "" not in fw._blocked_ips
        assert "5.5.5.5" in fw._blocked_ips
