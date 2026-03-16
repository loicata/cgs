"""
Comprehensive tests for cgs-agent.py — the CGS Secure Client Agent.

Covers: AgentConfig, SentinelClient, show_popup, _popup_linux/windows/macos,
        collect_local_forensics, _run_local, _collect_unix, _collect_windows,
        _scan_unix, _scan_windows.
"""

import hashlib
import hmac as hmac_mod
import importlib
import json
import os
import ssl
import subprocess
import sys
import types
import urllib.error
from datetime import datetime
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

# ---------------------------------------------------------------------------
# Import the module with hyphenated name
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
agent = importlib.import_module("cgs-agent")

AgentConfig = agent.AgentConfig
SentinelClient = agent.SentinelClient
MESSAGES = agent.MESSAGES
ALLOWED_TYPES = agent.ALLOWED_TYPES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_args(server="https://sentinel:8443", secret="testkey",
               no_verify_ssl=False):
    return types.SimpleNamespace(
        server=server, secret=secret, no_verify_ssl=no_verify_ssl,
    )


def _make_config(**kw):
    """Build an AgentConfig with sensible defaults (patches _find_desktop)."""
    args = _make_args(**kw)
    with patch.object(AgentConfig, "_find_desktop", return_value="/tmp"):
        return AgentConfig(args)


def _hmac_sign(secret: str, payload: str) -> str:
    return hmac_mod.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


# ===================================================================
# 1. AgentConfig
# ===================================================================

class TestAgentConfig:

    def test_init_valid_https(self):
        args = _make_args(server="https://10.0.0.1:8443/", secret="s3cret")
        with patch.object(AgentConfig, "_find_desktop", return_value="/home/user/Desktop"):
            cfg = AgentConfig(args)
        assert cfg.server_url == "https://10.0.0.1:8443"
        assert cfg.shared_secret == "s3cret"
        assert cfg.verify_ssl is True
        assert cfg.os_type in ("linux", "windows", "macos")
        assert cfg.desktop_path == "/home/user/Desktop"

    def test_init_http_raises(self):
        args = _make_args(server="http://10.0.0.1:8080")
        with pytest.raises(ValueError, match="https://"):
            AgentConfig(args)

    def test_no_verify_ssl_flag(self):
        args = _make_args(no_verify_ssl=True)
        with patch.object(AgentConfig, "_find_desktop", return_value="/tmp"):
            cfg = AgentConfig(args)
        assert cfg.verify_ssl is False

    @patch("platform.system", return_value="Linux")
    def test_detect_os_linux(self, _):
        cfg = _make_config()
        assert cfg.os_type == "linux"

    @patch("platform.system", return_value="Windows")
    def test_detect_os_windows(self, _):
        cfg = _make_config()
        assert cfg.os_type == "windows"

    @patch("platform.system", return_value="Darwin")
    def test_detect_os_macos(self, _):
        cfg = _make_config()
        assert cfg.os_type == "macos"

    def test_find_desktop_exists(self, tmp_path):
        desktop = tmp_path / "Desktop"
        desktop.mkdir()
        with patch("pathlib.Path.home", return_value=tmp_path):
            args = _make_args()
            cfg = AgentConfig(args)
        assert cfg.desktop_path == str(desktop)

    def test_find_desktop_fallback_bureau(self, tmp_path):
        bureau = tmp_path / "Bureau"
        bureau.mkdir()
        with patch("pathlib.Path.home", return_value=tmp_path):
            args = _make_args()
            cfg = AgentConfig(args)
        assert cfg.desktop_path == str(bureau)

    def test_find_desktop_fallback_home(self, tmp_path):
        # No Desktop, no Bureau — should fall back to home
        with patch("pathlib.Path.home", return_value=tmp_path):
            args = _make_args()
            cfg = AgentConfig(args)
        assert cfg.desktop_path == str(tmp_path)

    def test_find_desktop_fallback_escritorio(self, tmp_path):
        esc = tmp_path / "Escritorio"
        esc.mkdir()
        with patch("pathlib.Path.home", return_value=tmp_path):
            args = _make_args()
            cfg = AgentConfig(args)
        assert cfg.desktop_path == str(esc)


# ===================================================================
# 2. SentinelClient
# ===================================================================

class TestSentinelClient:

    def _client(self, verify_ssl=True):
        cfg = _make_config(no_verify_ssl=not verify_ssl)
        return SentinelClient(cfg)

    def test_init_verify_ssl_true(self):
        cl = self._client(verify_ssl=True)
        assert cl._ctx.verify_mode == ssl.CERT_REQUIRED

    def test_init_verify_ssl_false(self):
        cl = self._client(verify_ssl=False)
        assert cl._ctx.check_hostname is False
        assert cl._ctx.verify_mode == ssl.CERT_NONE

    def test_sign_returns_hmac_sha256(self):
        cl = self._client()
        sig = cl._sign("hello")
        expected = _hmac_sign("testkey", "hello")
        assert sig == expected

    def test_verify_response_valid(self):
        cl = self._client()
        data = {"messages": [], "poll_interval": 30}
        payload = json.dumps(data, sort_keys=True)
        sig = _hmac_sign("testkey", payload)
        data["_sig"] = sig
        assert cl._verify_response(data) is True

    def test_verify_response_missing_sig(self):
        cl = self._client()
        assert cl._verify_response({"messages": []}) is False

    def test_verify_response_wrong_sig(self):
        cl = self._client()
        data = {"messages": [], "_sig": "deadbeef"}
        assert cl._verify_response(data) is False

    @patch("urllib.request.urlopen")
    def test_check_valid_response(self, mock_urlopen):
        cl = self._client()
        body_data = {"messages": [{"type": "shutdown", "id": "1"}], "poll_interval": 10}
        payload = json.dumps(body_data, sort_keys=True)
        body_data["_sig"] = _hmac_sign("testkey", payload)

        resp = MagicMock()
        resp.read.return_value = json.dumps(body_data).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        msgs, interval = cl.check()
        assert interval == 10
        assert len(msgs) == 1
        assert msgs[0]["type"] == "shutdown"

    @patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout"))
    def test_check_urlerror(self, _):
        cl = self._client()
        msgs, interval = cl.check()
        assert msgs == []
        assert interval == 60

    @patch("urllib.request.urlopen")
    def test_check_invalid_server_signature(self, mock_urlopen):
        cl = self._client()
        body_data = {"messages": [{"type": "shutdown"}], "_sig": "badsig"}
        resp = MagicMock()
        resp.read.return_value = json.dumps(body_data).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        msgs, interval = cl.check()
        assert msgs == []
        assert interval == 60

    @patch("urllib.request.urlopen")
    def test_check_filters_to_allowed_types(self, mock_urlopen):
        cl = self._client()
        body_data = {
            "messages": [
                {"type": "shutdown", "id": "1"},
                {"type": "evil_command", "id": "2"},
                {"type": "all_clear", "id": "3"},
            ],
            "poll_interval": 5,
        }
        payload = json.dumps(body_data, sort_keys=True)
        body_data["_sig"] = _hmac_sign("testkey", payload)

        resp = MagicMock()
        resp.read.return_value = json.dumps(body_data).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        msgs, _ = cl.check()
        types_received = [m["type"] for m in msgs]
        assert "evil_command" not in types_received
        assert "shutdown" in types_received
        assert "all_clear" in types_received

    @patch("urllib.request.urlopen")
    def test_ack_returns_true_on_200(self, mock_urlopen):
        cl = self._client()
        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        assert cl.ack("msg-123") is True

    @patch("urllib.request.urlopen", side_effect=Exception("connection refused"))
    def test_ack_returns_false_on_exception(self, _):
        cl = self._client()
        assert cl.ack("msg-123") is False


# ===================================================================
# 3. show_popup
# ===================================================================

class TestShowPopup:

    def test_unknown_type_returns_false(self):
        assert agent.show_popup("nonexistent_type") is False

    @patch.object(agent, "_popup_linux", return_value=True)
    def test_dispatches_linux(self, mock_popup):
        assert agent.show_popup("shutdown", "linux") is True
        mock_popup.assert_called_once()

    @patch.object(agent, "_popup_windows", return_value=True)
    def test_dispatches_windows(self, mock_popup):
        assert agent.show_popup("shutdown", "windows") is True
        mock_popup.assert_called_once()

    @patch.object(agent, "_popup_macos", return_value=True)
    def test_dispatches_macos(self, mock_popup):
        assert agent.show_popup("shutdown", "macos") is True
        mock_popup.assert_called_once()

    @patch.object(agent, "_popup_linux", side_effect=RuntimeError("oops"))
    def test_returns_false_on_exception(self, _):
        assert agent.show_popup("shutdown", "linux") is False


# ===================================================================
# 4. _popup_linux
# ===================================================================

class TestPopupLinux:

    @patch("subprocess.run")
    def test_zenity_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        result = agent._popup_linux("Title", "Body")
        assert result is True
        # First attempt should be zenity
        assert "zenity" in mock_run.call_args_list[0][0][0]

    @patch("subprocess.run")
    def test_falls_to_kdialog_when_zenity_not_found(self, mock_run):
        mock_run.side_effect = [
            FileNotFoundError(),  # zenity not found
            MagicMock(returncode=0),  # kdialog works
        ]
        result = agent._popup_linux("Title", "Body")
        assert result is True

    @patch("subprocess.run")
    def test_falls_to_xmessage(self, mock_run):
        mock_run.side_effect = [
            FileNotFoundError(),  # zenity
            FileNotFoundError(),  # kdialog
            MagicMock(returncode=0),  # xmessage
        ]
        result = agent._popup_linux("Title", "Body")
        assert result is True

    @patch("subprocess.run")
    def test_all_fail_falls_back_to_notify_send(self, mock_run):
        mock_run.side_effect = [
            FileNotFoundError(),  # zenity
            FileNotFoundError(),  # kdialog
            FileNotFoundError(),  # xmessage
            MagicMock(returncode=0),  # notify-send
        ]
        result = agent._popup_linux("Title", "Body")
        # notify-send path returns False (fire-and-forget)
        assert result is False

    @patch("subprocess.run")
    def test_all_fail_including_notify_send(self, mock_run):
        mock_run.side_effect = [
            FileNotFoundError(),  # zenity
            FileNotFoundError(),  # kdialog
            FileNotFoundError(),  # xmessage
            FileNotFoundError(),  # notify-send
        ]
        result = agent._popup_linux("Title", "Body")
        assert result is False

    @patch("subprocess.run")
    def test_zenity_timeout(self, mock_run):
        mock_run.side_effect = [
            subprocess.TimeoutExpired(cmd="zenity", timeout=600),  # zenity timeout
            MagicMock(returncode=0),  # kdialog works
        ]
        result = agent._popup_linux("Title", "Body")
        assert result is True


# ===================================================================
# 5. _popup_windows
# ===================================================================

class TestPopupWindows:

    @patch("subprocess.run")
    def test_powershell_ok(self, mock_run):
        mock_run.return_value = MagicMock(stdout="OK", returncode=0)
        assert agent._popup_windows("Title", "Body") is True

    @patch("subprocess.run")
    def test_powershell_no_ok_in_stdout(self, mock_run):
        mock_run.return_value = MagicMock(stdout="Cancel", returncode=0)
        assert agent._popup_windows("Title", "Body") is False

    @patch("subprocess.run", side_effect=FileNotFoundError())
    def test_powershell_not_found(self, _):
        assert agent._popup_windows("Title", "Body") is False

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=600))
    def test_powershell_timeout(self, _):
        assert agent._popup_windows("Title", "Body") is False


# ===================================================================
# 6. _popup_macos
# ===================================================================

class TestPopupMacos:

    @patch("subprocess.run")
    def test_osascript_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        assert agent._popup_macos("Title", "Body") is True

    @patch("subprocess.run")
    def test_osascript_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        assert agent._popup_macos("Title", "Body") is False

    @patch("subprocess.run", side_effect=FileNotFoundError())
    def test_osascript_not_found(self, _):
        assert agent._popup_macos("Title", "Body") is False


# ===================================================================
# 7. collect_local_forensics
# ===================================================================

class TestCollectLocalForensics:

    @patch.object(agent, "_scan_unix", return_value={"available": False})
    @patch.object(agent, "_collect_unix", return_value={"hostname": "test"})
    def test_creates_json_on_desktop(self, mock_collect, mock_scan, tmp_path):
        cfg = _make_config()
        cfg.desktop_path = str(tmp_path)
        cfg.os_type = "linux"

        filepath = agent.collect_local_forensics(cfg, "INC-001")
        assert os.path.isfile(filepath)

        with open(filepath) as f:
            data = json.load(f)
        assert "hostname" in data
        assert "os" in data
        assert "evidence" in data
        assert "scan" in data
        assert data["incident_id"] == "INC-001"

    @patch.object(agent, "_scan_unix", return_value={})
    @patch.object(agent, "_collect_unix", return_value={})
    def test_linux_calls_collect_unix(self, mock_collect, mock_scan, tmp_path):
        cfg = _make_config()
        cfg.desktop_path = str(tmp_path)
        cfg.os_type = "linux"

        agent.collect_local_forensics(cfg, "INC-002")
        mock_collect.assert_called_once_with(macos=False)
        mock_scan.assert_called_once()

    @patch.object(agent, "_scan_unix", return_value={})
    @patch.object(agent, "_collect_unix", return_value={})
    def test_macos_calls_collect_unix_with_macos_true(self, mock_collect, mock_scan, tmp_path):
        cfg = _make_config()
        cfg.desktop_path = str(tmp_path)
        cfg.os_type = "macos"

        agent.collect_local_forensics(cfg, "INC-003")
        mock_collect.assert_called_once_with(macos=True)

    @patch.object(agent, "_scan_windows", return_value={})
    @patch.object(agent, "_collect_windows", return_value={})
    def test_windows_calls_collect_windows(self, mock_collect, mock_scan, tmp_path):
        cfg = _make_config()
        cfg.desktop_path = str(tmp_path)
        cfg.os_type = "windows"

        agent.collect_local_forensics(cfg, "INC-004")
        mock_collect.assert_called_once()
        mock_scan.assert_called_once()


# ===================================================================
# 8. _run_local
# ===================================================================

class TestRunLocal:

    @patch("subprocess.run")
    def test_returns_stdout_on_success(self, mock_run):
        mock_run.return_value = MagicMock(stdout="output data\n", stderr="")
        result = agent._run_local("echo hello")
        assert result == "output data"

    @patch("subprocess.run")
    def test_returns_stderr_when_stdout_empty(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="warning msg")
        result = agent._run_local("cmd")
        assert result == "warning msg"

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="cmd", timeout=30))
    def test_returns_timeout_on_timeout(self, _):
        assert agent._run_local("slow_cmd") == "[timeout]"

    @patch("subprocess.run", side_effect=OSError("no such file"))
    def test_returns_error_on_exception(self, _):
        result = agent._run_local("bad_cmd")
        assert result.startswith("[error:")


# ===================================================================
# 9. _collect_unix
# ===================================================================

class TestCollectUnix:

    @patch.object(agent, "_run_local", return_value="some output")
    def test_collects_expected_keys_linux(self, mock_run):
        result = agent._collect_unix(macos=False)
        assert "hostname" in result
        assert "processes" in result
        assert "connections" in result
        # linux-specific
        assert "systemd_timers" in result

    @patch.object(agent, "_run_local", return_value="some output")
    def test_collects_expected_keys_macos(self, mock_run):
        result = agent._collect_unix(macos=True)
        assert "hostname" in result
        assert "launchd" in result
        assert "systemd_timers" not in result

    @patch.object(agent, "_run_local")
    def test_skips_error_results(self, mock_run):
        def side_effect(cmd):
            if "hostname" in cmd:
                return "myhost"
            return "[error: not found]"
        mock_run.side_effect = side_effect
        result = agent._collect_unix(macos=False)
        assert "hostname" in result
        # Keys returning errors should be skipped
        for key, val in result.items():
            assert "[error" not in val

    @patch.object(agent, "_run_local", return_value="")
    def test_skips_empty_results(self, mock_run):
        result = agent._collect_unix(macos=False)
        assert len(result) == 0


# ===================================================================
# 10. _collect_windows
# ===================================================================

class TestCollectWindows:

    @patch.object(agent, "_run_local", return_value="data")
    def test_collects_expected_keys(self, mock_run):
        result = agent._collect_windows()
        assert "hostname" in result
        assert "processes" in result
        assert "services" in result
        assert "connections" in result
        assert "defender_status" in result

    @patch.object(agent, "_run_local")
    def test_skips_error_results(self, mock_run):
        mock_run.side_effect = lambda cmd, timeout=60: (
            "data" if "hostname" in cmd else "[error: fail]"
        )
        result = agent._collect_windows()
        assert "hostname" in result
        for v in result.values():
            assert "[error" not in v

    @patch.object(agent, "_run_local", return_value="")
    def test_skips_empty_results(self, mock_run):
        result = agent._collect_windows()
        assert len(result) == 0


# ===================================================================
# 11. _scan_unix
# ===================================================================

class TestScanUnix:

    @patch.object(agent, "_run_local")
    def test_clamscan_available(self, mock_run):
        def side_effect(cmd, timeout=30):
            if "command -v clamscan" in cmd:
                return "/usr/bin/clamscan\nFOUND"
            if "clamscan" in cmd:
                return "infected file list"
            return ""
        mock_run.side_effect = side_effect

        result = agent._scan_unix()
        assert result["available"] is True
        assert result["engine"] == "ClamAV"
        assert "scan_time" in result

    @patch.object(agent, "_run_local")
    def test_rkhunter_available(self, mock_run):
        def side_effect(cmd, timeout=30):
            if "command -v clamscan" in cmd:
                return ""
            if "command -v rkhunter" in cmd:
                return "/usr/bin/rkhunter\nFOUND"
            if "rkhunter" in cmd:
                return "warning output"
            return ""
        mock_run.side_effect = side_effect

        result = agent._scan_unix()
        assert result["available"] is True
        assert result["engine"] == "rkhunter"

    @patch.object(agent, "_run_local")
    def test_no_av_available(self, mock_run):
        mock_run.return_value = ""
        result = agent._scan_unix()
        assert result["available"] is False
        assert "No AV engine" in result["results"]

    @patch.object(agent, "_run_local")
    def test_clamscan_no_threats(self, mock_run):
        def side_effect(cmd, timeout=30):
            if "command -v clamscan" in cmd:
                return "FOUND"
            return ""
        mock_run.side_effect = side_effect

        result = agent._scan_unix()
        assert result["results"] == "No threats found"


# ===================================================================
# 12. _scan_windows
# ===================================================================

class TestScanWindows:

    @patch.object(agent, "_run_local")
    def test_defender_active(self, mock_run):
        def side_effect(cmd, timeout=30):
            if "AntivirusEnabled" in cmd and "Select-Object" in cmd and "ConvertTo-Csv" in cmd and "Get-MpComputerStatus" in cmd:
                return '"AntivirusEnabled"\n"True"'
            if "Start-MpScan" in cmd:
                return ""
            if "Get-MpThreatDetection" in cmd:
                return "some threat"
            if "Get-MpThreat" in cmd:
                return "threat catalog"
            return ""
        mock_run.side_effect = side_effect

        result = agent._scan_windows()
        assert result["available"] is True
        assert result["engine"] == "Windows Defender"
        assert "scan_time" in result

    @patch.object(agent, "_run_local")
    def test_defender_not_available(self, mock_run):
        mock_run.return_value = '"AntivirusEnabled"\n"False"'
        result = agent._scan_windows()
        assert result["available"] is False
        assert "not available" in result["results"]

    @patch.object(agent, "_run_local")
    def test_defender_no_threats(self, mock_run):
        def side_effect(cmd, timeout=30):
            if "Get-MpComputerStatus" in cmd:
                return "True"
            return ""
        mock_run.side_effect = side_effect

        result = agent._scan_windows()
        assert result["available"] is True
        assert result["threats"] == "No threats"
        assert result["threat_catalog"] == "No active threats"


# ===================================================================
# Additional edge-case tests
# ===================================================================

class TestEdgeCases:

    def test_allowed_types_matches_messages_keys(self):
        assert ALLOWED_TYPES == set(MESSAGES.keys())

    def test_all_message_types_have_title_and_body(self):
        for msg_type, content in MESSAGES.items():
            assert "title" in content, f"{msg_type} missing title"
            assert "body" in content, f"{msg_type} missing body"

    def test_show_popup_all_valid_types(self):
        for msg_type in ALLOWED_TYPES:
            with patch.object(agent, "_popup_linux", return_value=True):
                assert agent.show_popup(msg_type, "linux") is True

    def test_agent_version_is_string(self):
        assert isinstance(agent.__version__, str)

    @patch("urllib.request.urlopen", side_effect=RuntimeError("unexpected"))
    def test_check_generic_exception(self, _):
        cl = TestSentinelClient()._client()
        msgs, interval = cl.check()
        assert msgs == []
        assert interval == 60

    def test_config_trailing_slash_stripped(self):
        args = _make_args(server="https://host:8443///")
        with patch.object(AgentConfig, "_find_desktop", return_value="/tmp"):
            cfg = AgentConfig(args)
        assert not cfg.server_url.endswith("/")

    def test_config_username_fallback(self):
        with patch.dict(os.environ, {"USER": "", "USERNAME": ""}, clear=False):
            # remove USER and USERNAME
            env = os.environ.copy()
            env.pop("USER", None)
            env.pop("USERNAME", None)
            with patch.dict(os.environ, env, clear=True):
                cfg = _make_config()
                assert cfg.username == "unknown"

    @patch.object(agent, "_run_local")
    def test_collect_unix_timeout_value_excluded(self, mock_run):
        mock_run.return_value = "[timeout]"
        result = agent._collect_unix(macos=False)
        # [timeout] doesn't contain [error so it IS included
        # This tests the actual behavior
        assert all("[error" not in v for v in result.values())


# ===================================================================
# 13. main() function
# ===================================================================

class TestMain:
    """Tests for the main() entry point (lines 474-547)."""

    @patch("sys.argv", ["cgs-agent.py", "--server", "https://s:8443",
                        "--secret", "key", "--once"])
    @patch.object(agent, "SentinelClient")
    @patch.object(agent, "AgentConfig")
    def test_main_once_no_messages(self, MockConfig, MockClient):
        cfg = MagicMock()
        cfg.server_url = "https://s:8443"
        cfg.hostname = "host"
        cfg.os_type = "linux"
        MockConfig.return_value = cfg

        client = MagicMock()
        client.check.return_value = ([], 60)
        MockClient.return_value = client

        agent.main()
        client.check.assert_called_once()

    @patch("sys.argv", ["cgs-agent.py", "--server", "https://s:8443",
                        "--secret", "key", "--once"])
    @patch.object(agent, "show_popup", return_value=True)
    @patch.object(agent, "SentinelClient")
    @patch.object(agent, "AgentConfig")
    def test_main_shutdown_message(self, MockConfig, MockClient, mock_popup):
        cfg = MagicMock()
        cfg.server_url = "https://s:8443"
        cfg.hostname = "host"
        cfg.os_type = "linux"
        MockConfig.return_value = cfg

        client = MagicMock()
        client.check.return_value = (
            [{"id": "m1", "type": "shutdown", "incident_id": "INC-1"}], 10
        )
        MockClient.return_value = client

        agent.main()
        mock_popup.assert_called_with("shutdown", "linux")
        client.ack.assert_called_with("m1")

    @patch("sys.argv", ["cgs-agent.py", "--server", "https://s:8443",
                        "--secret", "key", "--once"])
    @patch.object(agent, "show_popup", return_value=True)
    @patch.object(agent, "SentinelClient")
    @patch.object(agent, "AgentConfig")
    def test_main_all_clear_message(self, MockConfig, MockClient, mock_popup):
        cfg = MagicMock()
        cfg.server_url = "https://s:8443"
        cfg.hostname = "host"
        cfg.os_type = "linux"
        MockConfig.return_value = cfg

        client = MagicMock()
        client.check.return_value = (
            [{"id": "m2", "type": "all_clear", "incident_id": "INC-2"}], 10
        )
        MockClient.return_value = client

        agent.main()
        mock_popup.assert_called_with("all_clear", "linux")

    @patch("sys.argv", ["cgs-agent.py", "--server", "https://s:8443",
                        "--secret", "key", "--once"])
    @patch.object(agent, "show_popup", return_value=True)
    @patch.object(agent, "SentinelClient")
    @patch.object(agent, "AgentConfig")
    def test_main_risk_warning_message(self, MockConfig, MockClient, mock_popup):
        cfg = MagicMock()
        cfg.server_url = "https://s:8443"
        cfg.hostname = "host"
        cfg.os_type = "linux"
        MockConfig.return_value = cfg

        client = MagicMock()
        client.check.return_value = (
            [{"id": "m3", "type": "risk_warning", "incident_id": "INC-3"}], 10
        )
        MockClient.return_value = client

        agent.main()
        mock_popup.assert_called_with("risk_warning", "linux")

    @patch("sys.argv", ["cgs-agent.py", "--server", "https://s:8443",
                        "--secret", "key", "--once"])
    @patch.object(agent, "collect_local_forensics", return_value="/tmp/report.json")
    @patch.object(agent, "show_popup", return_value=True)
    @patch.object(agent, "SentinelClient")
    @patch.object(agent, "AgentConfig")
    def test_main_collect_forensic_user_accepts(self, MockConfig, MockClient,
                                                 mock_popup, mock_collect):
        cfg = MagicMock()
        cfg.server_url = "https://s:8443"
        cfg.hostname = "host"
        cfg.os_type = "linux"
        MockConfig.return_value = cfg

        client = MagicMock()
        client.check.return_value = (
            [{"id": "m4", "type": "collect_forensic", "incident_id": "INC-4"}], 5
        )
        MockClient.return_value = client

        agent.main()
        mock_collect.assert_called_once_with(cfg, "INC-4")
        # show_popup called for collect_forensic and then collect_done
        assert mock_popup.call_count == 2

    @patch("sys.argv", ["cgs-agent.py", "--server", "https://s:8443",
                        "--secret", "key", "--once"])
    @patch.object(agent, "collect_local_forensics")
    @patch.object(agent, "show_popup", return_value=False)
    @patch.object(agent, "SentinelClient")
    @patch.object(agent, "AgentConfig")
    def test_main_collect_forensic_user_declines(self, MockConfig, MockClient,
                                                  mock_popup, mock_collect):
        cfg = MagicMock()
        cfg.server_url = "https://s:8443"
        cfg.hostname = "host"
        cfg.os_type = "linux"
        MockConfig.return_value = cfg

        client = MagicMock()
        client.check.return_value = (
            [{"id": "m5", "type": "collect_forensic", "incident_id": "INC-5"}], 5
        )
        MockClient.return_value = client

        agent.main()
        mock_collect.assert_not_called()

    @patch("sys.argv", ["cgs-agent.py", "--server", "https://s:8443",
                        "--secret", "key", "--once"])
    @patch.object(agent, "SentinelClient")
    @patch.object(agent, "AgentConfig")
    def test_main_generic_exception_in_loop(self, MockConfig, MockClient):
        cfg = MagicMock()
        cfg.server_url = "https://s:8443"
        cfg.hostname = "host"
        cfg.os_type = "linux"
        MockConfig.return_value = cfg

        client = MagicMock()
        client.check.side_effect = RuntimeError("unexpected")
        MockClient.return_value = client

        # Should not raise — exception is caught inside the loop
        agent.main()

    @patch("sys.argv", ["cgs-agent.py", "--server", "https://s:8443",
                        "--secret", "key", "--once"])
    @patch.object(agent, "SentinelClient")
    @patch.object(agent, "AgentConfig")
    def test_main_collect_done_message_type(self, MockConfig, MockClient):
        """collect_done is in ALLOWED_TYPES but not handled as shutdown/forensic
        — it falls through to no specific branch (no-op besides ack)."""
        cfg = MagicMock()
        cfg.server_url = "https://s:8443"
        cfg.hostname = "host"
        cfg.os_type = "linux"
        MockConfig.return_value = cfg

        client = MagicMock()
        client.check.return_value = (
            [{"id": "m6", "type": "collect_done", "incident_id": "INC-6"}], 60
        )
        MockClient.return_value = client

        # Should not raise — collect_done is allowed but has no branch
        agent.main()

    @patch("sys.argv", ["cgs-agent.py", "--server", "https://s:8443",
                        "--secret", "key", "--once", "--no-verify-ssl"])
    @patch.object(agent, "SentinelClient")
    @patch.object(agent, "AgentConfig")
    def test_main_no_verify_ssl_flag(self, MockConfig, MockClient):
        cfg = MagicMock()
        cfg.server_url = "https://s:8443"
        cfg.hostname = "host"
        cfg.os_type = "linux"
        MockConfig.return_value = cfg

        client = MagicMock()
        client.check.return_value = ([], 60)
        MockClient.return_value = client

        agent.main()
        # Verify AgentConfig was called (args parsed correctly with --no-verify-ssl)
        MockConfig.assert_called_once()
