"""Tests for core/snapshot.py — DefenseSnapshot."""

import json
import os
import sys
from unittest.mock import patch, MagicMock, mock_open

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.snapshot import DefenseSnapshot


class FakeConfig:
    def __init__(self, log_dir):
        self._log_dir = log_dir

    def get(self, key, default=None):
        if key == "general.log_dir":
            return self._log_dir
        return default


@pytest.fixture
def snap(tmp_path):
    cfg = FakeConfig(str(tmp_path))
    return DefenseSnapshot(cfg)


def _mock_subprocess_run_success(cmd, **kwargs):
    """Default mock: all subprocess calls succeed."""
    m = MagicMock()
    m.returncode = 0
    m.stdout = "# iptables-save output\n*filter\n:INPUT ACCEPT\nCOMMIT\n"
    return m


def _mock_subprocess_run_fail(cmd, **kwargs):
    m = MagicMock()
    m.returncode = 1
    m.stdout = ""
    return m


# ── Init ──

class TestInit:
    def test_creates_snapshot_directory(self, tmp_path):
        cfg = FakeConfig(str(tmp_path))
        s = DefenseSnapshot(cfg)
        assert os.path.isdir(s.snapshot_dir)
        assert s.snapshot_dir.endswith("snapshots")


# ── Take snapshot ──

class TestTake:
    @patch("core.snapshot.subprocess.run", side_effect=_mock_subprocess_run_success)
    def test_take_creates_json_file(self, mock_run, snap):
        with patch.object(snap, "_capture_etc_hosts", return_value="127.0.0.1 localhost\n"):
            path = snap.take("INC-001", reason="before block")
        assert os.path.exists(path)
        assert path.endswith(".json")
        with open(path) as f:
            data = json.load(f)
        assert data["incident_id"] == "INC-001"
        assert data["reason"] == "before block"
        assert "iptables" in data
        assert "nftables" in data
        assert "etc_hosts" in data
        assert "cgs_chain" in data

    @patch("core.snapshot.subprocess.run", side_effect=_mock_subprocess_run_success)
    def test_take_returns_valid_path(self, mock_run, snap):
        with patch.object(snap, "_capture_etc_hosts", return_value=""):
            path = snap.take("INC-002")
        assert "snap_INC-002" in os.path.basename(path)

    @patch("core.snapshot.subprocess.run", side_effect=_mock_subprocess_run_fail)
    def test_take_with_failed_subprocess_stores_empty(self, mock_run, snap):
        with patch.object(snap, "_capture_etc_hosts", return_value=""):
            path = snap.take("INC-003")
        with open(path) as f:
            data = json.load(f)
        assert data["iptables"] == ""
        assert data["nftables"] == ""
        assert data["cgs_chain"] == ""


# ── Capture methods ──

class TestCaptureMethods:
    @patch("core.snapshot.subprocess.run")
    def test_capture_iptables_success(self, mock_run, snap):
        mock_run.return_value = MagicMock(returncode=0, stdout="*filter\nCOMMIT\n")
        result = snap._capture_iptables()
        assert result == "*filter\nCOMMIT\n"

    @patch("core.snapshot.subprocess.run")
    def test_capture_iptables_failure(self, mock_run, snap):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert snap._capture_iptables() == ""

    @patch("core.snapshot.subprocess.run", side_effect=Exception("no iptables"))
    def test_capture_iptables_exception(self, mock_run, snap):
        assert snap._capture_iptables() == ""

    @patch("core.snapshot.subprocess.run")
    def test_capture_nftables_success(self, mock_run, snap):
        mock_run.return_value = MagicMock(returncode=0, stdout="table inet filter {}")
        assert snap._capture_nftables() == "table inet filter {}"

    @patch("core.snapshot.subprocess.run", side_effect=Exception("no nft"))
    def test_capture_nftables_exception(self, mock_run, snap):
        assert snap._capture_nftables() == ""

    def test_capture_etc_hosts_reads_file(self, snap, tmp_path):
        m = mock_open(read_data="127.0.0.1 localhost\n")
        with patch("builtins.open", m):
            result = snap._capture_etc_hosts()
        assert "localhost" in result

    def test_capture_etc_hosts_exception(self, snap):
        with patch("builtins.open", side_effect=PermissionError("denied")):
            assert snap._capture_etc_hosts() == ""

    @patch("core.snapshot.subprocess.run")
    def test_capture_cgs_chain_success(self, mock_run, snap):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Chain CGS\n1  DROP  all  --  45.33.32.156  0.0.0.0/0\n",
        )
        result = snap._capture_cgs_chain()
        assert "CGS" in result

    @patch("core.snapshot.subprocess.run", side_effect=Exception("no chain"))
    def test_capture_cgs_chain_exception(self, mock_run, snap):
        assert snap._capture_cgs_chain() == ""


# ── Restore ──

class TestRestore:
    def test_restore_nonexistent_file(self, snap):
        result = snap.restore("/nonexistent/snap.json")
        assert result["ok"] is False
        assert len(result["errors"]) >= 1

    @patch("core.snapshot.subprocess.run")
    def test_restore_iptables_success(self, mock_run, snap, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        snap_data = {
            "id": "snap_test",
            "incident_id": "INC-001",
            "created_at": "2026-01-01",
            "iptables": "*filter\nCOMMIT\n",
            "nftables": "",
            "etc_hosts": "",
            "cgs_chain": "",
        }
        path = tmp_path / "test_snap.json"
        path.write_text(json.dumps(snap_data))
        result = snap.restore(str(path))
        assert result["ok"] is True
        assert "iptables rules restored" in result["actions"]

    @patch("core.snapshot.subprocess.run")
    def test_restore_iptables_failure(self, mock_run, snap, tmp_path):
        mock_run.return_value = MagicMock(returncode=1)
        snap_data = {
            "id": "snap_test",
            "incident_id": "INC-001",
            "created_at": "2026-01-01",
            "iptables": "*filter\nCOMMIT\n",
            "nftables": "",
            "etc_hosts": "",
            "cgs_chain": "",
        }
        path = tmp_path / "test_snap.json"
        path.write_text(json.dumps(snap_data))
        result = snap.restore(str(path))
        assert result["ok"] is False
        assert "iptables restore failed" in result["errors"]

    @patch("core.snapshot.subprocess.run")
    def test_restore_nftables(self, mock_run, snap, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        snap_data = {
            "id": "snap_nft",
            "incident_id": "INC-002",
            "created_at": "2026-01-01",
            "iptables": "",
            "nftables": "table inet filter {}",
            "etc_hosts": "",
            "cgs_chain": "",
        }
        path = tmp_path / "nft_snap.json"
        path.write_text(json.dumps(snap_data))
        result = snap.restore(str(path))
        assert result["ok"] is True
        assert "nftables rules restored" in result["actions"]

    def test_restore_etc_hosts(self, snap, tmp_path):
        snap_data = {
            "id": "snap_hosts",
            "incident_id": "INC-003",
            "created_at": "2026-01-01",
            "iptables": "",
            "nftables": "",
            "etc_hosts": "127.0.0.1 localhost\n",
            "cgs_chain": "",
        }
        path = tmp_path / "hosts_snap.json"
        path.write_text(json.dumps(snap_data))

        with patch.object(snap, "_restore_etc_hosts", return_value=True) as mock_reh:
            result = snap.restore(str(path))
        assert result["ok"] is True
        assert "/etc/hosts restored" in result["actions"][0]
        mock_reh.assert_called_once_with("127.0.0.1 localhost\n")

    def test_restore_etc_hosts_direct_success(self, snap, tmp_path):
        fake_hosts = tmp_path / "fake_etc_hosts"
        with patch("builtins.open", mock_open()) as m:
            result = snap._restore_etc_hosts("127.0.0.1 localhost\n")
        assert result is True

    def test_restore_etc_hosts_failure(self, snap, tmp_path):
        snap_data = {
            "id": "snap_hosts_fail",
            "incident_id": "INC-004",
            "created_at": "2026-01-01",
            "iptables": "",
            "nftables": "",
            "etc_hosts": "127.0.0.1 localhost\n",
            "cgs_chain": "",
        }
        path = tmp_path / "hosts_snap_fail.json"
        path.write_text(json.dumps(snap_data))

        with patch("builtins.open", side_effect=PermissionError("denied")):
            # This will also fail to read the snapshot, so test differently
            pass

        # Direct method test
        with patch("builtins.open", side_effect=PermissionError("denied")):
            result = snap._restore_etc_hosts("127.0.0.1 localhost\n")
        assert result is False

    @patch("core.snapshot.subprocess.run")
    def test_restore_cgs_chain_with_rules(self, mock_run, snap, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        snap_data = {
            "id": "snap_cgs",
            "incident_id": "INC-005",
            "created_at": "2026-01-01",
            "iptables": "",
            "nftables": "",
            "etc_hosts": "",
            "cgs_chain": "Chain CGS\n1  DROP  all  --  45.33.32.156  0.0.0.0/0\n",
        }
        path = tmp_path / "cgs_snap.json"
        path.write_text(json.dumps(snap_data))
        result = snap.restore(str(path))
        assert result["ok"] is True
        assert "CGS iptables chain restored" in result["actions"]

    @patch("core.snapshot.subprocess.run", side_effect=Exception("fail"))
    def test_restore_cgs_chain_exception(self, mock_run, snap):
        result = snap._restore_cgs_chain("Chain CGS\n1  DROP  all  --  1.2.3.4  0.0.0.0/0\n")
        assert result is False

    def test_restore_iptables_empty_state(self, snap):
        assert snap._restore_iptables("") is True

    def test_restore_nftables_empty_state(self, snap):
        assert snap._restore_nftables("") is True

    def test_restore_etc_hosts_empty_state(self, snap):
        assert snap._restore_etc_hosts("") is True

    @patch("core.snapshot.subprocess.run", side_effect=Exception("fail"))
    def test_restore_iptables_exception(self, mock_run, snap):
        assert snap._restore_iptables("*filter\nCOMMIT") is False

    @patch("core.snapshot.subprocess.run", side_effect=Exception("fail"))
    def test_restore_nftables_exception(self, mock_run, snap):
        assert snap._restore_nftables("table inet filter {}") is False

    @patch("core.snapshot.subprocess.run")
    def test_restore_full_snapshot_all_components(self, mock_run, snap, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        snap_data = {
            "id": "snap_full",
            "incident_id": "INC-006",
            "created_at": "2026-01-01",
            "iptables": "*filter\nCOMMIT",
            "nftables": "table inet filter {}",
            "etc_hosts": "127.0.0.1 localhost",
            "cgs_chain": "Chain CGS\n1  DROP  all  --  1.2.3.4  0.0.0.0/0\n",
        }
        path = tmp_path / "full_snap.json"
        path.write_text(json.dumps(snap_data))
        with patch.object(snap, "_restore_etc_hosts", return_value=True):
            result = snap.restore(str(path))
        assert result["ok"] is True
        assert len(result["actions"]) >= 3


# ── List snapshots ──

class TestListSnapshots:
    @patch("core.snapshot.subprocess.run", side_effect=_mock_subprocess_run_success)
    def test_list_empty(self, mock_run, snap):
        result = snap.list_snapshots()
        assert result == []

    @patch("core.snapshot.subprocess.run", side_effect=_mock_subprocess_run_success)
    def test_list_after_take(self, mock_run, snap):
        with patch.object(snap, "_capture_etc_hosts", return_value=""):
            snap.take("INC-001", reason="test")
            snap.take("INC-002", reason="test2")
        result = snap.list_snapshots()
        assert len(result) == 2
        assert result[0]["incident_id"] in ("INC-001", "INC-002")
        assert "filepath" in result[0]
        assert "size_kb" in result[0]

    def test_list_skips_non_json(self, snap):
        # Create a non-JSON file in snapshot dir
        path = os.path.join(snap.snapshot_dir, "readme.txt")
        with open(path, "w") as f:
            f.write("not a snapshot")
        result = snap.list_snapshots()
        assert len(result) == 0

    def test_list_skips_invalid_json(self, snap):
        path = os.path.join(snap.snapshot_dir, "bad.json")
        with open(path, "w") as f:
            f.write("not valid json {{{")
        result = snap.list_snapshots()
        assert len(result) == 0

    @patch("core.snapshot.subprocess.run", side_effect=_mock_subprocess_run_success)
    def test_list_sorted_newest_first(self, mock_run, snap):
        with patch.object(snap, "_capture_etc_hosts", return_value=""):
            snap.take("INC-A")
            snap.take("INC-Z")
        result = snap.list_snapshots()
        assert len(result) == 2
        # Newest first (reversed alphabetical sort of filenames)
        assert result[0]["id"] >= result[1]["id"]
