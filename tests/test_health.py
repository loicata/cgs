"""Tests for core/health.py — HealthChecker class.

psutil and get_all_interfaces are fully mocked.
"""

import os
import sys
import tempfile
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path):
    from core.database import init_db, db
    try:
        if not db.is_closed():
            db.close()
    except Exception:
        pass
    init_db(str(tmp_path))
    yield tmp_path
    try:
        db.close()
    except Exception:
        pass


@pytest.fixture
def cfg(test_db):
    from core.config import Config
    import yaml
    cfg_path = os.path.join(str(test_db), "config.yaml")
    with open(cfg_path, "w") as f:
        yaml.dump({
            "general": {"data_dir": str(test_db), "log_dir": str(test_db)},
        }, f)
    return Config(cfg_path)


@pytest.fixture
def alert_fn():
    return MagicMock()


def _mock_psutil():
    """Return a dict of patches for all psutil calls used by HealthChecker."""
    mock_vm = MagicMock()
    mock_vm.percent = 45.0
    mock_vm.used = 4_000_000_000
    mock_vm.total = 16_000_000_000

    mock_partition = MagicMock()
    mock_partition.mountpoint = "/"
    mock_partition.fstype = "ext4"

    mock_disk_usage = MagicMock()
    mock_disk_usage.total = 500_000_000_000
    mock_disk_usage.percent = 55.0
    mock_disk_usage.free = 225_000_000_000

    return {
        "cpu_percent": 30.0,
        "virtual_memory": mock_vm,
        "getloadavg": (1.5, 2.0, 1.8),
        "boot_time": datetime(2026, 1, 1, 0, 0, 0).timestamp(),
        "disk_partitions": [mock_partition],
        "disk_usage": mock_disk_usage,
    }


@pytest.fixture
def health(cfg, alert_fn):
    from core.health import HealthChecker
    return HealthChecker(cfg, alert_fn)


# ===================================================================
# check_all returns system metrics
# ===================================================================

class TestCheckAll:
    @patch("core.health.get_all_interfaces", return_value={"eth0": {"ip": "10.0.0.1"}})
    @patch("core.health.psutil")
    def test_check_all_returns_complete_structure(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = m["disk_partitions"]
        mock_psutil.disk_usage.return_value = m["disk_usage"]

        result = health.check_all()
        assert "ts" in result
        assert "system" in result
        assert "disk" in result
        assert "network" in result

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_check_all_ts_is_iso_format(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = []
        mock_psutil.disk_usage.return_value = m["disk_usage"]

        result = health.check_all()
        # Should be parseable as ISO datetime
        datetime.fromisoformat(result["ts"])

    @patch("core.health.get_all_interfaces", return_value={"lo": {"ip": "127.0.0.1"}})
    @patch("core.health.psutil")
    def test_check_all_network_from_get_all_interfaces(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = []
        result = health.check_all()
        assert result["network"] == {"lo": {"ip": "127.0.0.1"}}


# ===================================================================
# CPU, RAM, disk usage values
# ===================================================================

class TestSystemMetrics:
    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_cpu_percent_value(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = 72.5
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = []

        result = health.check_all()
        assert result["system"]["cpu_percent"] == 72.5

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_memory_values(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = []

        result = health.check_all()
        assert result["system"]["memory_percent"] == 45.0
        assert result["system"]["mem_used_gb"] == 4.0
        assert result["system"]["mem_total_gb"] == 16.0

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_load_average(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = (3.14, 2.71, 1.0)
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = []

        result = health.check_all()
        assert result["system"]["load_1"] == 3.14

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_uptime_hours(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = []

        result = health.check_all()
        assert result["system"]["uptime_h"] > 0

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_disk_usage_values(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = m["disk_partitions"]
        mock_psutil.disk_usage.return_value = m["disk_usage"]

        result = health.check_all()
        assert "/" in result["disk"]
        disk = result["disk"]["/"]
        assert disk["total_gb"] == 500.0
        assert disk["used_pct"] == 55.0
        assert disk["free_gb"] == 225.0

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_disk_skips_snap_partitions(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]

        snap_part = MagicMock()
        snap_part.mountpoint = "/snap/core/12345"
        snap_part.fstype = "squashfs"
        mock_psutil.disk_partitions.return_value = [snap_part]

        result = health.check_all()
        assert len(result["disk"]) == 0

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_disk_skips_boot_efi(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]

        efi_part = MagicMock()
        efi_part.mountpoint = "/boot/efi"
        efi_part.fstype = "vfat"
        mock_psutil.disk_partitions.return_value = [efi_part]

        result = health.check_all()
        assert "/boot/efi" not in result["disk"]

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_disk_skips_run(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]

        run_part = MagicMock()
        run_part.mountpoint = "/run/user/1000"
        run_part.fstype = "tmpfs"
        mock_psutil.disk_partitions.return_value = [run_part]

        result = health.check_all()
        assert len(result["disk"]) == 0

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_disk_handles_permission_error(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]

        part = MagicMock()
        part.mountpoint = "/mnt/external"
        part.fstype = "ext4"
        mock_psutil.disk_partitions.return_value = [part]
        mock_psutil.disk_usage.side_effect = PermissionError("no access")

        result = health.check_all()
        assert "/mnt/external" not in result["disk"]

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_disk_skips_squashfs(self, mock_psutil, mock_ifaces, health):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = m["cpu_percent"]
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]

        part = MagicMock()
        part.mountpoint = "/mnt/data"
        part.fstype = "squashfs"
        mock_psutil.disk_partitions.return_value = [part]

        result = health.check_all()
        assert len(result["disk"]) == 0


# ===================================================================
# Alert on high usage
# ===================================================================

class TestAlertOnHighUsage:
    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_cpu_over_90_triggers_alert(self, mock_psutil, mock_ifaces, health, alert_fn):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = 95.0
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = []

        health.check_all()
        alert_fn.assert_called_once()
        kwargs = alert_fn.call_args[1]
        assert kwargs["category"] == "cpu"
        assert kwargs["severity"] == 2
        assert "95.0" in kwargs["title"]

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_cpu_under_90_no_alert(self, mock_psutil, mock_ifaces, health, alert_fn):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = 85.0
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = []

        health.check_all()
        alert_fn.assert_not_called()

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_ram_over_90_triggers_alert(self, mock_psutil, mock_ifaces, health, alert_fn):
        m = _mock_psutil()
        mock_vm = MagicMock()
        mock_vm.percent = 95.0
        mock_vm.used = 15_200_000_000
        mock_vm.total = 16_000_000_000
        mock_psutil.cpu_percent.return_value = 20.0
        mock_psutil.virtual_memory.return_value = mock_vm
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = []

        health.check_all()
        alert_fn.assert_called_once()
        kwargs = alert_fn.call_args[1]
        assert kwargs["category"] == "ram"

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_ram_under_90_no_alert(self, mock_psutil, mock_ifaces, health, alert_fn):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = 20.0
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]  # 45%
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = []

        health.check_all()
        alert_fn.assert_not_called()

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_disk_over_90_triggers_alert(self, mock_psutil, mock_ifaces, health, alert_fn):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = 20.0
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]

        part = MagicMock()
        part.mountpoint = "/"
        part.fstype = "ext4"
        mock_disk = MagicMock()
        mock_disk.total = 500_000_000_000
        mock_disk.percent = 95.0
        mock_disk.free = 25_000_000_000
        mock_psutil.disk_partitions.return_value = [part]
        mock_psutil.disk_usage.return_value = mock_disk

        health.check_all()
        alert_fn.assert_called_once()
        kwargs = alert_fn.call_args[1]
        assert kwargs["category"] == "disk"
        assert "95.0" in kwargs["title"]

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_disk_under_90_no_alert(self, mock_psutil, mock_ifaces, health, alert_fn):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = 20.0
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = m["disk_partitions"]
        mock_psutil.disk_usage.return_value = m["disk_usage"]  # 55%

        health.check_all()
        alert_fn.assert_not_called()

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_multiple_alerts_cpu_ram_disk(self, mock_psutil, mock_ifaces, health, alert_fn):
        mock_vm = MagicMock()
        mock_vm.percent = 95.0
        mock_vm.used = 15_200_000_000
        mock_vm.total = 16_000_000_000

        mock_psutil.cpu_percent.return_value = 95.0
        mock_psutil.virtual_memory.return_value = mock_vm
        mock_psutil.getloadavg.return_value = (5.0, 4.0, 3.0)
        mock_psutil.boot_time.return_value = _mock_psutil()["boot_time"]

        part = MagicMock()
        part.mountpoint = "/"
        part.fstype = "ext4"
        mock_disk = MagicMock()
        mock_disk.total = 500_000_000_000
        mock_disk.percent = 95.0
        mock_disk.free = 25_000_000_000
        mock_psutil.disk_partitions.return_value = [part]
        mock_psutil.disk_usage.return_value = mock_disk

        health.check_all()
        assert alert_fn.call_count == 3  # CPU + RAM + disk

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_cpu_exactly_90_no_alert(self, mock_psutil, mock_ifaces, health, alert_fn):
        """Threshold is > 90, so exactly 90 should not trigger."""
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = 90.0
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]
        mock_psutil.disk_partitions.return_value = []

        health.check_all()
        alert_fn.assert_not_called()

    @patch("core.health.get_all_interfaces", return_value={})
    @patch("core.health.psutil")
    def test_multiple_disk_alerts(self, mock_psutil, mock_ifaces, health, alert_fn):
        m = _mock_psutil()
        mock_psutil.cpu_percent.return_value = 20.0
        mock_psutil.virtual_memory.return_value = m["virtual_memory"]
        mock_psutil.getloadavg.return_value = m["getloadavg"]
        mock_psutil.boot_time.return_value = m["boot_time"]

        part1 = MagicMock()
        part1.mountpoint = "/"
        part1.fstype = "ext4"
        part2 = MagicMock()
        part2.mountpoint = "/home"
        part2.fstype = "ext4"
        mock_disk = MagicMock()
        mock_disk.total = 500_000_000_000
        mock_disk.percent = 95.0
        mock_disk.free = 25_000_000_000
        mock_psutil.disk_partitions.return_value = [part1, part2]
        mock_psutil.disk_usage.return_value = mock_disk

        health.check_all()
        assert alert_fn.call_count == 2  # Both disks over 90%


# ===================================================================
# Constructor
# ===================================================================

class TestConstructor:
    def test_stores_config_and_alert_fn(self, health, cfg, alert_fn):
        assert health.cfg is cfg
        assert health._alert is alert_fn
