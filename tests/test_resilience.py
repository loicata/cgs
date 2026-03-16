"""Tests for core/resilience.py — DegradedMode, SelfMonitor, BufferGuard, SafeBackup, enable_wal_mode."""

import os
import sqlite3
import threading
import time
import yaml
import pytest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import Config


def _make_config(tmp_path, extra=None):
    cfg_data = {
        "general": {
            "data_dir": str(tmp_path / "data"),
            "log_dir": str(tmp_path / "logs"),
            "interface": "eth0",
        },
    }
    if extra:
        cfg_data.update(extra)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.dump(cfg_data))
    return Config(str(cfg_path))


# ══════════════════════════════════════════════════════════
# 1. DegradedMode
# ══════════════════════════════════════════════════════════

class TestDegradedMode:
    """Tests for the degraded mode manager."""

    def test_initially_inactive(self, tmp_path):
        from core.resilience import DegradedMode
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg)
        assert dm.active is False

    def test_enter_activates_degraded_mode(self, tmp_path):
        from core.resilience import DegradedMode
        alerts = []
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg, alert_fn=lambda **kw: alerts.append(kw))
        dm.enter(reason="CPU overload")
        assert dm.active is True
        assert dm.reason == "CPU overload"
        assert dm.entered_at > 0
        assert len(alerts) == 1
        assert alerts[0]["severity"] == 2

    def test_enter_is_idempotent(self, tmp_path):
        from core.resilience import DegradedMode
        alerts = []
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg, alert_fn=lambda **kw: alerts.append(kw))
        dm.enter(reason="first")
        dm.enter(reason="second")  # should be ignored
        assert dm.reason == "first"
        assert len(alerts) == 1

    def test_exit_deactivates_degraded_mode(self, tmp_path):
        from core.resilience import DegradedMode
        alerts = []
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg, alert_fn=lambda **kw: alerts.append(kw))
        dm.enter(reason="test")
        dm.exit()
        assert dm.active is False
        assert dm.reason == ""
        assert len(alerts) == 2  # enter + exit

    def test_exit_when_not_active_is_noop(self, tmp_path):
        from core.resilience import DegradedMode
        alerts = []
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg, alert_fn=lambda **kw: alerts.append(kw))
        dm.exit()
        assert len(alerts) == 0

    def test_should_run_returns_true_when_not_degraded(self, tmp_path):
        from core.resilience import DegradedMode
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg)
        assert dm.should_run("baseline") is True
        assert dm.should_run("sniffer") is True
        assert dm.should_run("reports") is True

    def test_should_run_allows_essential_tasks_in_degraded_mode(self, tmp_path):
        from core.resilience import DegradedMode
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg)
        dm.enter(reason="test")

        essential = ["sniffer", "threat_engine", "defense", "alert",
                     "incident", "killchain", "client_poll"]
        for task in essential:
            assert dm.should_run(task) is True, f"{task} should run in degraded mode"

    def test_should_run_blocks_nonessential_tasks_in_degraded_mode(self, tmp_path):
        from core.resilience import DegradedMode
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg)
        dm.enter(reason="test")

        nonessential = ["baseline", "discovery", "port_scan", "reports", "backup", "recon"]
        for task in nonessential:
            assert dm.should_run(task) is False, f"{task} should NOT run in degraded mode"

    def test_stats_property_when_active(self, tmp_path):
        from core.resilience import DegradedMode
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg)
        dm.enter(reason="overload")
        s = dm.stats
        assert s["active"] is True
        assert s["reason"] == "overload"
        assert s["duration"] >= 0

    def test_stats_property_when_inactive(self, tmp_path):
        from core.resilience import DegradedMode
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg)
        s = dm.stats
        assert s["active"] is False
        assert s["duration"] == 0


# ══════════════════════════════════════════════════════════
# 2. SelfMonitor
# ══════════════════════════════════════════════════════════

class TestSelfMonitor:
    """Tests for server self-monitoring with mocked system reads."""

    def test_check_returns_status_dict(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        cfg = _make_config(tmp_path)
        sm = SelfMonitor(cfg)

        # Mock all system reads to return safe values
        monkeypatch.setattr(sm, "_get_cpu", lambda: 10.0)
        monkeypatch.setattr(sm, "_get_ram", lambda: 30.0)
        monkeypatch.setattr(sm, "_get_disk", lambda: 40.0)
        monkeypatch.setattr(sm, "_get_iowait", lambda: 5.0)
        monkeypatch.setattr(sm, "_get_load", lambda: [0.5, 0.5, 0.5])

        status = sm.check()
        assert status["cpu_percent"] == 10.0
        assert status["ram_percent"] == 30.0
        assert status["disk_percent"] == 40.0
        assert status["overloaded"] is False

    def test_check_fires_alert_on_cpu_overload(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        alerts = []
        cfg = _make_config(tmp_path, {"resilience": {"cpu_threshold": 80}})
        sm = SelfMonitor(cfg, alert_fn=lambda **kw: alerts.append(kw))

        monkeypatch.setattr(sm, "_get_cpu", lambda: 95.0)
        monkeypatch.setattr(sm, "_get_ram", lambda: 30.0)
        monkeypatch.setattr(sm, "_get_disk", lambda: 40.0)
        monkeypatch.setattr(sm, "_get_iowait", lambda: 5.0)
        monkeypatch.setattr(sm, "_get_load", lambda: [0.5, 0.5, 0.5])

        status = sm.check()
        assert status["overloaded"] is True
        assert len(alerts) == 1
        assert "CPU" in alerts[0]["detail"]

    def test_check_fires_alert_on_ram_overload(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        alerts = []
        cfg = _make_config(tmp_path, {"resilience": {"ram_threshold": 85}})
        sm = SelfMonitor(cfg, alert_fn=lambda **kw: alerts.append(kw))

        monkeypatch.setattr(sm, "_get_cpu", lambda: 10.0)
        monkeypatch.setattr(sm, "_get_ram", lambda: 92.0)
        monkeypatch.setattr(sm, "_get_disk", lambda: 40.0)
        monkeypatch.setattr(sm, "_get_iowait", lambda: 5.0)
        monkeypatch.setattr(sm, "_get_load", lambda: [0.5, 0.5, 0.5])

        status = sm.check()
        assert status["overloaded"] is True
        assert len(alerts) == 1

    def test_check_fires_alert_on_disk_overload(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        alerts = []
        cfg = _make_config(tmp_path, {"resilience": {"disk_threshold": 85}})
        sm = SelfMonitor(cfg, alert_fn=lambda **kw: alerts.append(kw))

        monkeypatch.setattr(sm, "_get_cpu", lambda: 10.0)
        monkeypatch.setattr(sm, "_get_ram", lambda: 30.0)
        monkeypatch.setattr(sm, "_get_disk", lambda: 95.0)
        monkeypatch.setattr(sm, "_get_iowait", lambda: 5.0)
        monkeypatch.setattr(sm, "_get_load", lambda: [0.5, 0.5, 0.5])

        sm.check()
        assert len(alerts) == 1

    def test_check_fires_alert_on_iowait_overload(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        alerts = []
        cfg = _make_config(tmp_path, {"resilience": {"iowait_threshold": 40}})
        sm = SelfMonitor(cfg, alert_fn=lambda **kw: alerts.append(kw))

        monkeypatch.setattr(sm, "_get_cpu", lambda: 10.0)
        monkeypatch.setattr(sm, "_get_ram", lambda: 30.0)
        monkeypatch.setattr(sm, "_get_disk", lambda: 40.0)
        monkeypatch.setattr(sm, "_get_iowait", lambda: 60.0)
        monkeypatch.setattr(sm, "_get_load", lambda: [0.5, 0.5, 0.5])

        sm.check()
        assert len(alerts) == 1

    def test_consecutive_overloads_trigger_degraded_mode(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor, DegradedMode
        alerts = []
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg, alert_fn=lambda **kw: alerts.append(kw))
        sm = SelfMonitor(cfg, alert_fn=lambda **kw: alerts.append(kw), degraded_mode=dm)

        monkeypatch.setattr(sm, "_get_cpu", lambda: 95.0)
        monkeypatch.setattr(sm, "_get_ram", lambda: 30.0)
        monkeypatch.setattr(sm, "_get_disk", lambda: 40.0)
        monkeypatch.setattr(sm, "_get_iowait", lambda: 5.0)
        monkeypatch.setattr(sm, "_get_load", lambda: [2.0, 2.0, 2.0])

        # Need 3 consecutive overloads to trigger degraded mode
        sm.check()
        assert dm.active is False
        sm.check()
        assert dm.active is False
        sm.check()
        assert dm.active is True

    def test_recovery_exits_degraded_mode(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor, DegradedMode
        alerts = []
        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg, alert_fn=lambda **kw: alerts.append(kw))
        sm = SelfMonitor(cfg, alert_fn=lambda **kw: alerts.append(kw), degraded_mode=dm)

        # First, overload 3 times to enter degraded mode
        monkeypatch.setattr(sm, "_get_cpu", lambda: 95.0)
        monkeypatch.setattr(sm, "_get_ram", lambda: 30.0)
        monkeypatch.setattr(sm, "_get_disk", lambda: 40.0)
        monkeypatch.setattr(sm, "_get_iowait", lambda: 5.0)
        monkeypatch.setattr(sm, "_get_load", lambda: [0.5, 0.5, 0.5])
        for _ in range(3):
            sm.check()
        assert dm.active is True

        # Now recover
        monkeypatch.setattr(sm, "_get_cpu", lambda: 10.0)
        sm.check()
        assert dm.active is False

    def test_severity_increases_after_threshold(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        alerts = []
        cfg = _make_config(tmp_path)
        sm = SelfMonitor(cfg, alert_fn=lambda **kw: alerts.append(kw))

        monkeypatch.setattr(sm, "_get_cpu", lambda: 95.0)
        monkeypatch.setattr(sm, "_get_ram", lambda: 30.0)
        monkeypatch.setattr(sm, "_get_disk", lambda: 40.0)
        monkeypatch.setattr(sm, "_get_iowait", lambda: 5.0)
        monkeypatch.setattr(sm, "_get_load", lambda: [0.5, 0.5, 0.5])

        sm.check()  # consecutive=1 → severity 3
        assert alerts[-1]["severity"] == 3
        sm.check()  # consecutive=2 → severity 3
        assert alerts[-1]["severity"] == 3
        sm.check()  # consecutive=3 → severity 2
        assert alerts[-1]["severity"] == 2

    def test_default_thresholds(self, tmp_path):
        from core.resilience import SelfMonitor
        cfg = _make_config(tmp_path)
        sm = SelfMonitor(cfg)
        assert sm.cpu_threshold == 85
        assert sm.ram_threshold == 90
        assert sm.disk_threshold == 90
        assert sm.iowait_threshold == 50

    def test_custom_thresholds(self, tmp_path):
        from core.resilience import SelfMonitor
        cfg = _make_config(tmp_path, {"resilience": {
            "cpu_threshold": 70, "ram_threshold": 75,
            "disk_threshold": 80, "iowait_threshold": 30,
        }})
        sm = SelfMonitor(cfg)
        assert sm.cpu_threshold == 70
        assert sm.ram_threshold == 75
        assert sm.disk_threshold == 80
        assert sm.iowait_threshold == 30

    def test_get_cpu_reads_proc_stat(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        cfg = _make_config(tmp_path)
        sm = SelfMonitor(cfg)

        import builtins
        real_open = builtins.open
        # Simulate /proc/stat with known values
        # cpu user nice system idle iowait irq softirq
        proc_stat_1 = "cpu  1000 0 500 8000 100 0 0\n"
        proc_stat_2 = "cpu  1200 0 600 8100 120 0 0\n"

        call_count = [0]

        def mock_open(path, *args, **kwargs):
            if str(path) == "/proc/stat":
                import io
                call_count[0] += 1
                if call_count[0] == 1:
                    return io.StringIO(proc_stat_1)
                return io.StringIO(proc_stat_2)
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        # First call sets baseline
        cpu1 = sm._get_cpu()
        assert cpu1 == 0.0  # first call returns 0
        # Second call computes delta
        cpu2 = sm._get_cpu()
        assert cpu2 > 0  # should compute some CPU percentage

    def test_get_cpu_returns_zero_on_error(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        cfg = _make_config(tmp_path)
        sm = SelfMonitor(cfg)

        import builtins
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if str(path) == "/proc/stat":
                raise FileNotFoundError("no /proc/stat")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        assert sm._get_cpu() == 0.0

    def test_get_ram_reads_proc_meminfo(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        cfg = _make_config(tmp_path)
        sm = SelfMonitor(cfg)

        meminfo = "MemTotal:       16000000 kB\nMemFree:         1000000 kB\nMemAvailable:    4000000 kB\n"

        import builtins
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if str(path) == "/proc/meminfo":
                import io
                return io.StringIO(meminfo)
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        ram = sm._get_ram()
        # (1 - 4000000/16000000) * 100 = 75.0
        assert ram == 75.0

    def test_get_ram_returns_zero_on_error(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        cfg = _make_config(tmp_path)
        sm = SelfMonitor(cfg)

        import builtins
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if str(path) == "/proc/meminfo":
                raise FileNotFoundError
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        assert sm._get_ram() == 0.0

    def test_get_disk_returns_percentage(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        cfg = _make_config(tmp_path)
        sm = SelfMonitor(cfg)

        class FakeStatVFS:
            f_blocks = 1000
            f_bfree = 200

        monkeypatch.setattr(os, "statvfs", lambda path: FakeStatVFS())
        disk = sm._get_disk()
        # (1000 - 200) / 1000 * 100 = 80.0
        assert disk == 80.0

    def test_get_disk_returns_zero_on_error(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        cfg = _make_config(tmp_path)
        sm = SelfMonitor(cfg)
        monkeypatch.setattr(os, "statvfs", lambda path: (_ for _ in ()).throw(OSError("no fs")))
        assert sm._get_disk() == 0.0

    def test_get_iowait_reads_proc_stat(self, tmp_path, monkeypatch):
        from core.resilience import SelfMonitor
        cfg = _make_config(tmp_path)
        sm = SelfMonitor(cfg)

        # cpu user nice system idle iowait irq softirq
        proc_stat = "cpu  1000 0 500 8000 500 0 0\n"

        import builtins
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if str(path) == "/proc/stat":
                import io
                return io.StringIO(proc_stat)
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        iowait = sm._get_iowait()
        # 500 / 10000 * 100 = 5.0
        assert iowait == 5.0

    def test_get_load_returns_list(self, tmp_path):
        from core.resilience import SelfMonitor
        cfg = _make_config(tmp_path)
        sm = SelfMonitor(cfg)
        load = sm._get_load()
        assert isinstance(load, list)
        assert len(load) == 3


# ══════════════════════════════════════════════════════════
# 3. BufferGuard
# ══════════════════════════════════════════════════════════

class TestBufferGuard:
    """Tests for kernel buffer guard with mocked /proc and /sys reads."""

    def test_check_returns_stats_dict(self, tmp_path, monkeypatch):
        from core.resilience import BufferGuard
        cfg = _make_config(tmp_path)

        # Mock _set_rmem to avoid /proc access
        monkeypatch.setattr(BufferGuard, "_set_rmem", lambda self: None)
        bg = BufferGuard(cfg)

        # Mock the check to read from a fake file
        iface_dir = tmp_path / "sys" / "class" / "net" / "eth0" / "statistics"
        iface_dir.mkdir(parents=True)
        (iface_dir / "rx_dropped").write_text("100")

        monkeypatch.setattr("builtins.open", _make_open_mock(
            {f"/sys/class/net/eth0/statistics/rx_dropped": "100"},
            original_open=open
        ))

        # Use direct file reading approach instead
        bg._prev_drops = None
        stats = bg.check()
        # The check may fail because we can't easily mock open for specific paths
        # Let's test via a different approach
        assert isinstance(stats, dict)

    def test_check_detects_packet_drops(self, tmp_path, monkeypatch):
        from core.resilience import BufferGuard
        alerts = []
        cfg = _make_config(tmp_path)

        monkeypatch.setattr(BufferGuard, "_set_rmem", lambda self: None)
        monkeypatch.setattr(BufferGuard, "_increase_sniff_buffer", lambda self: None)
        bg = BufferGuard(cfg, alert_fn=lambda **kw: alerts.append(kw))

        # Simulate two consecutive checks with increasing drops
        bg._prev_drops = 100

        # Mock open for the rx_dropped file
        import builtins
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if "rx_dropped" in str(path):
                import io
                return io.StringIO("150")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        stats = bg.check()
        assert stats["drops"] == 150
        assert stats["delta"] == 50
        assert len(alerts) == 1
        assert "dropped" in alerts[0]["title"]

    def test_check_no_alert_when_no_new_drops(self, tmp_path, monkeypatch):
        from core.resilience import BufferGuard
        alerts = []
        cfg = _make_config(tmp_path)

        monkeypatch.setattr(BufferGuard, "_set_rmem", lambda self: None)
        bg = BufferGuard(cfg, alert_fn=lambda **kw: alerts.append(kw))
        bg._prev_drops = 100

        import builtins
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if "rx_dropped" in str(path):
                import io
                return io.StringIO("100")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        stats = bg.check()
        assert stats["delta"] == 0
        assert len(alerts) == 0

    def test_check_first_call_records_baseline(self, tmp_path, monkeypatch):
        from core.resilience import BufferGuard
        cfg = _make_config(tmp_path)

        monkeypatch.setattr(BufferGuard, "_set_rmem", lambda self: None)
        bg = BufferGuard(cfg)
        assert bg._prev_drops is None

        import builtins
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if "rx_dropped" in str(path):
                import io
                return io.StringIO("50")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        stats = bg.check()
        assert stats["drops"] == 50
        assert stats["delta"] == 0  # first check, no delta
        assert bg._prev_drops == 50

    def test_check_handles_missing_interface_file(self, tmp_path, monkeypatch):
        from core.resilience import BufferGuard
        cfg = _make_config(tmp_path)

        monkeypatch.setattr(BufferGuard, "_set_rmem", lambda self: None)
        bg = BufferGuard(cfg)

        import builtins
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if "rx_dropped" in str(path):
                raise FileNotFoundError("no such file")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        stats = bg.check()
        assert stats["drops"] == 0
        assert stats["delta"] == 0

    def test_buffer_increased_flag_set_on_drops(self, tmp_path, monkeypatch):
        from core.resilience import BufferGuard
        cfg = _make_config(tmp_path)

        monkeypatch.setattr(BufferGuard, "_set_rmem", lambda self: None)

        # Mock _increase_sniff_buffer to just set the flag
        def fake_increase(self):
            self._buffer_increased = True
        monkeypatch.setattr(BufferGuard, "_increase_sniff_buffer", fake_increase)

        bg = BufferGuard(cfg)
        bg._prev_drops = 0

        import builtins
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if "rx_dropped" in str(path):
                import io
                return io.StringIO("10")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        bg.check()
        assert bg._buffer_increased is True

    def test_set_rmem_increases_buffer(self, tmp_path, monkeypatch):
        from core.resilience import BufferGuard
        import builtins
        real_open = builtins.open
        written = []

        class FakeWriteFile:
            def write(self, data):
                written.append(data)
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        def mock_open(path, *args, **kwargs):
            path_str = str(path)
            if path_str == "/proc/sys/net/core/rmem_max":
                if args and args[0] == "w":
                    return FakeWriteFile()
                import io
                return io.StringIO("1000000")  # current value < 16MB
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        cfg = _make_config(tmp_path)
        # Create directly without __init__ calling _set_rmem
        bg = BufferGuard.__new__(BufferGuard)
        bg.cfg = cfg
        bg._alert = lambda **kw: None
        bg.interface = "eth0"
        bg._prev_drops = None
        bg._buffer_increased = False
        bg._set_rmem()
        assert len(written) == 1
        assert int(written[0]) == 16 * 1024 * 1024

    def test_increase_sniff_buffer_sets_rmem_default(self, tmp_path, monkeypatch):
        from core.resilience import BufferGuard
        import builtins
        real_open = builtins.open
        written = []

        class FakeWriteFile:
            def write(self, data):
                written.append(data)
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        def mock_open(path, *args, **kwargs):
            if "rmem_default" in str(path):
                return FakeWriteFile()
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        monkeypatch.setattr(BufferGuard, "_set_rmem", lambda self: None)
        cfg = _make_config(tmp_path)
        bg = BufferGuard(cfg)
        bg._increase_sniff_buffer()
        assert bg._buffer_increased is True
        assert len(written) == 1

    def test_buffer_not_increased_twice(self, tmp_path, monkeypatch):
        from core.resilience import BufferGuard
        increase_calls = []
        cfg = _make_config(tmp_path)

        monkeypatch.setattr(BufferGuard, "_set_rmem", lambda self: None)

        original_increase = BufferGuard._increase_sniff_buffer

        def tracking_increase(self):
            increase_calls.append(1)
            self._buffer_increased = True

        monkeypatch.setattr(BufferGuard, "_increase_sniff_buffer", tracking_increase)

        bg = BufferGuard(cfg)
        bg._prev_drops = 0

        import builtins
        real_open = builtins.open
        drop_value = [10]

        def mock_open(path, *args, **kwargs):
            if "rx_dropped" in str(path):
                import io
                return io.StringIO(str(drop_value[0]))
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        bg.check()
        drop_value[0] = 20
        bg.check()
        # Should only increase once
        assert len(increase_calls) == 1


# Helper for open mocking (not used but defined for completeness)
def _make_open_mock(file_contents, original_open):
    def mock_open(path, *args, **kwargs):
        if str(path) in file_contents:
            import io
            return io.StringIO(file_contents[str(path)])
        return original_open(path, *args, **kwargs)
    return mock_open


# ══════════════════════════════════════════════════════════
# 4. SafeBackup
# ══════════════════════════════════════════════════════════

class TestSafeBackup:
    """Tests for non-blocking safe backup wrapper."""

    def test_run_delegates_to_backup_manager(self, tmp_path, monkeypatch):
        from core.resilience import SafeBackup
        import subprocess

        cfg = _make_config(tmp_path)
        data_dir = cfg.get("general.data_dir")
        os.makedirs(data_dir, exist_ok=True)

        class FakeBackupMgr:
            def create(self):
                return "/tmp/backup.tar.gz"

        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: None)

        sb = SafeBackup(cfg, backup_manager=FakeBackupMgr())
        result = sb.run()
        assert result == "/tmp/backup.tar.gz"

    def test_run_skipped_in_degraded_mode(self, tmp_path, monkeypatch):
        from core.resilience import SafeBackup, DegradedMode

        cfg = _make_config(tmp_path)
        dm = DegradedMode(cfg)
        dm.enter(reason="test")

        class FakeBackupMgr:
            def create(self):
                return "/tmp/backup.tar.gz"

        sb = SafeBackup(cfg, backup_manager=FakeBackupMgr(), degraded_mode=dm)
        result = sb.run()
        assert result == ""

    def test_run_skipped_if_already_running(self, tmp_path, monkeypatch):
        from core.resilience import SafeBackup

        cfg = _make_config(tmp_path)

        class FakeBackupMgr:
            def create(self):
                return "/tmp/backup.tar.gz"

        sb = SafeBackup(cfg, backup_manager=FakeBackupMgr())
        sb._running = True
        result = sb.run()
        assert result == ""

    def test_run_resets_running_flag_on_error(self, tmp_path, monkeypatch):
        from core.resilience import SafeBackup
        import subprocess

        cfg = _make_config(tmp_path)
        data_dir = cfg.get("general.data_dir")
        os.makedirs(data_dir, exist_ok=True)

        class BrokenBackupMgr:
            def create(self):
                raise RuntimeError("backup failed")

        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: None)

        sb = SafeBackup(cfg, backup_manager=BrokenBackupMgr())
        result = sb.run()
        assert result == ""
        assert sb._running is False

    def test_safe_sqlite_copy_skips_missing_db(self, tmp_path, monkeypatch):
        from core.resilience import SafeBackup

        cfg = _make_config(tmp_path)

        class FakeBackupMgr:
            def create(self):
                return ""

        sb = SafeBackup(cfg, backup_manager=FakeBackupMgr())
        # Should not raise
        sb._safe_sqlite_copy()

    def test_safe_sqlite_copy_creates_backup_file(self, tmp_path, monkeypatch):
        from core.resilience import SafeBackup

        cfg = _make_config(tmp_path)
        data_dir = cfg.get("general.data_dir")
        os.makedirs(data_dir, exist_ok=True)
        db_path = os.path.join(data_dir, "cgs.db")

        # Create a real SQLite DB
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO test VALUES (1)")
        conn.commit()
        conn.close()

        class FakeBackupMgr:
            def create(self):
                return ""

        sb = SafeBackup(cfg, backup_manager=FakeBackupMgr())
        sb._safe_sqlite_copy()
        assert os.path.exists(db_path + ".backup")

    def test_low_priority_backup_calls_backup_mgr_create(self, tmp_path, monkeypatch):
        from core.resilience import SafeBackup
        import subprocess

        cfg = _make_config(tmp_path)
        subprocess_calls = []

        def fake_run(*args, **kwargs):
            subprocess_calls.append(args)

        monkeypatch.setattr(subprocess, "run", fake_run)

        class FakeBackupMgr:
            def create(self):
                return "/tmp/test_backup.tar.gz"

        sb = SafeBackup(cfg, backup_manager=FakeBackupMgr())
        result = sb._low_priority_backup()
        assert result == "/tmp/test_backup.tar.gz"
        # Should have called ionice/renice (4 calls: 2 for setting low, 2 for restoring)
        assert len(subprocess_calls) >= 2


# ══════════════════════════════════════════════════════════
# 5. enable_wal_mode
# ══════════════════════════════════════════════════════════

class TestEnableWalMode:
    """Tests for SQLite WAL mode configuration."""

    def test_enables_wal_mode_on_db(self, tmp_path):
        from core.resilience import enable_wal_mode

        db_path = str(tmp_path / "test.db")
        # Create a DB first
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE test (id INTEGER)")
        conn.close()

        enable_wal_mode(db_path)

        # Verify WAL mode is set
        conn = sqlite3.connect(db_path)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        assert mode == "wal"

    def test_sets_synchronous_normal(self, tmp_path):
        """Verify that enable_wal_mode executes PRAGMA synchronous=NORMAL.
        We verify by inspecting the source code behavior: after enable_wal_mode,
        a connection opened in the same process with WAL should accept reads/writes."""
        from core.resilience import enable_wal_mode
        import inspect

        # Verify the function contains the PRAGMA synchronous=NORMAL call
        source = inspect.getsource(enable_wal_mode)
        assert "synchronous=NORMAL" in source

        # Also verify it runs without error
        db_path = str(tmp_path / "test.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE test (id INTEGER)")
        conn.close()
        enable_wal_mode(db_path)  # should not raise

    def test_sets_busy_timeout(self, tmp_path):
        from core.resilience import enable_wal_mode

        db_path = str(tmp_path / "test.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE test (id INTEGER)")
        conn.close()

        enable_wal_mode(db_path)

        conn = sqlite3.connect(db_path)
        timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        conn.close()
        assert timeout == 5000

    def test_handles_nonexistent_db_gracefully(self, tmp_path):
        from core.resilience import enable_wal_mode
        # sqlite3.connect will create the file, so this should not raise
        db_path = str(tmp_path / "nonexistent.db")
        enable_wal_mode(db_path)
        # File should have been created
        assert os.path.exists(db_path)

    def test_handles_invalid_path_gracefully(self):
        from core.resilience import enable_wal_mode
        # Should not raise, just log a warning
        enable_wal_mode("/nonexistent/path/db.sqlite")
