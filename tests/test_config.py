"""Tests for core/config.py — YAML configuration with defaults."""
import os
import sys

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import Config, DEFAULTS


def _make_base_yaml(tmp_path):
    """Helper: write a minimal config YAML that points data/log dirs to tmp_path."""
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.dump({
        "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs")},
    }))
    return str(cfg_path)


def _make_config(tmp_path, extra=None):
    """Helper: create a Config with safe temp dirs and optional extra overrides."""
    base = {"general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs")}}
    if extra:
        base.update(extra)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.dump(base))
    return Config(str(cfg_path))


# ══════════════════════════════════════════════════
# DEFAULTS structure
# ══════════════════════════════════════════════════

class TestDefaults:

    def test_defaults_contains_all_top_level_sections(self):
        """DEFAULTS dict contains all expected configuration sections."""
        expected = [
            "general", "network", "discovery", "sniffer", "suricata",
            "defense", "email", "recon", "netgate", "analysis",
            "identity", "client_agent", "notifications", "alerts",
            "web", "retention",
        ]
        for section in expected:
            assert section in DEFAULTS, f"Missing section: {section}"

    def test_default_web_host_is_localhost(self):
        """Default web host is 127.0.0.1 (not 0.0.0.0) for security."""
        assert DEFAULTS["web"]["host"] == "127.0.0.1"

    def test_default_web_secret_is_empty(self):
        """Default web secret is empty (triggers auto-generation)."""
        assert DEFAULTS["web"]["secret"] == ""

    def test_default_defense_mode_is_confirmation(self):
        """Default defense mode requires admin confirmation."""
        assert DEFAULTS["defense"]["mode"] == "confirmation"

    def test_default_email_is_disabled(self):
        """Email notifications are disabled by default."""
        assert DEFAULTS["email"]["enabled"] is False

    def test_default_log_level_is_info(self):
        """Default log level is INFO."""
        assert DEFAULTS["general"]["log_level"] == "INFO"


# ══════════════════════════════════════════════════
# Config loading
# ══════════════════════════════════════════════════

class TestConfigLoading:

    def test_load_from_nonexistent_file_uses_defaults(self, tmp_path):
        """Loading a non-existent config file uses defaults (with safe dirs)."""
        cfg = _make_config(tmp_path)
        assert cfg.get("general.log_level") == "INFO"
        assert cfg.get("web.port") == 8443

    def test_load_from_existing_file_merges_with_defaults(self, tmp_path):
        """Loading an existing config file merges user values with defaults."""
        cfg = _make_config(tmp_path, {"web": {"port": 9999}, "general": {
            "data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs"),
            "log_level": "DEBUG",
        }})
        assert cfg.get("general.log_level") == "DEBUG"
        assert cfg.get("web.port") == 9999
        # Defaults still present for unspecified values
        assert cfg.get("web.host") == "127.0.0.1"
        assert cfg.get("defense.enabled") is True

    def test_load_empty_file_uses_defaults(self, tmp_path):
        """Loading an empty YAML file with safe dirs uses defaults."""
        cfg = _make_config(tmp_path)
        assert cfg.get("web.port") == 8443

    def test_load_creates_data_and_log_dirs(self, tmp_path):
        """Loading config creates data_dir and log_dir if they don't exist."""
        data_dir = str(tmp_path / "data")
        log_dir = str(tmp_path / "logs")
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(yaml.dump({
            "general": {"data_dir": data_dir, "log_dir": log_dir},
        }))
        Config(str(cfg_path))
        assert os.path.isdir(data_dir)
        assert os.path.isdir(log_dir)

    def test_uses_safe_load(self, tmp_path):
        """Config uses yaml.safe_load to prevent arbitrary code execution."""
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(yaml.dump({
            "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs"),
                         "log_level": "WARNING"},
        }))
        cfg = Config(str(cfg_path))
        assert cfg.get("general.log_level") == "WARNING"


# ══════════════════════════════════════════════════
# Config.get()
# ══════════════════════════════════════════════════

class TestConfigGet:

    def test_get_simple_key(self, tmp_path):
        """Get a simple dotted key."""
        cfg = _make_config(tmp_path)
        assert cfg.get("web.enabled") is True

    def test_get_nested_key(self, tmp_path):
        """Get a deeply nested dotted key."""
        cfg = _make_config(tmp_path)
        assert cfg.get("notifications.slack.enabled") is False

    def test_get_missing_key_returns_default(self, tmp_path):
        """Get a missing key returns the provided default."""
        cfg = _make_config(tmp_path)
        assert cfg.get("nonexistent.key", "fallback") == "fallback"

    def test_get_missing_key_returns_none_by_default(self, tmp_path):
        """Get a missing key returns None when no default is provided."""
        cfg = _make_config(tmp_path)
        assert cfg.get("nonexistent.key") is None

    def test_get_partial_path_returns_dict(self, tmp_path):
        """Get a partial path returns the sub-dictionary."""
        cfg = _make_config(tmp_path)
        result = cfg.get("defense")
        assert isinstance(result, dict)
        assert "enabled" in result

    def test_get_list_value(self, tmp_path):
        """Get returns list values correctly."""
        cfg = _make_config(tmp_path)
        subnets = cfg.get("network.subnets")
        assert isinstance(subnets, list)
        assert "192.168.1.0/24" in subnets

    def test_get_top_ports_returns_correct_list(self, tmp_path):
        """Get returns the full top_ports list."""
        cfg = _make_config(tmp_path)
        ports = cfg.get("discovery.top_ports")
        assert isinstance(ports, list)
        assert 22 in ports
        assert 443 in ports

    def test_get_with_non_dict_intermediate_returns_default(self, tmp_path):
        """Get returns default when intermediate key is not a dict."""
        cfg = _make_config(tmp_path)
        assert cfg.get("web.port.subkey", "nope") == "nope"


# ══════════════════════════════════════════════════
# Config.set()
# ══════════════════════════════════════════════════

class TestConfigSet:

    def test_set_existing_key(self, tmp_path):
        """Set overwrites an existing key."""
        cfg = _make_config(tmp_path)
        cfg.set("web.port", 9999)
        assert cfg.get("web.port") == 9999

    def test_set_new_key_in_existing_section(self, tmp_path):
        """Set creates a new key in an existing section."""
        cfg = _make_config(tmp_path)
        cfg.set("web.new_setting", "hello")
        assert cfg.get("web.new_setting") == "hello"

    def test_set_creates_intermediate_dicts(self, tmp_path):
        """Set creates intermediate dictionaries if needed."""
        cfg = _make_config(tmp_path)
        cfg.set("custom.nested.deep.key", 42)
        assert cfg.get("custom.nested.deep.key") == 42

    def test_set_does_not_affect_other_keys(self, tmp_path):
        """Set only changes the target key, not sibling keys."""
        cfg = _make_config(tmp_path)
        original_host = cfg.get("web.host")
        cfg.set("web.port", 1234)
        assert cfg.get("web.host") == original_host


# ══════════════════════════════════════════════════
# Config.save()
# ══════════════════════════════════════════════════

class TestConfigSave:

    def test_save_writes_yaml_file(self, tmp_path):
        """Save writes a valid YAML file."""
        cfg = _make_config(tmp_path)
        cfg.set("web.port", 7777)
        cfg.save()
        with open(cfg._path) as f:
            data = yaml.safe_load(f)
        assert data["web"]["port"] == 7777

    def test_save_preserves_all_sections(self, tmp_path):
        """Save preserves all configuration sections."""
        cfg = _make_config(tmp_path)
        cfg.save()
        with open(cfg._path) as f:
            data = yaml.safe_load(f)
        for section in ["general", "network", "web", "defense"]:
            assert section in data

    def test_save_and_reload_round_trip(self, tmp_path):
        """Config can be saved and reloaded with the same values."""
        cfg1 = _make_config(tmp_path)
        cfg1.set("web.port", 5555)
        cfg1.set("general.log_level", "DEBUG")
        cfg1.save()
        cfg2 = Config(cfg1._path)
        assert cfg2.get("web.port") == 5555
        assert cfg2.get("general.log_level") == "DEBUG"

    def test_save_creates_parent_directories(self, tmp_path):
        """Save creates parent directories if they don't exist."""
        cfg = _make_config(tmp_path)
        new_path = tmp_path / "subdir" / "deep" / "config.yaml"
        cfg.path = new_path
        cfg._path = str(new_path)
        cfg.save()
        assert new_path.exists()


# ══════════════════════════════════════════════════
# Config._merge()
# ══════════════════════════════════════════════════

class TestConfigMerge:

    def test_merge_user_values_override_defaults(self):
        """User values override defaults."""
        result = Config._merge({"a": 1, "b": 2}, {"b": 99})
        assert result == {"a": 1, "b": 99}

    def test_merge_nested_dicts_are_deep_merged(self):
        """Nested dicts are merged recursively, not replaced."""
        base = {"section": {"key1": "v1", "key2": "v2"}}
        override = {"section": {"key2": "override"}}
        result = Config._merge(base, override)
        assert result["section"]["key1"] == "v1"
        assert result["section"]["key2"] == "override"

    def test_merge_new_keys_are_added(self):
        """New keys from override are added."""
        result = Config._merge({"a": 1}, {"b": 2})
        assert result == {"a": 1, "b": 2}

    def test_merge_non_dict_replaces_dict(self):
        """A non-dict override replaces a dict default."""
        result = Config._merge({"a": {"nested": True}}, {"a": "replaced"})
        assert result["a"] == "replaced"

    def test_merge_empty_override_keeps_defaults(self):
        """An empty override keeps all defaults."""
        base = {"a": 1, "b": {"c": 3}}
        result = Config._merge(base, {})
        assert result == base


# ══════════════════════════════════════════════════
# Integration tests
# ══════════════════════════════════════════════════

class TestConfigIntegration:

    def test_full_config_lifecycle(self, tmp_path):
        """Create, modify, save, reload, verify full lifecycle."""
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(yaml.dump({
            "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs")},
            "web": {"port": 8080},
            "defense": {"enabled": False},
        }))
        cfg = Config(str(cfg_path))

        # Verify merge with defaults
        assert cfg.get("web.port") == 8080
        assert cfg.get("web.host") == "127.0.0.1"
        assert cfg.get("defense.enabled") is False

        # Modify
        cfg.set("web.port", 9090)
        cfg.set("email.enabled", True)
        cfg.save()

        # Reload and verify
        cfg2 = Config(str(cfg_path))
        assert cfg2.get("web.port") == 9090
        assert cfg2.get("email.enabled") is True
        assert cfg2.get("defense.enabled") is False

    def test_config_with_all_default_sections_accessible(self, tmp_path):
        """All default configuration sections are accessible via dotted keys."""
        cfg = _make_config(tmp_path)
        assert cfg.get("discovery.arp_interval") == 300
        assert cfg.get("sniffer.enabled") is True
        assert cfg.get("analysis.portscan_threshold") == 15
        assert cfg.get("identity.spoof_threshold") == 50
        assert cfg.get("client_agent.enabled") is True
        assert cfg.get("retention.alerts_days") == 90
        assert cfg.get("alerts.cooldown_seconds") == 300
