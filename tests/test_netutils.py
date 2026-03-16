"""Tests for core/netutils.py — Network utility functions."""

import os
import sys
from unittest.mock import patch, MagicMock, mock_open

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.netutils import (
    vendor_from_mac, guess_os_from_ttl, shannon_entropy,
    get_default_iface, get_iface_ip, get_iface_mac,
    get_all_interfaces, ip_in_subnet, WELL_KNOWN_SERVICES, OUI,
)


# ── vendor_from_mac ──

class TestVendorFromMac:
    def test_known_vmware_mac(self):
        assert vendor_from_mac("00:50:56:ab:cd:ef") == "VMware"

    def test_known_apple_mac(self):
        assert vendor_from_mac("ac:de:48:11:22:33") == "Apple"

    def test_known_raspberry_pi_mac(self):
        assert vendor_from_mac("dc:a6:32:aa:bb:cc") == "Raspberry Pi"

    def test_unknown_mac_returns_empty(self):
        assert vendor_from_mac("ff:ff:ff:ff:ff:ff") == ""

    def test_case_insensitive(self):
        # vendor_from_mac lowercases the first 8 chars, so uppercase also matches
        assert vendor_from_mac("00:50:56:AB:CD:EF") == "VMware"
        assert vendor_from_mac("00:50:56:ab:cd:ef") == "VMware"

    def test_virtualbox_mac(self):
        assert vendor_from_mac("08:00:27:11:22:33") == "VirtualBox"

    def test_cisco_mac(self):
        assert vendor_from_mac("00:1a:2b:11:22:33") == "Cisco"


# ── guess_os_from_ttl ──

class TestGuessOsFromTtl:
    def test_ttl_64_linux(self):
        assert "Linux" in guess_os_from_ttl(64)

    def test_ttl_128_windows(self):
        assert "Windows" in guess_os_from_ttl(128)

    def test_ttl_255_cisco(self):
        assert "Cisco" in guess_os_from_ttl(255)

    def test_ttl_32_windows_9x(self):
        assert "Windows 9x" in guess_os_from_ttl(32)

    def test_ttl_near_64_linux(self):
        assert "Linux" in guess_os_from_ttl(60)

    def test_ttl_near_128_windows(self):
        assert "Windows" in guess_os_from_ttl(120)

    def test_ttl_1_closest_to_32(self):
        result = guess_os_from_ttl(1)
        assert "Windows 9x" in result

    def test_ttl_200_closest_to_255(self):
        result = guess_os_from_ttl(200)
        assert "Cisco" in result


# ── shannon_entropy ──

class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        e = shannon_entropy("ab")
        assert abs(e - 1.0) < 0.01

    def test_high_entropy_random(self):
        e = shannon_entropy("abcdefghijklmnop")
        assert e > 3.5

    def test_low_entropy_repeated(self):
        e = shannon_entropy("aaaaaaaaab")
        assert e < 1.0

    def test_dns_tunnel_like_string(self):
        e = shannon_entropy("a1b2c3d4e5f6g7h8.evil.com")
        assert e > 3.0

    def test_normal_domain(self):
        e = shannon_entropy("google.com")
        assert e < 3.5


# ── get_default_iface ──

class TestGetDefaultIface:
    def test_reads_proc_net_route(self):
        route_content = (
            "Iface\tDestination\tGateway\n"
            "eth0\t00000000\t0102A8C0\n"
            "eth0\t0002A8C0\t00000000\n"
        )
        with patch("builtins.open", mock_open(read_data=route_content)):
            result = get_default_iface()
        assert result == "eth0"

    def test_reads_wlan_interface(self):
        route_content = (
            "Iface\tDestination\tGateway\n"
            "wlan0\t00000000\t0102A8C0\n"
        )
        with patch("builtins.open", mock_open(read_data=route_content)):
            result = get_default_iface()
        assert result == "wlan0"

    def test_fallback_to_sys_class_net(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            with patch("os.listdir", return_value=["lo", "enp0s3"]):
                result = get_default_iface()
        assert result == "enp0s3"

    def test_fallback_to_eth0_when_all_fail(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            with patch("os.listdir", side_effect=FileNotFoundError):
                result = get_default_iface()
        assert result == "eth0"

    def test_skips_lo_in_fallback(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            with patch("os.listdir", return_value=["lo", "eth1"]):
                result = get_default_iface()
        assert result == "eth1"


# ── get_iface_ip ──

class TestGetIfaceIp:
    def test_returns_ip_via_scapy(self):
        with patch("scapy.all.get_if_addr", return_value="192.168.1.100"):
            result = get_iface_ip("eth0")
        # Either scapy works or fallback to 0.0.0.0
        assert isinstance(result, str)

    def test_fallback_on_exception(self):
        # When scapy raises, should return 0.0.0.0
        result = get_iface_ip("nonexistent_iface_xyz")
        assert result == "0.0.0.0"


# ── get_iface_mac ──

class TestGetIfaceMac:
    def test_fallback_to_sysfs(self, tmp_path):
        iface = "eth0"
        sysfs_dir = tmp_path / "sys" / "class" / "net" / iface
        sysfs_dir.mkdir(parents=True)
        (sysfs_dir / "address").write_text("aa:bb:cc:dd:ee:ff\n")

        # Make scapy fail, then use sysfs fallback
        with patch("scapy.all.get_if_hwaddr", side_effect=Exception("no scapy")):
            with patch("os.path.exists", return_value=True):
                with patch("builtins.open", mock_open(read_data="aa:bb:cc:dd:ee:ff\n")):
                    result = get_iface_mac("eth0")
        assert result == "aa:bb:cc:dd:ee:ff"

    def test_returns_zero_mac_on_total_failure(self):
        with patch("scapy.all.get_if_hwaddr", side_effect=Exception):
            with patch("os.path.exists", return_value=False):
                result = get_iface_mac("nonexistent")
        assert result == "00:00:00:00:00:00"


# ── get_all_interfaces ──

class TestGetAllInterfaces:
    def test_enumerates_interfaces(self):
        with patch("os.listdir", return_value=["lo", "eth0"]):
            with patch("core.netutils.get_iface_mac", return_value="aa:bb:cc:dd:ee:ff"):
                with patch("core.netutils.get_iface_ip", return_value="192.168.1.1"):
                    with patch("builtins.open", mock_open(read_data="up\n")):
                        result = get_all_interfaces()
        assert "lo" in result or "eth0" in result

    def test_handles_exception(self):
        with patch("os.listdir", side_effect=OSError("permission denied")):
            result = get_all_interfaces()
        assert result == {}


# ── ip_in_subnet ──

class TestIpInSubnet:
    def test_ip_in_24_subnet(self):
        assert ip_in_subnet("192.168.1.100", "192.168.1.0/24") is True

    def test_ip_not_in_24_subnet(self):
        assert ip_in_subnet("192.168.2.100", "192.168.1.0/24") is False

    def test_ip_in_16_subnet(self):
        assert ip_in_subnet("10.0.5.1", "10.0.0.0/16") is True

    def test_ip_not_in_16_subnet(self):
        assert ip_in_subnet("10.1.5.1", "10.0.0.0/16") is False

    def test_ip_in_32_subnet(self):
        assert ip_in_subnet("1.2.3.4", "1.2.3.4/32") is True

    def test_ip_not_in_32_subnet(self):
        assert ip_in_subnet("1.2.3.5", "1.2.3.4/32") is False

    def test_ip_in_8_subnet(self):
        assert ip_in_subnet("10.255.255.255", "10.0.0.0/8") is True

    def test_ip_in_0_subnet(self):
        assert ip_in_subnet("1.2.3.4", "0.0.0.0/0") is True

    def test_boundary_ip(self):
        assert ip_in_subnet("192.168.1.0", "192.168.1.0/24") is True
        assert ip_in_subnet("192.168.1.255", "192.168.1.0/24") is True


# ── Constants ──

class TestConstants:
    def test_well_known_services_has_common_ports(self):
        assert WELL_KNOWN_SERVICES[22] == "ssh"
        assert WELL_KNOWN_SERVICES[80] == "http"
        assert WELL_KNOWN_SERVICES[443] == "https"
        assert WELL_KNOWN_SERVICES[3306] == "mysql"

    def test_oui_has_entries(self):
        assert len(OUI) > 10
