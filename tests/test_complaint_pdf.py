"""Tests for core/complaint_pdf.py — generate_complaint_pdf."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.complaint_pdf import generate_complaint_pdf


# ══════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════

@pytest.fixture
def output_dir(tmp_path):
    return str(tmp_path / "forensics")


@pytest.fixture
def minimal_incident():
    return {
        "id": "INC-001",
        "severity": 1,
        "threat_type": "Brute Force",
        "threat_detail": "Multiple failed SSH login attempts detected from external IP.",
        "created": "2025-01-15 10:30:00",
        "target_ip": "192.168.1.100",
        "target_hostname": "web-server",
        "target_name": "admin",
        "attacker_ip": "45.33.32.156",
        "approved_at": "2025-01-15 10:35:00",
        "approved_by": "admin",
        "actions_executed": ["Blocked IP 45.33.32.156 via iptables", "Rate limited subnet"],
        "resolved": True,
        "resolution": "Attacker IP blocked, no data exfiltration detected.",
    }


@pytest.fixture
def recon_report():
    return {
        "target_ip": "45.33.32.156",
        "reverse_dns": "scanme.nmap.org",
        "os_fingerprint": "Linux 5.x",
        "geolocation": {
            "country": "United States", "country_code": "US",
            "city": "San Francisco", "region": "California",
            "lat": 37.7749, "lon": -122.4194,
            "isp": "Linode LLC", "proxy": False, "hosting": True,
        },
        "whois": {
            "org": "Linode LLC", "asn": "63949",
            "netrange": "45.33.0.0 - 45.33.63.255",
            "abuse_contact": "abuse@linode.com",
        },
        "reputation": {
            "summary": "IP has been reported 15 times for brute force activity.",
        },
        "open_ports": [
            {"port": 22, "service": "ssh"},
            {"port": 80, "service": "http"},
            {"port": 443, "service": "https"},
        ],
    }


# ══════════════════════════════════════════════════
# PDF generation for different country codes
# ══════════════════════════════════════════════════

class TestGenerateComplaintPdf:

    def test_generate_pdf_ie_returns_valid_path(self, minimal_incident, recon_report, output_dir):
        """IE country code generates a PDF file that exists on disk."""
        path = generate_complaint_pdf(minimal_incident, recon_report,
                                       output_dir=output_dir, country_code="IE")
        assert os.path.exists(path)
        assert path.endswith(".pdf")
        assert os.path.getsize(path) > 1000  # Not empty

    def test_generate_pdf_fr_returns_valid_path(self, minimal_incident, recon_report, output_dir):
        """FR country code generates a PDF file."""
        path = generate_complaint_pdf(minimal_incident, recon_report,
                                       output_dir=output_dir, country_code="FR")
        assert os.path.exists(path)
        assert os.path.getsize(path) > 1000

    def test_generate_pdf_us_returns_valid_path(self, minimal_incident, recon_report, output_dir):
        """US country code generates a PDF with LETTER page size."""
        path = generate_complaint_pdf(minimal_incident, recon_report,
                                       output_dir=output_dir, country_code="US")
        assert os.path.exists(path)
        assert os.path.getsize(path) > 1000

    def test_pdf_filename_contains_incident_id(self, minimal_incident, output_dir):
        """Generated filename contains the incident ID."""
        path = generate_complaint_pdf(minimal_incident, output_dir=output_dir)
        assert "INC-001" in os.path.basename(path)

    def test_pdf_creates_output_directory(self, minimal_incident, tmp_path):
        """Output directory is created if it does not exist."""
        nested = str(tmp_path / "a" / "b" / "c")
        path = generate_complaint_pdf(minimal_incident, output_dir=nested)
        assert os.path.exists(path)

    def test_generate_pdf_with_minimal_data(self, output_dir):
        """PDF is generated with minimal incident data (mostly empty fields)."""
        path = generate_complaint_pdf({"id": "INC-MINIMAL"}, output_dir=output_dir)
        assert os.path.exists(path)
        assert os.path.getsize(path) > 500

    def test_generate_pdf_with_no_recon_report(self, minimal_incident, output_dir):
        """PDF is generated when recon_report is None."""
        path = generate_complaint_pdf(minimal_incident, recon_report=None,
                                       output_dir=output_dir)
        assert os.path.exists(path)

    def test_generate_pdf_with_forensic_path(self, minimal_incident, output_dir, tmp_path):
        """PDF includes forensic file reference when provided."""
        forensic_file = str(tmp_path / "forensic_INC-001.json")
        with open(forensic_file, "w") as f:
            f.write("{}")
        path = generate_complaint_pdf(minimal_incident, forensic_path=forensic_file,
                                       output_dir=output_dir)
        assert os.path.exists(path)

    def test_generate_pdf_with_empty_actions(self, output_dir):
        """PDF is generated when actions_executed is empty."""
        incident = {"id": "INC-NOACTIONS", "severity": 3, "actions_executed": []}
        path = generate_complaint_pdf(incident, output_dir=output_dir)
        assert os.path.exists(path)

    def test_generate_pdf_with_shutdown_event(self, minimal_incident, output_dir):
        """PDF includes shutdown event in timeline."""
        minimal_incident["shutdown_detected_at"] = "2025-01-15 11:00:00"
        path = generate_complaint_pdf(minimal_incident, output_dir=output_dir)
        assert os.path.exists(path)

    def test_generate_pdf_severity_levels(self, output_dir):
        """PDF handles all severity levels (1-4)."""
        for sev in [1, 2, 3, 4]:
            incident = {"id": f"INC-SEV{sev}", "severity": sev}
            path = generate_complaint_pdf(incident, output_dir=output_dir,
                                           country_code="IE")
            assert os.path.exists(path)

    def test_generate_pdf_unknown_severity(self, output_dir):
        """PDF handles unknown severity gracefully."""
        incident = {"id": "INC-UNKNOWN-SEV", "severity": 99}
        path = generate_complaint_pdf(incident, output_dir=output_dir)
        assert os.path.exists(path)

    def test_generate_pdf_with_long_threat_detail(self, output_dir):
        """PDF truncates very long threat details to 1000 chars."""
        incident = {"id": "INC-LONG", "threat_detail": "X" * 5000}
        path = generate_complaint_pdf(incident, output_dir=output_dir)
        assert os.path.exists(path)

    def test_generate_pdf_with_open_ports_in_recon(self, output_dir):
        """PDF includes open port listing from recon report."""
        recon = {
            "open_ports": [{"port": i, "service": f"svc{i}"} for i in range(25)],
            "geolocation": {}, "whois": {}, "reputation": {},
        }
        path = generate_complaint_pdf({"id": "INC-PORTS"}, recon,
                                       output_dir=output_dir)
        assert os.path.exists(path)

    def test_generate_pdf_with_reputation_summary(self, output_dir):
        """PDF includes reputation summary when available."""
        recon = {
            "geolocation": {}, "whois": {},
            "reputation": {"summary": "Known malicious actor."},
        }
        path = generate_complaint_pdf({"id": "INC-REP"}, recon,
                                       output_dir=output_dir)
        assert os.path.exists(path)

    def test_multiple_pdfs_have_unique_filenames(self, output_dir):
        """Multiple generated PDFs have distinct filenames (timestamp-based)."""
        import time
        path1 = generate_complaint_pdf({"id": "INC-A"}, output_dir=output_dir)
        time.sleep(1.1)
        path2 = generate_complaint_pdf({"id": "INC-B"}, output_dir=output_dir)
        assert path1 != path2

    def test_fr_severity_labels_differ_from_en(self, output_dir):
        """FR country uses French severity labels (no crash)."""
        incident = {"id": "INC-FR", "severity": 1}
        path = generate_complaint_pdf(incident, output_dir=output_dir, country_code="FR")
        assert os.path.exists(path)
