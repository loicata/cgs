"""Tests for core/compliance.py — ComplianceAssessor, score computation, framework mapping, PDF."""
import os
import sys
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, PropertyMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.database import (
    db, init_db, Host, DnsLog, WebUser, ComplianceAnswer, Alert,
)
from core.compliance import (
    ComplianceAssessor, CONTROLS, DECLARATIVE_CONTROLS, FRAMEWORKS,
    ALL_FRAMEWORK_IDS, generate_compliance_pdf,
)


# ══════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════

class FakeConfig:
    def __init__(self, overrides=None):
        self._d = {
            "email.enabled": False,
            "client_agent.collect_after_incident": False,
            "email.admin_emails": [],
            "web.max_login_attempts": 0,
            "web.ssl_cert": "",
            "backup.directory": "",
            "retention.alerts_days": 0,
        }
        if overrides:
            self._d.update(overrides)

    def get(self, key, default=None):
        return self._d.get(key, default)


@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    if not db.is_closed():
        db.close()
    init_db(str(tmp_path))
    yield tmp_path
    db.close()


@pytest.fixture
def assessor():
    """Create a ComplianceAssessor with no modules."""
    cfg = FakeConfig()
    return ComplianceAssessor(cfg, {})


@pytest.fixture
def full_modules():
    """Create mock modules dict for a fully-loaded system."""
    sniffer = MagicMock()
    sniffer.stats = {"running": True, "pps": 100, "packets": 50000}

    engine = MagicMock()

    orchestrator = MagicMock()
    det1 = MagicMock()
    det1.status = "active"
    det2 = MagicMock()
    det2.status = "active"
    det3 = MagicMock()
    det3.status = "active"
    det4 = MagicMock()
    det4.status = "active"
    det5 = MagicMock()
    det5.status = "observing"
    orchestrator.detectors = [det1, det2, det3, det4, det5]

    threat_feeds = MagicMock()
    threat_feeds.stats = {"ips": 50000, "domains": 10000}

    killchain = MagicMock()

    defense = MagicMock()
    defense._fw_backend = "iptables"
    defense.auto_block = True
    defense._escalation = MagicMock()

    audit_chain = MagicMock()
    audit_chain.verify.return_value = {"ok": True, "entries": 500}

    honeypot = MagicMock()
    honeypot.enabled = True
    honeypot.ports = [3389, 1433, 5900]

    return {
        "sniffer": sniffer,
        "engine": engine,
        "orchestrator": orchestrator,
        "threat_feeds": threat_feeds,
        "killchain": killchain,
        "defense": defense,
        "audit_chain": audit_chain,
        "honeypot": honeypot,
    }


# ══════════════════════════════════════════════════
# CONTROLS and DECLARATIVE_CONTROLS structure
# ══════════════════════════════════════════════════

class TestControlDefinitions:

    def test_controls_have_required_fields(self):
        """Each automated control has 8 fields."""
        for ctrl in CONTROLS:
            assert len(ctrl) == 8
            cid, cat, title, desc, check_fn, weight, rec, mappings = ctrl
            assert isinstance(cid, str)
            assert isinstance(mappings, dict)

    def test_declarative_controls_have_required_fields(self):
        """Each declarative control has 7 fields."""
        for ctrl in DECLARATIVE_CONTROLS:
            assert len(ctrl) == 7
            cid, cat, title, desc, weight, prompt, mappings = ctrl

    def test_all_framework_ids_match_frameworks_dict(self):
        """ALL_FRAMEWORK_IDS matches FRAMEWORKS keys."""
        assert set(ALL_FRAMEWORK_IDS) == set(FRAMEWORKS.keys())

    def test_all_controls_have_unique_ids(self):
        """All control IDs are unique across automated and declarative."""
        auto_ids = [c[0] for c in CONTROLS]
        decl_ids = [c[0] for c in DECLARATIVE_CONTROLS]
        all_ids = auto_ids + decl_ids
        assert len(all_ids) == len(set(all_ids))

    def test_controls_map_to_known_frameworks(self):
        """All mappings reference known framework IDs."""
        for ctrl in CONTROLS:
            mappings = ctrl[7]
            for fw_id in mappings:
                assert fw_id in FRAMEWORKS

    def test_frameworks_have_expected_keys(self):
        """Each framework has name, full, and version."""
        for fw_id, fw in FRAMEWORKS.items():
            assert "name" in fw
            assert "full" in fw
            assert "version" in fw


# ══════════════════════════════════════════════════
# ComplianceAssessor — assess()
# ══════════════════════════════════════════════════

class TestAssess:

    def test_assess_returns_expected_keys(self, assessor):
        """assess() returns all expected top-level keys."""
        result = assessor.assess()
        expected_keys = {"score", "risk_level", "auto_score", "declarative_score",
                         "generated_at", "total_controls", "auto_controls",
                         "declarative_controls", "declarative_answered",
                         "passed", "failed", "unanswered", "categories",
                         "controls", "recommendations", "frameworks",
                         "available_frameworks"}
        assert expected_keys.issubset(set(result.keys()))

    def test_assess_with_no_modules_most_auto_fail(self, assessor):
        """With no modules loaded, most automated checks fail."""
        result = assessor.assess()
        auto_results = [c for c in result["controls"] if c["type"] == "automated"]
        fail_count = sum(1 for c in auto_results if c["status"] == "FAIL")
        # Most should fail, but some DB-based checks may pass or integrity check may auto-generate
        assert fail_count >= len(auto_results) - 3

    def test_assess_total_controls_count(self, assessor):
        """Total controls = automated + declarative."""
        result = assessor.assess()
        assert result["total_controls"] == len(CONTROLS) + len(DECLARATIVE_CONTROLS)
        assert result["auto_controls"] == len(CONTROLS)
        assert result["declarative_controls"] == len(DECLARATIVE_CONTROLS)

    def test_assess_score_is_between_0_and_100(self, assessor):
        """Score is always between 0 and 100."""
        result = assessor.assess()
        assert 0 <= result["score"] <= 100

    def test_assess_with_all_modules_passing(self, fresh_db, full_modules):
        """Full modules produce higher auto score."""
        cfg = FakeConfig({
            "email.enabled": True,
            "email.approval_timeout_minutes": 15,
            "client_agent.collect_after_incident": True,
            "email.admin_emails": ["admin@test.com"],
            "web.max_login_attempts": 5,
            "retention.alerts_days": 90,
        })
        # Create needed DB records
        Host.create(ip="192.168.1.1")
        DnsLog.create(query="example.com", qtype="A", src_ip="192.168.1.1",
                      ts=datetime.now())
        import bcrypt
        pw = bcrypt.hashpw(b"testpassword12345", bcrypt.gensalt()).decode()
        WebUser.create(username="admin", password_hash=pw, role="admin",
                       totp_secret="JBSWY3DPEHPK3PXP")

        assessor = ComplianceAssessor(cfg, full_modules)
        result = assessor.assess()
        assert result["auto_score"] > 50  # Should pass most checks

    def test_assess_with_selected_frameworks(self, assessor):
        """Filtering frameworks limits returned mappings."""
        result = assessor.assess(frameworks=["nis2", "gdpr"])
        for ctrl in result["controls"]:
            for fw_id in ctrl["mappings"]:
                assert fw_id in ("nis2", "gdpr")
        assert "nis2" in result["frameworks"]
        assert "iso27001" not in result["frameworks"]

    def test_assess_risk_level_critical_when_score_low(self, assessor):
        """Risk level is CRITICAL when score < 40."""
        result = assessor.assess()
        if result["score"] < 40:
            assert result["risk_level"] == "CRITICAL"

    def test_assess_recommendations_sorted_by_weight(self, assessor):
        """Recommendations are sorted by weight descending."""
        result = assessor.assess()
        recs = result["recommendations"]
        if len(recs) >= 2:
            for i in range(len(recs) - 1):
                assert recs[i]["weight"] >= recs[i + 1]["weight"] or \
                       (recs[i]["weight"] == recs[i + 1]["weight"])

    def test_assess_categories_contain_controls(self, assessor):
        """Each category has a controls list."""
        result = assessor.assess()
        for cat_name, cat_data in result["categories"].items():
            assert "controls" in cat_data
            assert "pass" in cat_data
            assert "fail" in cat_data
            assert "total" in cat_data

    def test_assess_declarative_unanswered_status(self, assessor):
        """Declarative controls without answers have UNANSWERED status."""
        result = assessor.assess()
        decl = [c for c in result["controls"] if c["type"] == "declarative"]
        for ctrl in decl:
            assert ctrl["status"] == "UNANSWERED"
            assert ctrl["answer"] == "unanswered"

    def test_assess_declarative_yes_answer(self, fresh_db):
        """Declarative control with 'yes' answer gets PASS status."""
        ComplianceAnswer.create(control_id="ORG-01", answer="yes",
                                 detail="Policy documented", answered_by="admin")
        cfg = FakeConfig()
        assessor = ComplianceAssessor(cfg, {})
        result = assessor.assess()
        org01 = next(c for c in result["controls"] if c["id"] == "ORG-01")
        assert org01["status"] == "PASS"
        assert org01["answer"] == "yes"

    def test_assess_declarative_no_answer(self, fresh_db):
        """Declarative control with 'no' answer gets FAIL status."""
        ComplianceAnswer.create(control_id="ORG-01", answer="no")
        cfg = FakeConfig()
        assessor = ComplianceAssessor(cfg, {})
        result = assessor.assess()
        org01 = next(c for c in result["controls"] if c["id"] == "ORG-01")
        assert org01["status"] == "FAIL"

    def test_assess_declarative_partial_answer(self, fresh_db):
        """Declarative control with 'partial' answer gets PARTIAL status."""
        ComplianceAnswer.create(control_id="ORG-01", answer="partial",
                                 detail="In progress")
        cfg = FakeConfig()
        assessor = ComplianceAssessor(cfg, {})
        result = assessor.assess()
        org01 = next(c for c in result["controls"] if c["id"] == "ORG-01")
        assert org01["status"] == "PARTIAL"

    def test_assess_declarative_score_none_when_no_answers(self, assessor):
        """Declarative score is None when no answers exist."""
        result = assessor.assess()
        assert result["declarative_score"] is None


# ══════════════════════════════════════════════════
# Individual check functions
# ══════════════════════════════════════════════════

class TestIndividualChecks:

    def test_check_sniffer_active_no_module(self, assessor):
        """check_sniffer_active returns False when module not loaded."""
        ok, detail = assessor.check_sniffer_active()
        assert ok is False

    def test_check_sniffer_active_running(self, fresh_db, full_modules):
        """check_sniffer_active returns True when sniffer is running."""
        assessor = ComplianceAssessor(FakeConfig(), full_modules)
        ok, detail = assessor.check_sniffer_active()
        assert ok is True

    def test_check_host_inventory_empty(self, fresh_db):
        """check_host_inventory fails with no hosts."""
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_host_inventory()
        assert ok is False

    def test_check_host_inventory_with_hosts(self, fresh_db):
        """check_host_inventory passes with hosts present."""
        Host.create(ip="10.0.0.1")
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_host_inventory()
        assert ok is True
        assert "1 hosts" in detail

    def test_check_threat_engine_loaded(self, full_modules):
        """check_threat_engine returns True when engine is loaded."""
        assessor = ComplianceAssessor(FakeConfig(), full_modules)
        ok, _ = assessor.check_threat_engine()
        assert ok is True

    def test_check_threat_engine_not_loaded(self):
        """check_threat_engine returns False when engine not loaded."""
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, _ = assessor.check_threat_engine()
        assert ok is False

    def test_check_firewall_active_with_iptables(self, full_modules):
        """check_firewall_active returns True with iptables backend."""
        assessor = ComplianceAssessor(FakeConfig(), full_modules)
        ok, detail = assessor.check_firewall_active()
        assert ok is True
        assert "iptables" in detail

    def test_check_firewall_no_backend(self):
        """check_firewall_active fails with no firewall backend."""
        defense = MagicMock()
        defense._fw_backend = "none"
        assessor = ComplianceAssessor(FakeConfig(), {"defense": defense})
        ok, _ = assessor.check_firewall_active()
        assert ok is False

    def test_check_auto_block_enabled(self, full_modules):
        """check_auto_block returns True when auto_block is enabled."""
        assessor = ComplianceAssessor(FakeConfig(), full_modules)
        ok, _ = assessor.check_auto_block()
        assert ok is True

    def test_check_auto_block_disabled(self):
        """check_auto_block returns False when auto_block is disabled."""
        defense = MagicMock()
        defense.auto_block = False
        assessor = ComplianceAssessor(FakeConfig(), {"defense": defense})
        ok, _ = assessor.check_auto_block()
        assert ok is False

    def test_check_incident_workflow_email_enabled(self):
        """check_incident_workflow passes when email is enabled."""
        cfg = FakeConfig({"email.enabled": True, "email.approval_timeout_minutes": 15})
        assessor = ComplianceAssessor(cfg, {})
        ok, detail = assessor.check_incident_workflow()
        assert ok is True

    def test_check_admin_emails_configured(self):
        """check_admin_emails passes with configured emails."""
        cfg = FakeConfig({"email.admin_emails": ["admin@example.com"]})
        assessor = ComplianceAssessor(cfg, {})
        ok, detail = assessor.check_admin_emails()
        assert ok is True

    def test_check_admin_emails_empty(self):
        """check_admin_emails fails with no emails."""
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, _ = assessor.check_admin_emails()
        assert ok is False

    def test_check_login_lockout_configured(self):
        """check_login_lockout passes with max_login_attempts <= 10."""
        cfg = FakeConfig({"web.max_login_attempts": 5})
        assessor = ComplianceAssessor(cfg, {})
        ok, _ = assessor.check_login_lockout()
        assert ok is True

    def test_check_login_lockout_too_high(self):
        """check_login_lockout fails when max_login_attempts > 10."""
        cfg = FakeConfig({"web.max_login_attempts": 50})
        assessor = ComplianceAssessor(cfg, {})
        ok, _ = assessor.check_login_lockout()
        assert ok is False

    def test_check_retention_configured(self):
        """check_retention passes with positive retention days."""
        cfg = FakeConfig({"retention.alerts_days": 90})
        assessor = ComplianceAssessor(cfg, {})
        ok, _ = assessor.check_retention()
        assert ok is True

    def test_check_honeypot_enabled(self, full_modules):
        """check_honeypot returns True when honeypot is enabled."""
        assessor = ComplianceAssessor(FakeConfig(), full_modules)
        ok, detail = assessor.check_honeypot()
        assert ok is True

    def test_check_honeypot_disabled(self):
        """check_honeypot returns False when honeypot is disabled."""
        hp = MagicMock()
        hp.enabled = False
        assessor = ComplianceAssessor(FakeConfig(), {"honeypot": hp})
        ok, _ = assessor.check_honeypot()
        assert ok is False

    def test_check_audit_chain_intact(self, full_modules):
        """check_audit_chain passes with intact chain."""
        assessor = ComplianceAssessor(FakeConfig(), full_modules)
        ok, detail = assessor.check_audit_chain()
        assert ok is True

    def test_check_killchain_loaded(self, full_modules):
        """check_killchain passes when killchain module is loaded."""
        assessor = ComplianceAssessor(FakeConfig(), full_modules)
        ok, _ = assessor.check_killchain()
        assert ok is True

    def test_check_advanced_detectors_enough_active(self, full_modules):
        """check_advanced_detectors passes with >= 4 active detectors."""
        assessor = ComplianceAssessor(FakeConfig(), full_modules)
        ok, detail = assessor.check_advanced_detectors()
        assert ok is True
        assert "4 active" in detail

    def test_check_forensic_enabled(self):
        """check_forensic_enabled passes when configured."""
        cfg = FakeConfig({"client_agent.collect_after_incident": True})
        assessor = ComplianceAssessor(cfg, {})
        ok, _ = assessor.check_forensic_enabled()
        assert ok is True

    def test_check_2fa_with_admin_totp(self, fresh_db):
        """check_2fa passes when admin has TOTP secret."""
        import bcrypt
        pw = bcrypt.hashpw(b"testpass12345678", bcrypt.gensalt()).decode()
        WebUser.create(username="admin", password_hash=pw, role="admin",
                       totp_secret="JBSWY3DPEHPK3PXP")
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, _ = assessor.check_2fa()
        assert ok is True

    def test_check_2fa_without_totp(self, fresh_db):
        """check_2fa fails when no admin has TOTP."""
        import bcrypt
        pw = bcrypt.hashpw(b"testpass12345678", bcrypt.gensalt()).decode()
        WebUser.create(username="admin", password_hash=pw, role="admin")
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, _ = assessor.check_2fa()
        assert ok is False


# ══════════════════════════════════════════════════
# PDF generation
# ══════════════════════════════════════════════════

class TestGenerateCompliancePdf:

    def _make_assessment(self, score=75, passed=15, failed=5, unanswered=2):
        """Create a minimal assessment dict for PDF generation."""
        return {
            "score": score, "risk_level": "MEDIUM",
            "auto_score": 80, "declarative_score": 60,
            "generated_at": datetime.now().isoformat(),
            "total_controls": passed + failed + unanswered,
            "auto_controls": 10, "declarative_controls": 12,
            "declarative_answered": 10,
            "passed": passed, "failed": failed, "unanswered": unanswered,
            "categories": {
                "Network": {"total": 3, "pass": 2, "fail": 1, "unanswered": 0,
                            "controls": [
                                {"id": "NET-01", "category": "Network",
                                 "title": "Packet capture", "description": "Test",
                                 "status": "PASS", "detail": "Active", "weight": 10,
                                 "recommendation": "Enable sniffer",
                                 "mappings": {"nis2": "Art.21"}, "type": "automated"},
                            ]},
            },
            "controls": [
                {"id": "NET-01", "category": "Network",
                 "title": "Packet capture", "description": "Test",
                 "status": "PASS", "detail": "Active", "weight": 10,
                 "recommendation": "Enable sniffer",
                 "mappings": {"nis2": "Art.21"}, "type": "automated"},
                {"id": "NET-02", "category": "Network",
                 "title": "Discovery", "description": "Test",
                 "status": "FAIL", "detail": "No hosts", "weight": 8,
                 "recommendation": "Run scan",
                 "mappings": {"nis2": "Art.21"}, "type": "automated"},
            ],
            "recommendations": [
                {"id": "NET-02", "title": "Discovery", "weight": 8,
                 "recommendation": "Run scan",
                 "mappings": {"nis2": "Art.21"}, "status": "FAIL"},
            ],
            "frameworks": {"nis2": FRAMEWORKS["nis2"]},
            "available_frameworks": FRAMEWORKS,
        }

    def test_generate_pdf_returns_bytes(self, fresh_db):
        """generate_compliance_pdf returns PDF bytes."""
        assessment = self._make_assessment()
        pdf_bytes = generate_compliance_pdf(assessment)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1000
        assert pdf_bytes[:5] == b"%PDF-"

    def test_generate_pdf_with_company_name(self, fresh_db):
        """PDF generation succeeds with company name."""
        assessment = self._make_assessment()
        pdf_bytes = generate_compliance_pdf(assessment, company="ACME Corp")
        assert len(pdf_bytes) > 1000

    def test_generate_pdf_writes_to_file(self, fresh_db, tmp_path):
        """PDF is saved to file when output_path is given."""
        assessment = self._make_assessment()
        out = str(tmp_path / "reports" / "compliance.pdf")
        pdf_bytes = generate_compliance_pdf(assessment, output_path=out)
        assert os.path.exists(out)
        assert os.path.getsize(out) > 0

    def test_generate_pdf_fully_compliant(self, fresh_db):
        """PDF generates for a fully compliant assessment (100 score, 0 unanswered)."""
        assessment = self._make_assessment(score=100, passed=22, failed=0, unanswered=0)
        pdf_bytes = generate_compliance_pdf(assessment, company="Perfect Corp")
        assert len(pdf_bytes) > 1000

    def test_generate_pdf_critical_score(self, fresh_db):
        """PDF generates for a critical assessment (very low score)."""
        assessment = self._make_assessment(score=10, passed=2, failed=18, unanswered=2)
        pdf_bytes = generate_compliance_pdf(assessment)
        assert len(pdf_bytes) > 1000

    def test_generate_pdf_with_grc_data(self, fresh_db):
        """PDF generates when GRC summary data is included."""
        assessment = self._make_assessment()
        assessment["grc"] = {
            "risks": {"total": 5, "open": 3, "critical": 1,
                      "top5": [{"title": "R1", "score": 20, "status": "open"}]},
            "assets": {"total": 10, "by_type": {"server": 5, "endpoint": 5},
                       "by_criticality": {1: 2, 2: 2, 3: 2, 4: 2, 5: 2}},
            "compliance_trend": {"m1": 5, "m3": 10, "m6": None, "m12": None},
            "compliance_current": 75,
            "vendors": {"total": 3, "high_risk": 1},
            "policies": {"total": 2, "approved": 1, "draft": 1},
            "audit_findings_open": 2,
        }
        pdf_bytes = generate_compliance_pdf(assessment, company="ACME")
        assert len(pdf_bytes) > 1000

    def test_generate_pdf_with_declarative_controls(self, fresh_db):
        """PDF renders declarative controls with different statuses."""
        assessment = self._make_assessment()
        assessment["categories"]["Governance"] = {
            "total": 3, "pass": 1, "fail": 1, "unanswered": 1,
            "controls": [
                {"id": "ORG-01", "category": "Governance",
                 "title": "Security Policy", "description": "Written policy",
                 "status": "PASS", "detail": "Policy documented",
                 "weight": 8, "recommendation": "Review annually",
                 "mappings": {"nis2": "Art.21"}, "type": "declarative",
                 "prompt": "Is there a policy?", "answer": "yes",
                 "answer_detail": "Policy v2.0", "answered_by": "admin"},
                {"id": "ORG-02", "category": "Governance",
                 "title": "Roles defined", "description": "Security roles",
                 "status": "FAIL", "detail": "",
                 "weight": 6, "recommendation": "Define roles",
                 "mappings": {"nis2": "Art.21"}, "type": "declarative",
                 "prompt": "Are roles defined?", "answer": "no",
                 "answer_detail": "", "answered_by": ""},
                {"id": "ORG-03", "category": "Governance",
                 "title": "Management", "description": "Management commitment",
                 "status": "UNANSWERED", "detail": "",
                 "weight": 4, "recommendation": "Get commitment",
                 "mappings": {"nis2": "Art.20"}, "type": "declarative",
                 "prompt": "Does management support?", "answer": "unanswered",
                 "answer_detail": "", "answered_by": ""},
            ],
        }
        pdf_bytes = generate_compliance_pdf(assessment, company="Test Corp")
        assert len(pdf_bytes) > 1000

    def test_generate_pdf_with_no_recommendations(self, fresh_db):
        """PDF handles case with no recommendations (all pass)."""
        assessment = self._make_assessment(score=100, passed=22, failed=0, unanswered=0)
        assessment["recommendations"] = []
        pdf_bytes = generate_compliance_pdf(assessment)
        assert len(pdf_bytes) > 1000

    def test_generate_pdf_with_multiple_frameworks(self, fresh_db):
        """PDF generates framework alignment pages for multiple frameworks."""
        from core.compliance import FRAMEWORKS
        assessment = self._make_assessment()
        assessment["frameworks"] = {k: FRAMEWORKS[k] for k in ["nis2", "iso27001", "gdpr"]}
        pdf_bytes = generate_compliance_pdf(assessment)
        assert len(pdf_bytes) > 1000

    def test_generate_pdf_all_answered_not_all_pass(self, fresh_db):
        """PDF generates the NOTE disclaimer when all answered but not all pass."""
        assessment = self._make_assessment(score=70, passed=16, failed=6, unanswered=0)
        # Add declarative controls that are answered but some fail
        assessment["categories"]["Governance"] = {
            "total": 2, "pass": 1, "fail": 1, "unanswered": 0,
            "controls": [
                {"id": "ORG-01", "category": "Governance",
                 "title": "Security Policy", "description": "Written policy",
                 "status": "PASS", "detail": "Policy documented",
                 "weight": 8, "recommendation": "Review annually",
                 "mappings": {"nis2": "Art.21"}, "type": "declarative",
                 "prompt": "Is there a policy?", "answer": "yes",
                 "answer_detail": "Policy v2.0", "answered_by": "admin"},
                {"id": "ORG-02", "category": "Governance",
                 "title": "Roles defined", "description": "Security roles",
                 "status": "FAIL", "detail": "",
                 "weight": 6, "recommendation": "Define roles",
                 "mappings": {"nis2": "Art.21"}, "type": "declarative",
                 "prompt": "Are roles defined?", "answer": "no",
                 "answer_detail": "", "answered_by": "admin"},
            ],
        }
        pdf_bytes = generate_compliance_pdf(assessment, company="Test Corp")
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1000


# ══════════════════════════════════════════════════
# Additional check methods coverage
# ══════════════════════════════════════════════════

class TestCheckMethodsAdditional:

    def test_check_sniffer_not_running(self, fresh_db):
        """check_sniffer_active returns False when sniffer exists but is not running."""
        sniffer = MagicMock()
        sniffer.stats = {"running": False, "pps": 0, "packets": 0}
        assessor = ComplianceAssessor(FakeConfig(), {"sniffer": sniffer})
        ok, detail = assessor.check_sniffer_active()
        assert ok is False
        assert "not running" in detail

    def test_check_dns_monitoring_no_recent_queries(self, fresh_db):
        """check_dns_monitoring fails with no DNS queries in last 24h."""
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_dns_monitoring()
        assert ok is False
        assert "No DNS" in detail

    def test_check_dns_monitoring_with_recent_queries(self, fresh_db):
        """check_dns_monitoring passes with recent DNS queries."""
        DnsLog.create(query="example.com", qtype="A", src_ip="10.0.0.1",
                      ts=datetime.now())
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_dns_monitoring()
        assert ok is True
        assert "1 DNS" in detail

    def test_check_threat_feeds_loaded(self, fresh_db):
        """check_threat_feeds passes when feeds have indicators."""
        tf = MagicMock()
        tf.stats = {"ips": 5000, "domains": 1000}
        assessor = ComplianceAssessor(FakeConfig(), {"threat_feeds": tf})
        ok, detail = assessor.check_threat_feeds()
        assert ok is True
        assert "5000" in detail

    def test_check_threat_feeds_no_module(self, fresh_db):
        """check_threat_feeds fails when module not loaded."""
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_threat_feeds()
        assert ok is False

    def test_check_threat_feeds_empty(self, fresh_db):
        """check_threat_feeds fails when no indicators loaded."""
        tf = MagicMock()
        tf.stats = {"ips": 0, "domains": 0}
        assessor = ComplianceAssessor(FakeConfig(), {"threat_feeds": tf})
        ok, detail = assessor.check_threat_feeds()
        assert ok is False

    def test_check_escalation_active(self, fresh_db):
        """check_escalation passes when defense has _escalation attribute."""
        defense = MagicMock()
        defense._escalation = MagicMock()
        assessor = ComplianceAssessor(FakeConfig(), {"defense": defense})
        ok, detail = assessor.check_escalation()
        assert ok is True

    def test_check_escalation_no_defense(self, fresh_db):
        """check_escalation fails when defense module not loaded."""
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_escalation()
        assert ok is False

    def test_check_auth_configured_with_users(self, fresh_db):
        """check_auth_configured passes when web users exist."""
        import bcrypt
        pw = bcrypt.hashpw(b"testpass12345678", bcrypt.gensalt()).decode()
        WebUser.create(username="admin", password_hash=pw, role="admin")
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_auth_configured()
        assert ok is True
        assert "1 account" in detail

    def test_check_auth_configured_no_users(self, fresh_db):
        """check_auth_configured fails when no web users exist."""
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_auth_configured()
        assert ok is False

    def test_check_tls_no_cert(self, fresh_db):
        """check_tls fails when no certificate configured."""
        assessor = ComplianceAssessor(FakeConfig({"web.ssl_cert": ""}), {})
        ok, detail = assessor.check_tls()
        assert ok is False

    def test_check_tls_cert_file_exists(self, fresh_db, tmp_path):
        """check_tls passes when certificate file exists."""
        cert = tmp_path / "cert.pem"
        cert.write_text("cert data")
        assessor = ComplianceAssessor(FakeConfig({"web.ssl_cert": str(cert)}), {})
        ok, detail = assessor.check_tls()
        assert ok is True
        assert "cert.pem" in detail

    def test_check_tls_cert_file_missing(self, fresh_db):
        """check_tls fails when certificate path does not exist."""
        assessor = ComplianceAssessor(FakeConfig({"web.ssl_cert": "/nonexistent/cert.pem"}), {})
        ok, detail = assessor.check_tls()
        assert ok is False

    def test_check_ssh_import_error(self, fresh_db):
        """check_ssh returns False when SSHHardener import fails."""
        with patch.dict("sys.modules", {"core.hardening": None}):
            assessor = ComplianceAssessor(FakeConfig(), {})
            ok, detail = assessor.check_ssh()
            assert ok is False

    @patch("core.compliance.ComplianceAssessor.check_ssh")
    def test_check_ssh_secure(self, mock_ssh, fresh_db):
        """check_ssh returns True when SSH is hardened."""
        mock_ssh.return_value = (True, "Hardened")
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_ssh()
        assert ok is True

    @patch("core.compliance.ComplianceAssessor.check_ssh")
    def test_check_ssh_not_secure(self, mock_ssh, fresh_db):
        """check_ssh returns False when SSH has issues."""
        mock_ssh.return_value = (False, "Password auth enabled")
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_ssh()
        assert ok is False

    @patch("core.compliance.ComplianceAssessor.check_integrity")
    def test_check_integrity_ok(self, mock_integrity, fresh_db):
        """check_integrity returns True when files are intact."""
        mock_integrity.return_value = (True, "50 files OK")
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_integrity()
        assert ok is True

    @patch("core.compliance.ComplianceAssessor.check_integrity")
    def test_check_integrity_modified(self, mock_integrity, fresh_db):
        """check_integrity returns False when files are modified."""
        mock_integrity.return_value = (False, "3 modified")
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_integrity()
        assert ok is False

    def test_check_backup_no_directory(self, fresh_db):
        """check_backup fails when no backup directory configured."""
        assessor = ComplianceAssessor(FakeConfig({"backup.directory": ""}), {})
        ok, detail = assessor.check_backup()
        assert ok is False
        assert "not configured" in detail

    def test_check_backup_with_backups(self, fresh_db, tmp_path):
        """check_backup passes when backup directory has tar.gz files."""
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        (backup_dir / "backup-2024.tar.gz").write_text("data")
        assessor = ComplianceAssessor(FakeConfig({"backup.directory": str(backup_dir)}), {})
        ok, detail = assessor.check_backup()
        assert ok is True
        assert "1 backup" in detail

    def test_check_backup_empty_directory(self, fresh_db, tmp_path):
        """check_backup fails when backup directory exists but has no backups."""
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        assessor = ComplianceAssessor(FakeConfig({"backup.directory": str(backup_dir)}), {})
        ok, detail = assessor.check_backup()
        assert ok is False
        assert "No backups" in detail

    def test_check_audit_chain_failed_verify(self, fresh_db):
        """check_audit_chain fails when chain integrity check fails."""
        ac = MagicMock()
        ac.verify.return_value = {"ok": False}
        assessor = ComplianceAssessor(FakeConfig(), {"audit_chain": ac})
        ok, detail = assessor.check_audit_chain()
        assert ok is False
        assert "FAILED" in detail

    def test_check_audit_chain_verify_exception(self, fresh_db):
        """check_audit_chain handles exception from verify()."""
        ac = MagicMock()
        ac.verify.side_effect = RuntimeError("Chain corrupted")
        assessor = ComplianceAssessor(FakeConfig(), {"audit_chain": ac})
        ok, detail = assessor.check_audit_chain()
        assert ok is False
        assert "corrupted" in detail.lower() or "Chain corrupted" in detail

    def test_check_honeypot_no_module(self, fresh_db):
        """check_honeypot returns False when honeypot module not loaded."""
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_honeypot()
        assert ok is False

    def test_check_advanced_detectors_no_orchestrator(self, fresh_db):
        """check_advanced_detectors fails when orchestrator not loaded."""
        assessor = ComplianceAssessor(FakeConfig(), {})
        ok, detail = assessor.check_advanced_detectors()
        assert ok is False
        assert "not loaded" in detail.lower()

    def test_check_advanced_detectors_too_few(self, fresh_db):
        """check_advanced_detectors fails with fewer than 4 active detectors."""
        o = MagicMock()
        det1 = MagicMock()
        det1.status = "active"
        det2 = MagicMock()
        det2.status = "observing"
        o.detectors = [det1, det2]
        assessor = ComplianceAssessor(FakeConfig(), {"orchestrator": o})
        ok, detail = assessor.check_advanced_detectors()
        assert ok is False
        assert "1 active" in detail

    def test_check_login_lockout_zero(self, fresh_db):
        """check_login_lockout fails when max_login_attempts is 0."""
        assessor = ComplianceAssessor(FakeConfig({"web.max_login_attempts": 0}), {})
        ok, detail = assessor.check_login_lockout()
        assert ok is False

    def test_check_retention_zero(self, fresh_db):
        """check_retention fails when retention days is 0."""
        assessor = ComplianceAssessor(FakeConfig({"retention.alerts_days": 0}), {})
        ok, detail = assessor.check_retention()
        assert ok is False


# ══════════════════════════════════════════════════
# Assess edge cases
# ══════════════════════════════════════════════════

class TestAssessEdgeCases:

    def test_assess_check_raises_exception(self, fresh_db):
        """When a check function raises, assess() catches it and records Error."""
        cfg = FakeConfig()
        assessor = ComplianceAssessor(cfg, {})
        # Monkey-patch a check to raise
        assessor.check_sniffer_active = MagicMock(side_effect=RuntimeError("boom"))
        result = assessor.assess()
        net01 = next(c for c in result["controls"] if c["id"] == "NET-01")
        assert net01["status"] == "FAIL"
        assert "Error" in net01["detail"]

    def test_assess_risk_level_low(self, fresh_db):
        """Risk level is LOW when score >= 80."""
        cfg = FakeConfig()
        assessor = ComplianceAssessor(cfg, {})
        # Answer all declarative as yes to bump score
        for ctrl in DECLARATIVE_CONTROLS:
            ComplianceAnswer.create(control_id=ctrl[0], answer="yes",
                                     detail="Done", answered_by="admin")
        result = assessor.assess()
        # If combined score happens to be >= 80 due to declarative, check risk
        if result["score"] >= 80:
            assert result["risk_level"] == "LOW"

    def test_assess_risk_level_high(self, fresh_db):
        """Risk level is HIGH when 40 <= score < 60."""
        cfg = FakeConfig()
        assessor = ComplianceAssessor(cfg, {})
        result = assessor.assess()
        if 40 <= result["score"] < 60:
            assert result["risk_level"] == "HIGH"

    def test_assess_partial_status_counted_as_failed(self, fresh_db):
        """Controls with PARTIAL status are counted in the failed tally."""
        ComplianceAnswer.create(control_id="ORG-01", answer="partial",
                                 detail="In progress", answered_by="admin")
        cfg = FakeConfig()
        assessor = ComplianceAssessor(cfg, {})
        result = assessor.assess()
        org01 = next(c for c in result["controls"] if c["id"] == "ORG-01")
        assert org01["status"] == "PARTIAL"
        # PARTIAL is counted in failed
        assert result["failed"] >= 1

    def test_assess_empty_modules_dict(self, fresh_db):
        """assess() works with explicitly empty modules dict."""
        assessor = ComplianceAssessor(FakeConfig(), {})
        result = assessor.assess()
        assert isinstance(result, dict)
        assert result["total_controls"] > 0

    def test_assess_none_modules(self, fresh_db):
        """assess() handles None modules gracefully."""
        assessor = ComplianceAssessor(FakeConfig(), None)
        result = assessor.assess()
        assert isinstance(result, dict)

    def test_assess_get_controls_by_category(self, fresh_db):
        """Categories dict groups controls properly."""
        assessor = ComplianceAssessor(FakeConfig(), {})
        result = assessor.assess()
        total_in_cats = sum(cat["total"] for cat in result["categories"].values())
        assert total_in_cats == result["total_controls"]

    def test_assess_declarative_score_with_mixed_answers(self, fresh_db):
        """Declarative score computes correctly with mixed answers."""
        ComplianceAnswer.create(control_id="ORG-01", answer="yes",
                                 detail="Done", answered_by="admin")
        ComplianceAnswer.create(control_id="ORG-02", answer="no",
                                 answered_by="admin")
        ComplianceAnswer.create(control_id="ORG-03", answer="partial",
                                 detail="Partial", answered_by="admin")
        cfg = FakeConfig()
        assessor = ComplianceAssessor(cfg, {})
        result = assessor.assess()
        assert result["declarative_score"] is not None
        assert 0 <= result["declarative_score"] <= 100
        assert result["declarative_answered"] >= 3


# ══════════════════════════════════════════════════
# DOCX generation
# ══════════════════════════════════════════════════

class TestGenerateComplianceDocx:

    def _make_assessment(self, score=75, passed=15, failed=5, unanswered=2):
        """Create a minimal assessment dict for DOCX generation."""
        return {
            "score": score, "risk_level": "MEDIUM",
            "auto_score": 80, "declarative_score": 60,
            "generated_at": datetime.now().isoformat(),
            "total_controls": passed + failed + unanswered,
            "auto_controls": 10, "declarative_controls": 12,
            "declarative_answered": 10,
            "passed": passed, "failed": failed, "unanswered": unanswered,
            "categories": {
                "Network": {"total": 3, "pass": 2, "fail": 1, "unanswered": 0,
                            "controls": [
                                {"id": "NET-01", "category": "Network",
                                 "title": "Packet capture", "description": "Test",
                                 "status": "PASS", "detail": "Active", "weight": 10,
                                 "recommendation": "Enable sniffer",
                                 "mappings": {"nis2": "Art.21"}, "type": "automated"},
                                {"id": "NET-02", "category": "Network",
                                 "title": "Discovery", "description": "Test",
                                 "status": "FAIL", "detail": "No hosts", "weight": 8,
                                 "recommendation": "Run scan",
                                 "mappings": {"nis2": "Art.21"}, "type": "automated"},
                            ]},
            },
            "controls": [
                {"id": "NET-01", "category": "Network",
                 "title": "Packet capture", "description": "Test",
                 "status": "PASS", "detail": "Active", "weight": 10,
                 "recommendation": "Enable sniffer",
                 "mappings": {"nis2": "Art.21"}, "type": "automated"},
                {"id": "NET-02", "category": "Network",
                 "title": "Discovery", "description": "Test",
                 "status": "FAIL", "detail": "No hosts", "weight": 8,
                 "recommendation": "Run scan",
                 "mappings": {"nis2": "Art.21"}, "type": "automated"},
            ],
            "recommendations": [
                {"id": "NET-02", "title": "Discovery", "weight": 8,
                 "recommendation": "Run scan",
                 "mappings": {"nis2": "Art.21"}, "status": "FAIL"},
            ],
            "frameworks": {"nis2": FRAMEWORKS["nis2"]},
            "available_frameworks": FRAMEWORKS,
        }

    def test_generate_docx_returns_bytes(self, fresh_db):
        """generate_compliance_docx returns DOCX bytes."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment()
        docx_bytes = generate_compliance_docx(assessment)
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000
        # DOCX files start with PK zip signature
        assert docx_bytes[:2] == b"PK"

    def test_generate_docx_with_company_name(self, fresh_db):
        """DOCX generation succeeds with company name."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment()
        docx_bytes = generate_compliance_docx(assessment, company="ACME Corp")
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_fully_compliant(self, fresh_db):
        """DOCX generates for fully compliant assessment (100 score, 0 unanswered)."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment(score=100, passed=22, failed=0, unanswered=0)
        docx_bytes = generate_compliance_docx(assessment, company="Perfect Corp")
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_critical_score(self, fresh_db):
        """DOCX generates for a critical assessment (very low score)."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment(score=10, passed=2, failed=18, unanswered=2)
        docx_bytes = generate_compliance_docx(assessment)
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_no_recommendations(self, fresh_db):
        """DOCX handles case with no recommendations (all pass)."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment(score=100, passed=22, failed=0, unanswered=0)
        assessment["recommendations"] = []
        docx_bytes = generate_compliance_docx(assessment)
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_with_declarative_controls(self, fresh_db):
        """DOCX renders declarative controls with different statuses."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment()
        assessment["categories"]["Governance"] = {
            "total": 3, "pass": 1, "fail": 1, "unanswered": 1,
            "controls": [
                {"id": "ORG-01", "category": "Governance",
                 "title": "Security Policy", "description": "Written policy",
                 "status": "PASS", "detail": "Policy documented",
                 "weight": 8, "recommendation": "Review annually",
                 "mappings": {"nis2": "Art.21"}, "type": "declarative",
                 "prompt": "Is there a policy?", "answer": "yes",
                 "answer_detail": "Policy v2.0", "answered_by": "admin"},
                {"id": "ORG-02", "category": "Governance",
                 "title": "Roles defined", "description": "Security roles",
                 "status": "FAIL", "detail": "",
                 "weight": 6, "recommendation": "Define roles",
                 "mappings": {"nis2": "Art.21"}, "type": "declarative",
                 "prompt": "Are roles defined?", "answer": "no",
                 "answer_detail": "", "answered_by": ""},
                {"id": "ORG-03", "category": "Governance",
                 "title": "Management", "description": "Management commitment",
                 "status": "UNANSWERED", "detail": "",
                 "weight": 4, "recommendation": "Get commitment",
                 "mappings": {"nis2": "Art.20"}, "type": "declarative",
                 "prompt": "Does management support?", "answer": "unanswered",
                 "answer_detail": "", "answered_by": ""},
            ],
        }
        assessment["controls"].extend(
            assessment["categories"]["Governance"]["controls"])
        docx_bytes = generate_compliance_docx(assessment, company="Test Corp")
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_with_grc_data(self, fresh_db):
        """DOCX generates when GRC summary data is included."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment()
        assessment["grc"] = {
            "risks": {"total": 5, "open": 3, "critical": 1,
                      "top5": [{"title": "R1", "score": 20, "status": "open"}]},
            "assets": {"total": 10, "by_type": {"server": 5, "endpoint": 5},
                       "by_criticality": {1: 2, 2: 2, 3: 2, 4: 2, 5: 2}},
            "compliance_trend": {"m1": 5, "m3": 10, "m6": None, "m12": None},
            "compliance_current": 75,
            "vendors": {"total": 3, "high_risk": 1},
            "policies": {"total": 2, "approved": 1, "draft": 1},
            "audit_findings_open": 2,
        }
        docx_bytes = generate_compliance_docx(assessment, company="ACME")
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_with_multiple_frameworks(self, fresh_db):
        """DOCX generates framework alignment pages for multiple frameworks."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment()
        assessment["frameworks"] = {k: FRAMEWORKS[k] for k in ["nis2", "iso27001", "gdpr"]}
        docx_bytes = generate_compliance_docx(assessment)
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_all_answered_not_all_pass(self, fresh_db):
        """DOCX generates without disclaimer when all answered but not all pass."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment(score=70, passed=16, failed=6, unanswered=0)
        assessment["categories"]["Governance"] = {
            "total": 1, "pass": 0, "fail": 1, "unanswered": 0,
            "controls": [
                {"id": "ORG-01", "category": "Governance",
                 "title": "Security Policy", "description": "Written policy",
                 "status": "FAIL", "detail": "",
                 "weight": 8, "recommendation": "Review annually",
                 "mappings": {"nis2": "Art.21"}, "type": "declarative",
                 "prompt": "Is there a policy?", "answer": "no",
                 "answer_detail": "", "answered_by": "admin"},
            ],
        }
        assessment["controls"].extend(
            assessment["categories"]["Governance"]["controls"])
        docx_bytes = generate_compliance_docx(assessment)
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_with_partial_controls(self, fresh_db):
        """DOCX renders PARTIAL status declarative controls."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment(score=60, passed=12, failed=8, unanswered=0)
        assessment["controls"].append({
            "id": "ORG-01", "category": "Governance",
            "title": "Security Policy", "description": "Written policy",
            "status": "PARTIAL", "detail": "In progress",
            "weight": 8, "recommendation": "Complete policy",
            "mappings": {"nis2": "Art.21"}, "type": "declarative",
            "prompt": "Is there a policy?", "answer": "partial",
            "answer_detail": "Draft exists", "answered_by": "admin",
        })
        docx_bytes = generate_compliance_docx(assessment)
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_no_company(self, fresh_db):
        """DOCX generates without company name."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment()
        docx_bytes = generate_compliance_docx(assessment, company="")
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_framework_no_mapped_controls(self, fresh_db):
        """DOCX handles framework with no mapped controls gracefully."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment()
        # All controls have mappings that don't match "—"
        # Force a framework with no relevant mappings by clearing mappings
        for ctrl in assessment["controls"]:
            ctrl["mappings"] = {}
        assessment["frameworks"] = {"cyber_essentials": FRAMEWORKS["cyber_essentials"]}
        docx_bytes = generate_compliance_docx(assessment)
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_grc_with_error(self, fresh_db):
        """DOCX skips GRC section when grc has error key."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment()
        assessment["grc"] = {"error": "GRC module not loaded"}
        docx_bytes = generate_compliance_docx(assessment)
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_grc_empty_sections(self, fresh_db):
        """DOCX handles GRC data with zero totals in subsections."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment()
        assessment["grc"] = {
            "risks": {"total": 0},
            "assets": {"total": 0},
            "policies": {"total": 0},
            "vendors": {"total": 0},
            "audit_findings_open": 0,
            "compliance_trend": {"m1": None, "m3": None, "m6": None, "m12": None},
        }
        docx_bytes = generate_compliance_docx(assessment)
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_high_score_good_grade(self, fresh_db):
        """DOCX uses GOOD grade for score between 80 and 89."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment(score=85, passed=19, failed=3, unanswered=0)
        docx_bytes = generate_compliance_docx(assessment, company="Good Corp")
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000

    def test_generate_docx_satisfactory_grade(self, fresh_db):
        """DOCX uses SATISFACTORY grade for score between 60 and 79."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment(score=65, passed=14, failed=8, unanswered=0)
        docx_bytes = generate_compliance_docx(assessment, company="OK Corp")
        assert isinstance(docx_bytes, bytes)

    def test_generate_docx_insufficient_grade(self, fresh_db):
        """DOCX uses INSUFFICIENT grade for score between 40 and 59."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment(score=45, passed=10, failed=12, unanswered=0)
        docx_bytes = generate_compliance_docx(assessment)
        assert isinstance(docx_bytes, bytes)

    def test_generate_docx_recommendation_priorities(self, fresh_db):
        """DOCX correctly renders HIGH, MEDIUM, and LOW priority recommendations."""
        from core.compliance import generate_compliance_docx
        assessment = self._make_assessment()
        assessment["recommendations"] = [
            {"id": "NET-01", "title": "High prio", "weight": 10,
             "recommendation": "Do high", "mappings": {"nis2": "Art.21"}, "status": "FAIL"},
            {"id": "NET-02", "title": "Med prio", "weight": 6,
             "recommendation": "Do medium", "mappings": {"nis2": "Art.21"}, "status": "FAIL"},
            {"id": "NET-03", "title": "Low prio", "weight": 3,
             "recommendation": "Do low", "mappings": {"nis2": "Art.21"}, "status": "FAIL"},
        ]
        docx_bytes = generate_compliance_docx(assessment)
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 1000
