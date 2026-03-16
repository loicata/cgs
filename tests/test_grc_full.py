"""Tests for core/grc.py — capture_compliance_snapshot, risk matrix, evidence, vendors."""
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta
from io import BytesIO
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.database import (
    db, init_db, Risk, Asset, Evidence, ComplianceSnapshot,
    Policy, Audit, AuditFinding, Vendor, VendorQuestion, RiskControlMap,
    WebUser,
)
from core.grc import (
    capture_compliance_snapshot, get_compliance_history,
    get_risk_matrix, get_risk_exposure,
    save_evidence, get_evidence_path, delete_evidence,
    compute_vendor_score, create_vendor_with_questions,
    get_grc_summary, ALLOWED_EXT, MAX_EVIDENCE_SIZE, DEFAULT_VENDOR_QUESTIONS,
)


# ══════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════

class FakeConfig:
    def __init__(self, data_dir):
        self._d = {
            "general.data_dir": data_dir,
            "general.log_dir": data_dir,
        }

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
def evidence_dir(tmp_path):
    d = str(tmp_path / "evidence")
    os.makedirs(d, exist_ok=True)
    return d


# ══════════════════════════════════════════════════
# capture_compliance_snapshot
# ══════════════════════════════════════════════════

class TestCaptureComplianceSnapshot:

    def test_snapshot_creates_record_in_db(self, fresh_db):
        """capture_compliance_snapshot creates a ComplianceSnapshot record."""
        cfg = FakeConfig(str(fresh_db))
        mock_assessor = MagicMock()
        mock_assessor.return_value.assess.return_value = {
            "score": 75, "auto_score": 80, "declarative_score": 70,
            "risk_level": "MEDIUM", "passed": 15, "failed": 5, "unanswered": 2,
            "categories": {
                "Network": {"total": 3, "pass": 2, "fail": 1},
                "Detection": {"total": 4, "pass": 3, "fail": 1},
            },
        }
        with patch("core.compliance.ComplianceAssessor", mock_assessor):
            capture_compliance_snapshot(cfg, {})
        assert ComplianceSnapshot.select().count() == 1
        snap = ComplianceSnapshot.select().first()
        assert snap.score == 75
        assert snap.risk_level == "MEDIUM"

    def test_snapshot_stores_category_json(self, fresh_db):
        """Snapshot stores per-category summary as JSON."""
        cfg = FakeConfig(str(fresh_db))
        mock_assessor = MagicMock()
        mock_assessor.return_value.assess.return_value = {
            "score": 60, "auto_score": 60, "declarative_score": None,
            "risk_level": "MEDIUM", "passed": 10, "failed": 10, "unanswered": 0,
            "categories": {"Network": {"total": 5, "pass": 3, "fail": 2}},
        }
        with patch("core.compliance.ComplianceAssessor", mock_assessor):
            capture_compliance_snapshot(cfg, {})
        snap = ComplianceSnapshot.select().first()
        cats = json.loads(snap.categories_json)
        assert "Network" in cats
        assert cats["Network"]["score"] == 60

    def test_snapshot_handles_assessor_error(self, fresh_db):
        """capture_compliance_snapshot handles exceptions gracefully."""
        cfg = FakeConfig(str(fresh_db))
        mock_assessor = MagicMock()
        mock_assessor.return_value.assess.side_effect = RuntimeError("test error")
        with patch("core.compliance.ComplianceAssessor", mock_assessor):
            capture_compliance_snapshot(cfg, {})  # Should not raise
        assert ComplianceSnapshot.select().count() == 0


# ══════════════════════════════════════════════════
# get_compliance_history
# ══════════════════════════════════════════════════

class TestGetComplianceHistory:

    def test_empty_history_returns_zero_current(self, fresh_db):
        """Empty history returns current=0."""
        result = get_compliance_history(12)
        assert result["current"] == 0
        assert result["snapshots"] == []

    def test_history_with_snapshots(self, fresh_db):
        """History returns snapshots in chronological order."""
        for i in range(3):
            ComplianceSnapshot.create(
                score=50 + i * 10, auto_score=50 + i * 10,
                risk_level="MEDIUM", passed=10 + i, failed=5,
                categories_json=json.dumps({"Network": {"pass": 2, "fail": 1, "score": 67}}),
            )
        result = get_compliance_history(12)
        assert len(result["snapshots"]) == 3
        assert result["current"] == 70

    def test_history_deltas(self, fresh_db):
        """Deltas are computed correctly."""
        # Create old snapshot dated 100 days ago (before 90-day m3 cutoff)
        old = ComplianceSnapshot.create(score=40, auto_score=40, risk_level="HIGH",
                                         passed=8, failed=12)
        ComplianceSnapshot.update(ts=datetime.now() - timedelta(days=100)).where(
            ComplianceSnapshot.id == old.id).execute()
        # Create recent snapshot
        ComplianceSnapshot.create(score=70, auto_score=70, risk_level="MEDIUM",
                                   passed=14, failed=6)
        result = get_compliance_history(12)
        # m3 delta: current(70) - old(40) = 30; old is at -100d so it's before -90d target
        assert result["deltas"]["m3"] == 30


# ══════════════════════════════════════════════════
# get_risk_matrix
# ══════════════════════════════════════════════════

class TestGetRiskMatrix:

    def test_empty_risk_matrix(self, fresh_db):
        """Empty risk register returns all-zero matrix."""
        result = get_risk_matrix()
        assert result["matrix"] == [[0]*5 for _ in range(5)]

    def test_risk_matrix_counts_risks(self, fresh_db):
        """Risks are placed in correct matrix cells."""
        Risk.create(title="Risk A", likelihood=3, impact=4, risk_score=12, status="open")
        Risk.create(title="Risk B", likelihood=5, impact=5, risk_score=25, status="open")
        result = get_risk_matrix()
        # likelihood=3 -> index 2, impact=4 -> index 3
        assert result["matrix"][2][3] == 1
        # likelihood=5 -> index 4, impact=5 -> index 4
        assert result["matrix"][4][4] == 1

    def test_closed_risks_excluded(self, fresh_db):
        """Closed risks are not counted in the matrix."""
        Risk.create(title="Closed", likelihood=1, impact=1, risk_score=1, status="closed")
        result = get_risk_matrix()
        assert result["matrix"] == [[0]*5 for _ in range(5)]

    def test_risk_details_in_cells(self, fresh_db):
        """Risk details are available per cell."""
        Risk.create(title="Risk X", likelihood=2, impact=3, risk_score=6, status="open")
        result = get_risk_matrix()
        key = "1,2"
        assert key in result["details"]
        assert result["details"][key][0]["title"] == "Risk X"


# ══════════════════════════════════════════════════
# get_risk_exposure
# ══════════════════════════════════════════════════

class TestGetRiskExposure:

    def test_no_failing_controls_returns_empty(self, fresh_db):
        """All passing controls returns empty exposure list."""
        controls = [{"id": "NET-01", "status": "PASS"}]
        result = get_risk_exposure(controls)
        assert result == []

    def test_failing_control_exposes_mapped_risk(self, fresh_db):
        """Failing control exposes its mapped risk."""
        r = Risk.create(title="Data leak", likelihood=4, impact=5, risk_score=20, status="open")
        RiskControlMap.create(risk_id=r.id, control_id="NET-01")
        controls = [{"id": "NET-01", "status": "FAIL"}]
        result = get_risk_exposure(controls)
        assert len(result) == 1
        assert result[0]["title"] == "Data leak"
        assert "NET-01" in result[0]["failing_controls"]

    def test_exposure_sorted_by_risk_score_descending(self, fresh_db):
        """Exposed risks are sorted by risk score (highest first)."""
        r1 = Risk.create(title="Low", likelihood=1, impact=1, risk_score=1, status="open")
        r2 = Risk.create(title="High", likelihood=5, impact=5, risk_score=25, status="open")
        RiskControlMap.create(risk_id=r1.id, control_id="NET-01")
        RiskControlMap.create(risk_id=r2.id, control_id="NET-02")
        controls = [{"id": "NET-01", "status": "FAIL"}, {"id": "NET-02", "status": "FAIL"}]
        result = get_risk_exposure(controls)
        assert result[0]["risk_score"] > result[1]["risk_score"]


# ══════════════════════════════════════════════════
# Evidence management
# ══════════════════════════════════════════════════

class TestEvidenceManagement:

    def _make_file_obj(self, filename, content):
        """Create a mock file upload object."""
        fobj = MagicMock()
        fobj.filename = filename
        fobj.read.return_value = content
        return fobj

    def test_save_evidence_pdf(self, fresh_db, evidence_dir):
        """Saving a PDF evidence file succeeds."""
        fobj = self._make_file_obj("report.pdf", b"%PDF-1.4 content here")
        result = save_evidence(fobj, "NET-01", "Network report", "admin", evidence_dir)
        assert result["filename"] == "report.pdf"
        assert result["control_id"] == "NET-01"
        assert Evidence.select().count() == 1

    def test_save_evidence_rejects_disallowed_extension(self, fresh_db, evidence_dir):
        """Disallowed file extensions are rejected."""
        fobj = self._make_file_obj("script.exe", b"MZ...")
        with pytest.raises(ValueError, match="not allowed"):
            save_evidence(fobj, "NET-01", "malicious", "admin", evidence_dir)

    def test_save_evidence_rejects_oversized_file(self, fresh_db, evidence_dir):
        """Files exceeding MAX_EVIDENCE_SIZE are rejected."""
        fobj = self._make_file_obj("huge.txt", b"x" * (MAX_EVIDENCE_SIZE + 1))
        with pytest.raises(ValueError, match="too large"):
            save_evidence(fobj, "NET-01", "huge", "admin", evidence_dir)

    def test_save_evidence_validates_magic_bytes(self, fresh_db, evidence_dir):
        """Files with wrong magic bytes for their extension are rejected."""
        fobj = self._make_file_obj("fake.png", b"NOT A PNG FILE")
        with pytest.raises(ValueError, match="does not match"):
            save_evidence(fobj, "NET-01", "fake png", "admin", evidence_dir)

    def test_save_evidence_txt_accepts_any_content(self, fresh_db, evidence_dir):
        """TXT files accept any content (no magic byte check)."""
        fobj = self._make_file_obj("notes.txt", b"just some text")
        result = save_evidence(fobj, "NET-01", "notes", "admin", evidence_dir)
        assert result["filename"] == "notes.txt"

    def test_get_evidence_path_returns_correct_path(self, fresh_db, evidence_dir):
        """get_evidence_path returns the stored file path."""
        fobj = self._make_file_obj("report.pdf", b"%PDF-1.4 content here")
        result = save_evidence(fobj, "NET-01", "report", "admin", evidence_dir)
        filepath, filename, mime = get_evidence_path(result["id"], evidence_dir)
        assert os.path.exists(filepath)
        assert filename == "report.pdf"

    def test_delete_evidence_removes_file_and_record(self, fresh_db, evidence_dir):
        """delete_evidence removes both file and database record."""
        fobj = self._make_file_obj("report.pdf", b"%PDF-1.4 content here")
        result = save_evidence(fobj, "NET-01", "report", "admin", evidence_dir)
        ev_id = result["id"]
        delete_evidence(ev_id, evidence_dir)
        assert Evidence.select().count() == 0


# ══════════════════════════════════════════════════
# Vendor risk scoring
# ══════════════════════════════════════════════════

class TestVendorScoring:

    def test_no_questions_returns_na(self, fresh_db):
        """No questions returns N/A grade."""
        v = Vendor.create(name="Test", criticality=3)
        result = compute_vendor_score(v.id)
        assert result["grade"] == "N/A"
        assert result["score"] == 0

    def test_all_yes_returns_grade_a(self, fresh_db):
        """All 'yes' answers returns grade A, score 100."""
        v = Vendor.create(name="Good Vendor", criticality=3)
        for q in DEFAULT_VENDOR_QUESTIONS:
            VendorQuestion.create(vendor_id=v.id, question=q, answer="yes")
        result = compute_vendor_score(v.id)
        assert result["grade"] == "A"
        assert result["score"] == 100
        assert result["risk_level"] == "low"

    def test_all_no_returns_grade_f(self, fresh_db):
        """All 'no' answers returns grade F."""
        v = Vendor.create(name="Bad Vendor", criticality=5)
        for q in DEFAULT_VENDOR_QUESTIONS:
            VendorQuestion.create(vendor_id=v.id, question=q, answer="no")
        result = compute_vendor_score(v.id)
        assert result["grade"] == "F"
        assert result["score"] == 0

    def test_partial_answers_score(self, fresh_db):
        """Partial answers score 50 points each."""
        v = Vendor.create(name="OK Vendor", criticality=3)
        for q in DEFAULT_VENDOR_QUESTIONS:
            VendorQuestion.create(vendor_id=v.id, question=q, answer="partial")
        result = compute_vendor_score(v.id)
        assert result["score"] == 50
        assert result["grade"] == "C"

    def test_mixed_answers(self, fresh_db):
        """Mixed answers produce intermediate score."""
        v = Vendor.create(name="Mixed", criticality=3)
        answers = ["yes"] * 5 + ["no"] * 5
        for i, q in enumerate(DEFAULT_VENDOR_QUESTIONS):
            VendorQuestion.create(vendor_id=v.id, question=q, answer=answers[i])
        result = compute_vendor_score(v.id)
        assert result["score"] == 50
        assert result["answered"] == 10


# ══════════════════════════════════════════════════
# create_vendor_with_questions
# ══════════════════════════════════════════════════

class TestCreateVendorWithQuestions:

    def test_creates_vendor_and_questions(self, fresh_db):
        """Creates vendor with all default questions."""
        vid = create_vendor_with_questions(
            {"name": "CloudCo", "service": "Hosting", "criticality": 4}, "admin")
        assert Vendor.get_by_id(vid).name == "CloudCo"
        assert VendorQuestion.select().where(VendorQuestion.vendor_id == vid).count() == len(DEFAULT_VENDOR_QUESTIONS)

    def test_criticality_is_clamped(self, fresh_db):
        """Criticality is clamped to 1-5 range."""
        vid = create_vendor_with_questions({"name": "V", "criticality": 99}, "admin")
        assert Vendor.get_by_id(vid).criticality == 5
        vid2 = create_vendor_with_questions({"name": "V2", "criticality": -1}, "admin")
        assert Vendor.get_by_id(vid2).criticality == 1


# ══════════════════════════════════════════════════
# get_grc_summary
# ══════════════════════════════════════════════════

class TestGetGrcSummary:

    def test_summary_returns_expected_keys(self, fresh_db):
        """GRC summary contains all expected sections."""
        result = get_grc_summary()
        assert "risks" in result
        assert "assets" in result
        assert "compliance_current" in result
        assert "vendors" in result
        assert "policies" in result

    def test_summary_counts_risks(self, fresh_db):
        """Summary correctly counts open and critical risks."""
        Risk.create(title="R1", likelihood=5, impact=5, risk_score=25, status="open")
        Risk.create(title="R2", likelihood=1, impact=1, risk_score=1, status="closed")
        result = get_grc_summary()
        assert result["risks"]["total"] == 2
        assert result["risks"]["open"] == 1
        assert result["risks"]["critical"] == 1

    def test_summary_counts_assets_by_type(self, fresh_db):
        """Summary groups assets by type."""
        Asset.create(name="Web1", asset_type="server", criticality=4)
        Asset.create(name="Web2", asset_type="server", criticality=3)
        Asset.create(name="Laptop1", asset_type="endpoint", criticality=2)
        result = get_grc_summary()
        assert result["assets"]["total"] == 3
        assert result["assets"]["by_type"]["server"] == 2
        assert result["assets"]["by_type"]["endpoint"] == 1

    def test_summary_counts_policies(self, fresh_db):
        """Summary counts policies by status."""
        Policy.create(title="P1", status="approved", author="admin")
        Policy.create(title="P2", status="draft", author="admin")
        result = get_grc_summary()
        assert result["policies"]["total"] == 2
        assert result["policies"]["approved"] == 1
        assert result["policies"]["draft"] == 1
