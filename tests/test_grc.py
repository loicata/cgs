def test_risk_matrix(test_db):
    from core.database import Risk
    from core.grc import get_risk_matrix
    Risk.create(title="R1", likelihood=5, impact=5, risk_score=25)
    Risk.create(title="R2", likelihood=2, impact=3, risk_score=6)
    m = get_risk_matrix()
    assert "matrix" in m
    assert len(m["matrix"]) == 5
    assert m["matrix"][4][4] == 1  # R1 at L=5,I=5

def test_vendor_scoring(test_db):
    from core.grc import create_vendor_with_questions, compute_vendor_score
    vid = create_vendor_with_questions({"name": "TestVendor"}, "admin")
    score = compute_vendor_score(vid)
    assert score["score"] == 0  # all unanswered
    assert score["total"] == 10

def test_compliance_snapshot(test_db, test_config):
    from core.grc import capture_compliance_snapshot, get_compliance_history
    from core.database import ComplianceSnapshot
    capture_compliance_snapshot(test_config, {})
    assert ComplianceSnapshot.select().count() == 1
    h = get_compliance_history(1)
    assert len(h["snapshots"]) == 1

def test_grc_summary(test_db):
    from core.database import Risk, Asset, Vendor
    from core.grc import get_grc_summary
    Risk.create(title="R1", likelihood=5, impact=5, risk_score=25)
    Asset.create(name="Server1", asset_type="server")
    Vendor.create(name="V1", risk_level="high")
    s = get_grc_summary()
    assert s["risks"]["total"] == 1
    assert s["assets"]["total"] == 1
    assert s["vendors"]["total"] == 1
