def test_assess_returns_score(test_db, test_config):
    from core.compliance import ComplianceAssessor
    assessor = ComplianceAssessor(test_config, {})
    result = assessor.assess()
    assert "score" in result
    assert 0 <= result["score"] <= 100
    assert "controls" in result
    assert "recommendations" in result
    assert "categories" in result

def test_assess_with_frameworks(test_db, test_config):
    from core.compliance import ComplianceAssessor
    assessor = ComplianceAssessor(test_config, {})
    result = assessor.assess(frameworks=["nis2", "iso27001"])
    assert "nis2" in result["frameworks"]
    assert "iso27001" in result["frameworks"]
    assert "soc2" not in result["frameworks"]

def test_declarative_controls_present(test_db, test_config):
    from core.compliance import ComplianceAssessor
    assessor = ComplianceAssessor(test_config, {})
    result = assessor.assess()
    decl = [c for c in result["controls"] if c["type"] == "declarative"]
    assert len(decl) > 0
    auto = [c for c in result["controls"] if c["type"] == "automated"]
    assert len(auto) > 0

def test_compliance_answer(test_db):
    from core.database import ComplianceAnswer
    ComplianceAnswer.create(control_id="ORG-01", answer="yes", detail="Policy v2.0", answered_by="admin")
    a = ComplianceAnswer.get(ComplianceAnswer.control_id == "ORG-01")
    assert a.answer == "yes"
