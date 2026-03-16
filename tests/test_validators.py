"""Tests for core/validators.py — validation helpers and pagination."""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.validators import (
    ValidationError, validate_risk, validate_asset, validate_policy,
    validate_audit, validate_finding, validate_vendor,
    _str, _int_range, _enum, paginate,
)


# ── _str helper ──

class TestStr:
    def test_str_returns_stripped_value(self):
        assert _str({"k": "  hello  "}, "k") == "hello"

    def test_str_missing_key_returns_default(self):
        assert _str({}, "k", default="fallback") == "fallback"

    def test_str_required_missing_appends_error(self):
        errors = []
        result = _str({}, "k", required=True, errors=errors)
        assert result == ""
        assert "k is required" in errors

    def test_str_required_present_no_error(self):
        errors = []
        result = _str({"k": "val"}, "k", required=True, errors=errors)
        assert result == "val"
        assert errors == []

    def test_str_truncates_to_max_len(self):
        assert _str({"k": "abcdefghij"}, "k", max_len=5) == "abcde"

    def test_str_strips_control_characters(self):
        result = _str({"k": "he\x00ll\x07o"}, "k")
        assert result == "hello"

    def test_str_non_string_converted(self):
        assert _str({"k": 42}, "k") == "42"

    def test_str_none_value_returns_default(self):
        assert _str({"k": None}, "k", default="d") == "d"

    def test_str_empty_string_with_default(self):
        assert _str({"k": ""}, "k", default="d") == "d"

    def test_str_whitespace_only_required_raises_error(self):
        errors = []
        _str({"k": "   "}, "k", required=True, errors=errors)
        assert len(errors) == 1


# ── _int_range helper ──

class TestIntRange:
    def test_int_range_clamps_high(self):
        assert _int_range({"k": 10}, "k", 1, 5) == 5

    def test_int_range_clamps_low(self):
        assert _int_range({"k": 0}, "k", 1, 5) == 1

    def test_int_range_in_range(self):
        assert _int_range({"k": 3}, "k", 1, 5) == 3

    def test_int_range_missing_returns_default(self):
        assert _int_range({}, "k", 1, 5, default=3) == 3

    def test_int_range_invalid_returns_default(self):
        assert _int_range({"k": "abc"}, "k", 1, 5, default=3) == 3

    def test_int_range_invalid_no_default_returns_min(self):
        assert _int_range({"k": "abc"}, "k", 1, 5) == 1

    def test_int_range_string_number(self):
        assert _int_range({"k": "4"}, "k", 1, 5) == 4

    def test_int_range_none_value(self):
        assert _int_range({"k": None}, "k", 1, 5, default=2) == 2


# ── _enum helper ──

class TestEnum:
    def test_enum_valid_value(self):
        assert _enum({"k": "b"}, "k", ["a", "b", "c"]) == "b"

    def test_enum_invalid_returns_default(self):
        assert _enum({"k": "x"}, "k", ["a", "b"], default="a") == "a"

    def test_enum_missing_returns_default(self):
        assert _enum({}, "k", ["a", "b"], default="b") == "b"

    def test_enum_invalid_default_not_in_allowed_returns_first(self):
        assert _enum({"k": "x"}, "k", ["a", "b"], default="z") == "a"

    def test_enum_no_default_uses_first(self):
        assert _enum({}, "k", ["a", "b"]) == "a"


# ── validate_risk ──

class TestValidateRisk:
    def test_valid_risk(self):
        data = {"title": "Test Risk", "likelihood": 4, "impact": 3}
        result = validate_risk(data)
        assert result["title"] == "Test Risk"
        assert result["risk_score"] == 12
        assert result["status"] == "open"
        assert result["treatment"] == "mitigate"

    def test_risk_missing_title_raises(self):
        with pytest.raises(ValidationError) as exc_info:
            validate_risk({})
        assert "title is required" in exc_info.value.errors

    def test_risk_defaults_applied(self):
        result = validate_risk({"title": "R"})
        assert result["category"] == "operational"
        assert result["likelihood"] == 3
        assert result["impact"] == 3
        assert result["risk_score"] == 9

    def test_risk_enum_values(self):
        result = validate_risk({
            "title": "R",
            "category": "technical",
            "status": "closed",
            "treatment": "avoid",
        })
        assert result["category"] == "technical"
        assert result["status"] == "closed"
        assert result["treatment"] == "avoid"

    def test_risk_invalid_enum_uses_default(self):
        result = validate_risk({"title": "R", "category": "bogus"})
        assert result["category"] == "operational"


# ── validate_asset ──

class TestValidateAsset:
    def test_valid_asset(self):
        result = validate_asset({"name": "Web Server"})
        assert result["name"] == "Web Server"
        assert result["asset_type"] == "server"
        assert result["criticality"] == 3

    def test_asset_missing_name_raises(self):
        with pytest.raises(ValidationError):
            validate_asset({})

    def test_asset_all_fields(self):
        data = {
            "name": "DB",
            "asset_type": "data",
            "owner": "ops",
            "criticality": 5,
            "classification": "restricted",
            "location": "DC1",
            "description": "Main database",
            "dependencies": "network",
        }
        result = validate_asset(data)
        assert result["asset_type"] == "data"
        assert result["classification"] == "restricted"
        assert result["criticality"] == 5


# ── validate_policy ──

class TestValidatePolicy:
    def test_valid_policy(self):
        result = validate_policy({"title": "Security Policy"})
        assert result["title"] == "Security Policy"
        assert result["version"] == "1.0"
        assert result["status"] == "draft"

    def test_policy_missing_title_raises(self):
        with pytest.raises(ValidationError):
            validate_policy({})

    def test_policy_all_statuses(self):
        for s in ["draft", "review", "approved", "retired"]:
            result = validate_policy({"title": "P", "status": s})
            assert result["status"] == s


# ── validate_audit ──

class TestValidateAudit:
    def test_valid_audit(self):
        result = validate_audit({"title": "Q1 Audit"})
        assert result["title"] == "Q1 Audit"
        assert result["status"] == "planned"

    def test_audit_missing_title_raises(self):
        with pytest.raises(ValidationError):
            validate_audit({})


# ── validate_finding ──

class TestValidateFinding:
    def test_valid_finding(self):
        result = validate_finding({"description": "SQLi found"})
        assert result["description"] == "SQLi found"
        assert result["severity"] == "medium"
        assert result["status"] == "open"

    def test_finding_missing_description_raises(self):
        with pytest.raises(ValidationError):
            validate_finding({})

    def test_finding_severity_values(self):
        for s in ["critical", "high", "medium", "low", "info"]:
            result = validate_finding({"description": "x", "severity": s})
            assert result["severity"] == s


# ── validate_vendor ──

class TestValidateVendor:
    def test_valid_vendor(self):
        result = validate_vendor({"name": "Acme"})
        assert result["name"] == "Acme"
        assert result["criticality"] == 3

    def test_vendor_missing_name_raises(self):
        with pytest.raises(ValidationError):
            validate_vendor({})


# ── paginate ──

class TestPaginate:
    def test_paginate_basic(self, test_db):
        from core.database import Host
        for i in range(15):
            Host.create(ip=f"10.0.0.{i}")
        items, meta = paginate(Host.select(), page=1, per_page=5)
        assert len(items) == 5
        assert meta["total"] == 15
        assert meta["pages"] == 3
        assert meta["page"] == 1
        assert meta["per_page"] == 5

    def test_paginate_page_2(self, test_db):
        from core.database import Host
        for i in range(10):
            Host.create(ip=f"10.0.0.{i}")
        items, meta = paginate(Host.select(), page=2, per_page=4)
        assert len(items) == 4
        assert meta["page"] == 2

    def test_paginate_clamps_page_min(self, test_db):
        from core.database import Host
        Host.create(ip="10.0.0.1")
        _, meta = paginate(Host.select(), page=-5, per_page=10)
        assert meta["page"] == 1

    def test_paginate_clamps_per_page(self, test_db):
        from core.database import Host
        Host.create(ip="10.0.0.1")
        _, meta = paginate(Host.select(), per_page=999, max_per_page=50)
        assert meta["per_page"] == 50

    def test_paginate_per_page_min_is_one(self, test_db):
        from core.database import Host
        Host.create(ip="10.0.0.1")
        _, meta = paginate(Host.select(), per_page=0)
        assert meta["per_page"] == 1

    def test_paginate_empty_query(self, test_db):
        from core.database import Host
        items, meta = paginate(Host.select(), page=1, per_page=10)
        assert items == []
        assert meta["total"] == 0
        assert meta["pages"] == 0
