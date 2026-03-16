"""CGS — Input validation and pagination helpers."""

import re

class ValidationError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors


def validate_risk(data: dict) -> dict:
    """Validate and clean risk data. Raises ValidationError."""
    errors = []
    clean = {}
    clean["title"] = _str(data, "title", required=True, max_len=200, errors=errors)
    clean["description"] = _str(data, "description", max_len=2000, errors=errors)
    clean["category"] = _enum(data, "category", ["operational", "technical", "legal", "financial", "strategic"], default="operational", errors=errors)
    clean["likelihood"] = _int_range(data, "likelihood", 1, 5, default=3, errors=errors)
    clean["impact"] = _int_range(data, "impact", 1, 5, default=3, errors=errors)
    clean["risk_score"] = clean["likelihood"] * clean["impact"]
    clean["owner"] = _str(data, "owner", max_len=100, errors=errors)
    clean["status"] = _enum(data, "status", ["open", "mitigating", "accepted", "closed"], default="open", errors=errors)
    clean["treatment"] = _enum(data, "treatment", ["mitigate", "accept", "transfer", "avoid"], default="mitigate", errors=errors)
    clean["treatment_plan"] = _str(data, "treatment_plan", max_len=2000, errors=errors)
    if errors:
        raise ValidationError(errors)
    return clean


def validate_asset(data: dict) -> dict:
    """Validate and clean asset data. Raises ValidationError."""
    errors = []
    clean = {}
    clean["name"] = _str(data, "name", required=True, max_len=200, errors=errors)
    clean["asset_type"] = _enum(data, "asset_type", ["server", "application", "data", "service", "person"], default="server", errors=errors)
    clean["owner"] = _str(data, "owner", max_len=100, errors=errors)
    clean["criticality"] = _int_range(data, "criticality", 1, 5, default=3, errors=errors)
    clean["classification"] = _enum(data, "classification", ["public", "internal", "confidential", "restricted"], default="internal", errors=errors)
    clean["location"] = _str(data, "location", max_len=200, errors=errors)
    clean["description"] = _str(data, "description", max_len=2000, errors=errors)
    clean["dependencies"] = _str(data, "dependencies", max_len=500, errors=errors)
    if errors:
        raise ValidationError(errors)
    return clean


def validate_policy(data: dict) -> dict:
    """Validate and clean policy data. Raises ValidationError."""
    errors = []
    clean = {}
    clean["title"] = _str(data, "title", required=True, max_len=200, errors=errors)
    clean["content"] = _str(data, "content", max_len=50000, errors=errors)
    clean["version"] = _str(data, "version", max_len=20, default="1.0", errors=errors)
    clean["status"] = _enum(data, "status", ["draft", "review", "approved", "retired"], default="draft", errors=errors)
    clean["author"] = _str(data, "author", max_len=100, errors=errors)
    clean["approver"] = _str(data, "approver", max_len=100, errors=errors)
    if errors:
        raise ValidationError(errors)
    return clean


def validate_audit(data: dict) -> dict:
    """Validate and clean audit data. Raises ValidationError."""
    errors = []
    clean = {}
    clean["title"] = _str(data, "title", required=True, max_len=200, errors=errors)
    clean["scope"] = _str(data, "scope", max_len=2000, errors=errors)
    clean["auditor"] = _str(data, "auditor", max_len=100, errors=errors)
    clean["status"] = _enum(data, "status", ["planned", "in-progress", "complete"], default="planned", errors=errors)
    if errors:
        raise ValidationError(errors)
    return clean


def validate_finding(data: dict) -> dict:
    """Validate and clean finding data. Raises ValidationError."""
    errors = []
    clean = {}
    clean["description"] = _str(data, "description", required=True, max_len=2000, errors=errors)
    clean["severity"] = _enum(data, "severity", ["critical", "high", "medium", "low", "info"], default="medium", errors=errors)
    clean["remediation_plan"] = _str(data, "remediation_plan", max_len=2000, errors=errors)
    clean["responsible"] = _str(data, "responsible", max_len=100, errors=errors)
    clean["status"] = _enum(data, "status", ["open", "remediation", "closed"], default="open", errors=errors)
    if errors:
        raise ValidationError(errors)
    return clean


def validate_vendor(data: dict) -> dict:
    """Validate and clean vendor data. Raises ValidationError."""
    errors = []
    clean = {}
    clean["name"] = _str(data, "name", required=True, max_len=200, errors=errors)
    clean["service"] = _str(data, "service", max_len=200, errors=errors)
    clean["criticality"] = _int_range(data, "criticality", 1, 5, default=3, errors=errors)
    clean["contact"] = _str(data, "contact", max_len=200, errors=errors)
    clean["notes"] = _str(data, "notes", max_len=2000, errors=errors)
    if errors:
        raise ValidationError(errors)
    return clean


def paginate(query, page: int = 1, per_page: int = 50, max_per_page: int = 200):
    """Apply pagination to a Peewee query. Returns (items, meta)."""
    page = max(1, page)
    per_page = max(1, min(per_page, max_per_page))
    total = query.count()
    items = list(query.paginate(page, per_page))
    return items, {
        "page": page, "per_page": per_page,
        "total": total, "pages": (total + per_page - 1) // per_page,
    }


# ── Internal helpers ──

def _str(data, key, required=False, max_len=500, default="", errors=None):
    v = data.get(key, "")
    if not isinstance(v, str):
        v = str(v) if v else ""
    v = v.strip()[:max_len]
    # Remove control characters
    v = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', v)
    if required and not v:
        if errors is not None:
            errors.append(f"{key} is required")
    return v or default


def _int_range(data, key, min_v, max_v, default=None, errors=None):
    v = data.get(key, default)
    try:
        v = int(v)
        return max(min_v, min(max_v, v))
    except (TypeError, ValueError):
        return default if default is not None else min_v


def _enum(data, key, allowed, default=None, errors=None):
    v = data.get(key, default)
    if v in allowed:
        return v
    return default if default in allowed else allowed[0]
