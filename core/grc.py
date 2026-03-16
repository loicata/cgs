"""
CGS — GRC business logic.

Handles: compliance snapshots, risk matrix, evidence files,
vendor risk scoring, risk-control exposure analysis.
"""

import json
import logging
import mimetypes
import os
import uuid
from datetime import datetime, timedelta

logger = logging.getLogger("cgs.grc")

ALLOWED_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".doc", ".docx",
               ".xlsx", ".xls", ".txt", ".csv", ".pptx", ".odt", ".ods"}
MAX_EVIDENCE_SIZE = 10 * 1024 * 1024  # 10 MB

DEFAULT_VENDOR_QUESTIONS = [
    "Does the vendor have an information security policy?",
    "Does the vendor encrypt data in transit and at rest?",
    "Does the vendor perform regular security assessments?",
    "Does the vendor have incident response procedures?",
    "Does the vendor comply with relevant data protection regulations?",
    "Does the vendor perform background checks on employees?",
    "Does the vendor have business continuity/disaster recovery plans?",
    "Does the vendor provide security audit reports (SOC 2, ISO 27001)?",
    "Does the vendor have access control policies?",
    "Does the vendor monitor for security threats?",
]


# ══════════════════════════════════════════════════
# Compliance history snapshot
# ══════════════════════════════════════════════════

def capture_compliance_snapshot(config, modules):
    """Run compliance assessment and store a snapshot. Called daily by daemon."""
    try:
        from core.compliance import ComplianceAssessor
        from core.database import ComplianceSnapshot, db

        assessor = ComplianceAssessor(config, modules)
        result = assessor.assess()

        # Build per-category summary
        cat_summary = {}
        for cat_name, cat_data in result.get("categories", {}).items():
            total = cat_data["total"]
            passed = cat_data["pass"]
            cat_summary[cat_name] = {
                "pass": passed, "fail": cat_data["fail"],
                "score": round(passed / max(total, 1) * 100),
            }

        with db.atomic():
            ComplianceSnapshot.create(
                score=result["score"],
                auto_score=result.get("auto_score", 0),
                decl_score=result.get("declarative_score"),
                risk_level=result["risk_level"],
                passed=result["passed"],
                failed=result["failed"],
                unanswered=result.get("unanswered", 0),
                categories_json=json.dumps(cat_summary),
            )
        logger.info("Compliance snapshot: score=%d/%d passed", result["score"], result["passed"])
    except Exception as e:
        logger.error("Compliance snapshot failed: %s", e)


def get_compliance_history(months: int = 12) -> dict:
    """Get compliance trend data for the last N months."""
    from core.database import ComplianceSnapshot
    cutoff = datetime.now() - timedelta(days=months * 30)
    snapshots = list(ComplianceSnapshot.select()
                     .where(ComplianceSnapshot.ts >= cutoff)
                     .order_by(ComplianceSnapshot.ts))

    history = []
    for s in snapshots:
        cats = {}
        try:
            cats = json.loads(s.categories_json) if s.categories_json else {}
        except Exception as e:
            logger.debug("Failed to parse compliance snapshot categories: %s", e)
        history.append({
            "ts": s.ts.isoformat(),
            "score": s.score,
            "auto_score": s.auto_score,
            "decl_score": s.decl_score,
            "risk_level": s.risk_level,
            "passed": s.passed,
            "failed": s.failed,
            "unanswered": s.unanswered,
            "categories": cats,
        })

    # Compute deltas
    current = history[-1]["score"] if history else 0
    deltas = {}
    for label, days in [("m1", 30), ("m3", 90), ("m6", 180), ("m12", 365)]:
        target = datetime.now() - timedelta(days=days)
        closest = None
        for s in snapshots:
            if s.ts <= target:
                closest = s
        deltas[label] = current - closest.score if closest else None

    return {"snapshots": history, "deltas": deltas, "current": current}


# ══════════════════════════════════════════════════
# Risk matrix
# ══════════════════════════════════════════════════

def get_risk_matrix() -> dict:
    """Returns 5x5 risk matrix with counts and risk details."""
    from core.database import Risk
    matrix = [[0]*5 for _ in range(5)]  # [likelihood][impact]
    risks_by_cell = {}

    for r in Risk.select().where(Risk.status != "closed"):
        li = max(0, min(4, r.likelihood - 1))
        im = max(0, min(4, r.impact - 1))
        matrix[li][im] += 1
        key = f"{li},{im}"
        if key not in risks_by_cell:
            risks_by_cell[key] = []
        risks_by_cell[key].append({"id": r.id, "title": r.title, "score": r.risk_score})

    return {"matrix": matrix, "details": risks_by_cell}


# ══════════════════════════════════════════════════
# Risk-control exposure
# ══════════════════════════════════════════════════

def get_risk_exposure(assessment_controls: list) -> list:
    """Find risks exposed by failing controls."""
    from core.database import Risk, RiskControlMap

    # Get all failing control IDs
    failing = {c["id"] for c in assessment_controls if c.get("status") != "PASS"}
    if not failing:
        return []

    # Find risk-control mappings for failing controls
    exposed = {}
    for m in RiskControlMap.select():
        if m.control_id in failing:
            if m.risk_id not in exposed:
                try:
                    r = Risk.get_by_id(m.risk_id)
                    exposed[m.risk_id] = {
                        "risk_id": r.id, "title": r.title,
                        "risk_score": r.risk_score, "status": r.status,
                        "failing_controls": [],
                    }
                except Exception as e:
                    logger.debug("Failed to load risk %s: %s", m.risk_id, e)
                    continue
            exposed[m.risk_id]["failing_controls"].append(m.control_id)

    return sorted(exposed.values(), key=lambda x: -x["risk_score"])


# ══════════════════════════════════════════════════
# Evidence file management
# ══════════════════════════════════════════════════

def save_evidence(file_obj, control_id: str, description: str,
                  username: str, evidence_dir: str) -> dict:
    """Save uploaded evidence file. Returns Evidence record as dict."""
    from core.database import Evidence

    filename = file_obj.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXT:
        raise ValueError(f"File type {ext} not allowed")

    # Read and check size
    data = file_obj.read()
    if len(data) > MAX_EVIDENCE_SIZE:
        raise ValueError(f"File too large ({len(data)} bytes, max {MAX_EVIDENCE_SIZE})")

    # Validate magic bytes match claimed extension
    MAGIC_BYTES = {
        ".pdf": [b"%PDF"],
        ".png": [b"\x89PNG"],
        ".jpg": [b"\xff\xd8\xff"],
        ".jpeg": [b"\xff\xd8\xff"],
        ".gif": [b"GIF87a", b"GIF89a"],
        ".doc": [b"\xd0\xcf\x11\xe0"],  # OLE2
        ".docx": [b"PK\x03\x04"],  # ZIP-based
        ".xlsx": [b"PK\x03\x04"],
        ".xls": [b"\xd0\xcf\x11\xe0"],
        ".pptx": [b"PK\x03\x04"],
        ".odt": [b"PK\x03\x04"],
        ".ods": [b"PK\x03\x04"],
        ".txt": [],  # any content ok
        ".csv": [],  # any content ok
    }

    if ext in MAGIC_BYTES and MAGIC_BYTES[ext]:
        valid = any(data.startswith(magic) for magic in MAGIC_BYTES[ext])
        if not valid:
            raise ValueError(f"File content does not match extension {ext}")

    # Store with UUID name
    stored_name = f"{uuid.uuid4().hex}{ext}"
    os.makedirs(evidence_dir, exist_ok=True)
    filepath = os.path.join(evidence_dir, stored_name)
    with open(filepath, "wb") as f:
        f.write(data)

    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    ev = Evidence.create(
        control_id=control_id, filename=filename,
        stored_name=stored_name, file_size=len(data),
        mime_type=mime, description=description,
        uploaded_by=username)

    return {"id": ev.id, "filename": filename, "size": len(data), "control_id": control_id}


def get_evidence_path(evidence_id: int, evidence_dir: str) -> tuple:
    """Returns (filepath, original_filename, mime_type) or raises."""
    from core.database import Evidence
    ev = Evidence.get_by_id(evidence_id)
    filepath = os.path.join(evidence_dir, ev.stored_name)
    # Path traversal protection
    real = os.path.realpath(filepath)
    if not real.startswith(os.path.realpath(evidence_dir)):
        raise ValueError("Invalid path")
    if not os.path.exists(filepath):
        raise FileNotFoundError("File not found on disk")
    return filepath, ev.filename, ev.mime_type


def delete_evidence(evidence_id: int, evidence_dir: str):
    """Delete evidence record and file."""
    from core.database import Evidence, db
    ev = Evidence.get_by_id(evidence_id)
    filepath = os.path.join(evidence_dir, ev.stored_name)
    with db.atomic():
        ev.delete_instance()
        if os.path.exists(filepath):
            os.remove(filepath)


# ══════════════════════════════════════════════════
# Vendor risk scoring
# ══════════════════════════════════════════════════

def compute_vendor_score(vendor_id: int) -> dict:
    """Compute vendor risk score from questionnaire answers."""
    from core.database import VendorQuestion
    questions = list(VendorQuestion.select().where(VendorQuestion.vendor_id == vendor_id))
    if not questions:
        return {"score": 0, "grade": "N/A", "answered": 0, "total": 0}

    total = len(questions)
    score_map = {"yes": 100, "partial": 50, "no": 0, "unanswered": 0}
    points = sum(score_map.get(q.answer, 0) for q in questions)
    answered = sum(1 for q in questions if q.answer != "unanswered")
    avg = round(points / max(total, 1))

    if avg >= 80:
        grade = "A"
    elif avg >= 60:
        grade = "B"
    elif avg >= 40:
        grade = "C"
    elif avg >= 20:
        grade = "D"
    else:
        grade = "F"

    risk_level = "low" if avg >= 80 else "medium" if avg >= 50 else "high" if avg >= 20 else "critical"
    return {"score": avg, "grade": grade, "risk_level": risk_level,
            "answered": answered, "total": total}


def create_vendor_with_questions(vendor_data: dict, username: str) -> int:
    """Create vendor and populate default questionnaire. Returns vendor ID."""
    from core.database import Vendor, VendorQuestion, db
    with db.atomic():
        v = Vendor.create(
            name=vendor_data.get("name", ""),
            service=vendor_data.get("service", ""),
            criticality=max(1, min(5, int(vendor_data.get("criticality", 3)))),
            contact=vendor_data.get("contact", ""),
            notes=vendor_data.get("notes", ""),
            created_by=username)

        for q in DEFAULT_VENDOR_QUESTIONS:
            VendorQuestion.create(vendor_id=v.id, question=q)

    return v.id


# ══════════════════════════════════════════════════
# GRC summary (for PDF/DOCX export)
# ══════════════════════════════════════════════════

def get_grc_summary() -> dict:
    """Get summary stats from all GRC modules for report export."""
    from core.database import (Risk, Asset, Evidence, ComplianceSnapshot,
                               Policy, Audit, AuditFinding, Vendor)
    summary = {}
    try:
        # Risks
        risks = list(Risk.select())
        summary["risks"] = {
            "total": len(risks),
            "open": sum(1 for r in risks if r.status == "open"),
            "critical": sum(1 for r in risks if r.risk_score >= 15),
            "top5": [{"title": r.title, "score": r.risk_score, "status": r.status}
                     for r in sorted(risks, key=lambda x: -x.risk_score)[:5]],
        }
        # Assets
        assets = list(Asset.select())
        summary["assets"] = {
            "total": len(assets),
            "by_type": {},
            "by_criticality": {i: 0 for i in range(1, 6)},
        }
        for a in assets:
            summary["assets"]["by_type"][a.asset_type] = summary["assets"]["by_type"].get(a.asset_type, 0) + 1
            summary["assets"]["by_criticality"][a.criticality] = summary["assets"]["by_criticality"].get(a.criticality, 0) + 1
        # Compliance trend
        history = get_compliance_history(6)
        summary["compliance_trend"] = history["deltas"]
        summary["compliance_current"] = history["current"]
        # Audits
        findings = list(AuditFinding.select().where(AuditFinding.status != "closed"))
        summary["audit_findings_open"] = len(findings)
        # Vendors
        vendors = list(Vendor.select())
        summary["vendors"] = {
            "total": len(vendors),
            "high_risk": sum(1 for v in vendors if v.risk_level in ("high", "critical")),
        }
        # Policies
        policies = list(Policy.select())
        summary["policies"] = {
            "total": len(policies),
            "approved": sum(1 for p in policies if p.status == "approved"),
            "draft": sum(1 for p in policies if p.status == "draft"),
        }
    except Exception as e:
        summary["error"] = str(e)

    return summary
