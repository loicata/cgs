"""GRC (Governance, Risk, Compliance) routes Blueprint."""
from datetime import datetime
from flask import Blueprint, jsonify, request, session
from web.shared import ctx, config, auth, csrf_protect, audit

grc_bp = Blueprint("grc_bp", __name__)


# ══════════════════════════════════════════════════
# GRC — Risk Register
# ══════════════════════════════════════════════════

@grc_bp.route("/api/grc/risks")
@auth
def api_grc_risks():
    from core.database import Risk
    status = request.args.get("status")
    q = Risk.select().order_by(Risk.created_at.desc())
    if status:
        q = q.where(Risk.status == status)
    return jsonify([{
        "id": r.id, "title": r.title, "description": r.description or "",
        "category": r.category, "likelihood": r.likelihood, "impact": r.impact,
        "risk_score": r.risk_score, "owner": r.owner or "", "status": r.status,
        "treatment": r.treatment, "treatment_plan": r.treatment_plan or "",
        "review_date": r.review_date.isoformat() if r.review_date else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        "created_by": r.created_by or "",
    } for r in q])

@grc_bp.route("/api/grc/risks", methods=["POST"])
@auth
@csrf_protect
def api_grc_create_risk():
    from core.database import Risk
    data = request.get_json(force=True, silent=True) or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"e": "title required"}), 400
    likelihood = max(1, min(5, int(data.get("likelihood", 3))))
    impact = max(1, min(5, int(data.get("impact", 3))))
    risk_score = likelihood * impact
    r = Risk.create(
        title=title,
        description=data.get("description", ""),
        category=data.get("category", "operational"),
        likelihood=likelihood, impact=impact, risk_score=risk_score,
        owner=data.get("owner", ""),
        status=data.get("status", "open"),
        treatment=data.get("treatment", "mitigate"),
        treatment_plan=data.get("treatment_plan", ""),
        created_by=session.get("username"),
    )
    audit("GRC_CREATE_RISK", f"id={r.id} title={title}")
    return jsonify({"ok": True, "id": r.id})

@grc_bp.route("/api/grc/risks/<int:rid>", methods=["PUT"])
@auth
@csrf_protect
def api_grc_update_risk(rid):
    from core.database import Risk
    data = request.get_json(force=True, silent=True) or {}
    try:
        r = Risk.get_by_id(rid)
    except Risk.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    for f in ("title", "description", "category", "owner", "status", "treatment", "treatment_plan"):
        if f in data:
            setattr(r, f, data[f])
    if "likelihood" in data:
        r.likelihood = max(1, min(5, int(data["likelihood"])))
    if "impact" in data:
        r.impact = max(1, min(5, int(data["impact"])))
    if "likelihood" in data or "impact" in data:
        r.risk_score = r.likelihood * r.impact
    if "review_date" in data and data["review_date"]:
        r.review_date = datetime.fromisoformat(data["review_date"])
    r.updated_at = datetime.now()
    r.save()
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/risks/<int:rid>", methods=["DELETE"])
@auth
@csrf_protect
def api_grc_delete_risk(rid):
    from core.database import Risk
    try:
        r = Risk.get_by_id(rid)
    except Risk.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    title = r.title
    r.delete_instance()
    audit("GRC_DELETE_RISK", f"id={rid} title={title}")
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/risks/matrix")
@auth
def api_grc_risk_matrix():
    from core.grc import get_risk_matrix
    return jsonify(get_risk_matrix())


# ══════════════════════════════════════════════════
# GRC — Asset Register
# ══════════════════════════════════════════════════

@grc_bp.route("/api/grc/assets")
@auth
def api_grc_assets():
    from core.database import Asset
    q = Asset.select().order_by(Asset.created_at.desc())
    atype = request.args.get("type")
    if atype:
        q = q.where(Asset.asset_type == atype)
    return jsonify([{
        "id": a.id, "asset_type": a.asset_type, "name": a.name,
        "owner": a.owner or "", "criticality": a.criticality,
        "classification": a.classification, "location": a.location or "",
        "description": a.description or "", "dependencies": a.dependencies or "",
        "host_id": a.host_id,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        "created_by": a.created_by or "",
    } for a in q])

@grc_bp.route("/api/grc/assets", methods=["POST"])
@auth
@csrf_protect
def api_grc_create_asset():
    from core.database import Asset
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"e": "name required"}), 400
    a = Asset.create(
        name=name,
        asset_type=data.get("asset_type", "server"),
        owner=data.get("owner", ""),
        criticality=data.get("criticality", 3),
        classification=data.get("classification", "internal"),
        location=data.get("location", ""),
        description=data.get("description", ""),
        dependencies=data.get("dependencies", ""),
        host_id=data.get("host_id"),
        created_by=session.get("username"),
    )
    audit("GRC_CREATE_ASSET", f"id={a.id} name={name}")
    return jsonify({"ok": True, "id": a.id})

@grc_bp.route("/api/grc/assets/<int:aid>", methods=["PUT"])
@auth
@csrf_protect
def api_grc_update_asset(aid):
    from core.database import Asset
    data = request.get_json(force=True, silent=True) or {}
    try:
        a = Asset.get_by_id(aid)
    except Asset.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    for f in ("name", "asset_type", "owner", "classification", "location",
              "description", "dependencies"):
        if f in data:
            setattr(a, f, data[f])
    if "criticality" in data:
        a.criticality = int(data["criticality"])
    if "host_id" in data:
        a.host_id = data["host_id"]
    a.updated_at = datetime.now()
    a.save()
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/assets/<int:aid>", methods=["DELETE"])
@auth
@csrf_protect
def api_grc_delete_asset(aid):
    from core.database import Asset
    try:
        a = Asset.get_by_id(aid)
    except Asset.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    name = a.name
    a.delete_instance()
    audit("GRC_DELETE_ASSET", f"id={aid} name={name}")
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════
# GRC — Evidence
# ══════════════════════════════════════════════════

@grc_bp.route("/api/grc/evidence")
@auth
def api_grc_evidence():
    from core.database import Evidence
    q = Evidence.select().order_by(Evidence.uploaded_at.desc())
    control_id = request.args.get("control_id")
    if control_id:
        q = q.where(Evidence.control_id == control_id)
    return jsonify([{
        "id": e.id, "control_id": e.control_id, "filename": e.filename,
        "file_size": e.file_size, "mime_type": e.mime_type or "",
        "description": e.description or "", "uploaded_by": e.uploaded_by or "",
        "uploaded_at": e.uploaded_at.isoformat() if e.uploaded_at else None,
    } for e in q])

@grc_bp.route("/api/grc/evidence", methods=["POST"])
@auth
@csrf_protect
def api_grc_upload_evidence():
    from core.grc import save_evidence
    from web.shared import config as _config
    f = request.files.get("file")
    if not f:
        return jsonify({"e": "file required"}), 400
    control_id = request.form.get("control_id", "").strip()
    if not control_id:
        return jsonify({"e": "control_id required"}), 400
    description = request.form.get("description", "")
    cfg = (ctx.get("config") or _config)
    evidence_dir = cfg.get("grc.evidence_dir", "/opt/cgs/data/evidence") if cfg else "/opt/cgs/data/evidence"
    try:
        result = save_evidence(f, control_id, description, session.get("username", ""), evidence_dir)
        audit("GRC_UPLOAD_EVIDENCE", f"id={result.get('id')} control={control_id}")
        return jsonify({"ok": True, **result})
    except Exception as e:
        return jsonify({"e": str(e)}), 400

@grc_bp.route("/api/grc/evidence/<int:eid>/download")
@auth
def api_grc_download_evidence(eid):
    from flask import send_file
    from core.grc import get_evidence_path
    from web.shared import config as _config
    cfg = (ctx.get("config") or _config)
    evidence_dir = cfg.get("grc.evidence_dir", "/opt/cgs/data/evidence") if cfg else "/opt/cgs/data/evidence"
    try:
        filepath, original_name, mime_type = get_evidence_path(eid, evidence_dir)
        return send_file(filepath, as_attachment=True, download_name=original_name,
                         mimetype=mime_type or "application/octet-stream")
    except Exception as e:
        return jsonify({"e": str(e)}), 404

@grc_bp.route("/api/grc/evidence/<int:eid>", methods=["DELETE"])
@auth
@csrf_protect
def api_grc_delete_evidence(eid):
    from core.grc import delete_evidence
    from web.shared import config as _config
    cfg = (ctx.get("config") or _config)
    evidence_dir = cfg.get("grc.evidence_dir", "/opt/cgs/data/evidence") if cfg else "/opt/cgs/data/evidence"
    try:
        delete_evidence(eid, evidence_dir)
        audit("GRC_DELETE_EVIDENCE", f"id={eid}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"e": str(e)}), 404


# ══════════════════════════════════════════════════
# GRC — Compliance History
# ══════════════════════════════════════════════════

@grc_bp.route("/api/grc/compliance-history")
@auth
def api_grc_compliance_history():
    from core.grc import get_compliance_history
    months = int(request.args.get("months", 12))
    return jsonify(get_compliance_history(months))

@grc_bp.route("/api/grc/compliance-history/snapshot", methods=["POST"])
@auth
@csrf_protect
def api_grc_compliance_snapshot():
    from core.grc import capture_compliance_snapshot
    from web.shared import config as _config
    cfg = (ctx.get("config") or _config)
    try:
        result = capture_compliance_snapshot(cfg, ctx)
        audit("GRC_COMPLIANCE_SNAPSHOT", "manual snapshot")
        return jsonify({"ok": True, "snapshot": result})
    except Exception as e:
        return jsonify({"e": str(e)}), 500


# ══════════════════════════════════════════════════
# GRC — Policy Register
# ══════════════════════════════════════════════════

@grc_bp.route("/api/grc/policies")
@auth
def api_grc_policies():
    from core.database import Policy, PolicyAck
    policies = Policy.select().order_by(Policy.created_at.desc())
    out = []
    for p in policies:
        ack_count = PolicyAck.select().where(PolicyAck.policy_id == p.id).count()
        out.append({
            "id": p.id, "title": p.title, "content": p.content or "",
            "version": p.version, "status": p.status,
            "author": p.author or "", "approver": p.approver or "",
            "approved_date": p.approved_date.isoformat() if p.approved_date else None,
            "next_review_date": p.next_review_date.isoformat() if p.next_review_date else None,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
            "ack_count": ack_count,
        })
    return jsonify(out)

@grc_bp.route("/api/grc/policies", methods=["POST"])
@auth
@csrf_protect
def api_grc_create_policy():
    from core.database import Policy
    data = request.get_json(force=True, silent=True) or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"e": "title required"}), 400
    p = Policy.create(
        title=title,
        content=data.get("content", ""),
        version=data.get("version", "1.0"),
        status=data.get("status", "draft"),
        author=data.get("author", ""),
        approver=data.get("approver", ""),
    )
    audit("GRC_CREATE_POLICY", f"id={p.id} title={title}")
    return jsonify({"ok": True, "id": p.id})

@grc_bp.route("/api/grc/policies/<int:pid>", methods=["PUT"])
@auth
@csrf_protect
def api_grc_update_policy(pid):
    from core.database import Policy
    data = request.get_json(force=True, silent=True) or {}
    try:
        p = Policy.get_by_id(pid)
    except Policy.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    for f in ("title", "content", "version", "status", "author", "approver"):
        if f in data:
            setattr(p, f, data[f])
    if "approved_date" in data and data["approved_date"]:
        p.approved_date = datetime.fromisoformat(data["approved_date"])
    if "next_review_date" in data and data["next_review_date"]:
        p.next_review_date = datetime.fromisoformat(data["next_review_date"])
    p.updated_at = datetime.now()
    p.save()
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/policies/<int:pid>", methods=["DELETE"])
@auth
@csrf_protect
def api_grc_delete_policy(pid):
    from core.database import Policy, PolicyAck
    try:
        p = Policy.get_by_id(pid)
    except Policy.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    title = p.title
    PolicyAck.delete().where(PolicyAck.policy_id == pid).execute()
    p.delete_instance()
    audit("GRC_DELETE_POLICY", f"id={pid} title={title}")
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/policies/<int:pid>/ack", methods=["POST"])
@auth
@csrf_protect
def api_grc_ack_policy(pid):
    from core.database import Policy, PolicyAck
    try:
        Policy.get_by_id(pid)
    except Policy.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    username = session.get("username", "")
    try:
        PolicyAck.create(policy_id=pid, username=username)
    except Exception:
        return jsonify({"e": "already acknowledged"}), 409
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/policies/<int:pid>/acks")
@auth
def api_grc_policy_acks(pid):
    from core.database import PolicyAck
    acks = PolicyAck.select().where(PolicyAck.policy_id == pid).order_by(PolicyAck.acked_at.desc())
    return jsonify([{
        "id": a.id, "username": a.username,
        "acked_at": a.acked_at.isoformat() if a.acked_at else None,
    } for a in acks])


# ══════════════════════════════════════════════════
# GRC — Audit Management
# ══════════════════════════════════════════════════

@grc_bp.route("/api/grc/audits")
@auth
def api_grc_audits():
    from core.database import Audit
    return jsonify([{
        "id": a.id, "title": a.title, "scope": a.scope or "",
        "auditor": a.auditor or "", "status": a.status,
        "scheduled_date": a.scheduled_date.isoformat() if a.scheduled_date else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        "created_by": a.created_by or "",
    } for a in Audit.select().order_by(Audit.created_at.desc())])

@grc_bp.route("/api/grc/audits", methods=["POST"])
@auth
@csrf_protect
def api_grc_create_audit():
    from core.database import Audit
    data = request.get_json(force=True, silent=True) or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"e": "title required"}), 400
    a = Audit.create(
        title=title,
        scope=data.get("scope", ""),
        auditor=data.get("auditor", ""),
        status=data.get("status", "planned"),
        created_by=session.get("username"),
    )
    if data.get("scheduled_date"):
        a.scheduled_date = datetime.fromisoformat(data["scheduled_date"])
        a.save()
    audit("GRC_CREATE_AUDIT", f"id={a.id} title={title}")
    return jsonify({"ok": True, "id": a.id})

@grc_bp.route("/api/grc/audits/<int:aid>", methods=["PUT"])
@auth
@csrf_protect
def api_grc_update_audit(aid):
    from core.database import Audit
    data = request.get_json(force=True, silent=True) or {}
    try:
        a = Audit.get_by_id(aid)
    except Audit.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    for f in ("title", "scope", "auditor", "status"):
        if f in data:
            setattr(a, f, data[f])
    if "scheduled_date" in data and data["scheduled_date"]:
        a.scheduled_date = datetime.fromisoformat(data["scheduled_date"])
    a.updated_at = datetime.now()
    a.save()
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/audits/<int:aid>", methods=["DELETE"])
@auth
@csrf_protect
def api_grc_delete_audit(aid):
    from core.database import Audit, AuditFinding
    try:
        a = Audit.get_by_id(aid)
    except Audit.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    title = a.title
    AuditFinding.delete().where(AuditFinding.audit_id == aid).execute()
    a.delete_instance()
    audit("GRC_DELETE_AUDIT", f"id={aid} title={title}")
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/audits/<int:aid>/findings")
@auth
def api_grc_audit_findings(aid):
    from core.database import AuditFinding
    return jsonify([{
        "id": f.id, "audit_id": f.audit_id, "severity": f.severity,
        "description": f.description, "remediation_plan": f.remediation_plan or "",
        "responsible": f.responsible or "", "status": f.status,
        "due_date": f.due_date.isoformat() if f.due_date else None,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "updated_at": f.updated_at.isoformat() if f.updated_at else None,
    } for f in AuditFinding.select().where(AuditFinding.audit_id == aid)
         .order_by(AuditFinding.created_at.desc())])

@grc_bp.route("/api/grc/audits/<int:aid>/findings", methods=["POST"])
@auth
@csrf_protect
def api_grc_create_finding(aid):
    from core.database import Audit, AuditFinding
    try:
        Audit.get_by_id(aid)
    except Audit.DoesNotExist:
        return jsonify({"e": "audit not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    description = data.get("description", "").strip()
    if not description:
        return jsonify({"e": "description required"}), 400
    f = AuditFinding.create(
        audit_id=aid,
        severity=data.get("severity", "medium"),
        description=description,
        remediation_plan=data.get("remediation_plan", ""),
        responsible=data.get("responsible", ""),
        status=data.get("status", "open"),
    )
    if data.get("due_date"):
        f.due_date = datetime.fromisoformat(data["due_date"])
        f.save()
    audit("GRC_CREATE_FINDING", f"id={f.id} audit_id={aid}")
    return jsonify({"ok": True, "id": f.id})

@grc_bp.route("/api/grc/findings/<int:fid>", methods=["PUT"])
@auth
@csrf_protect
def api_grc_update_finding(fid):
    from core.database import AuditFinding
    data = request.get_json(force=True, silent=True) or {}
    try:
        f = AuditFinding.get_by_id(fid)
    except AuditFinding.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    for field in ("severity", "description", "remediation_plan", "responsible", "status"):
        if field in data:
            setattr(f, field, data[field])
    if "due_date" in data and data["due_date"]:
        f.due_date = datetime.fromisoformat(data["due_date"])
    f.updated_at = datetime.now()
    f.save()
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/findings/<int:fid>", methods=["DELETE"])
@auth
@csrf_protect
def api_grc_delete_finding(fid):
    from core.database import AuditFinding
    try:
        f = AuditFinding.get_by_id(fid)
    except AuditFinding.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    f.delete_instance()
    audit("GRC_DELETE_FINDING", f"id={fid}")
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════
# GRC — Risk-Control Mapping
# ══════════════════════════════════════════════════

@grc_bp.route("/api/grc/risk-control-map")
@auth
def api_grc_risk_control_map():
    from core.database import RiskControlMap
    q = RiskControlMap.select().order_by(RiskControlMap.created_at.desc())
    risk_id = request.args.get("risk_id")
    control_id = request.args.get("control_id")
    if risk_id:
        q = q.where(RiskControlMap.risk_id == int(risk_id))
    if control_id:
        q = q.where(RiskControlMap.control_id == control_id)
    return jsonify([{
        "id": m.id, "risk_id": m.risk_id, "control_id": m.control_id,
        "notes": m.notes or "",
        "created_at": m.created_at.isoformat() if m.created_at else None,
    } for m in q])

@grc_bp.route("/api/grc/risk-control-map", methods=["POST"])
@auth
@csrf_protect
def api_grc_create_risk_control_map():
    from core.database import RiskControlMap
    data = request.get_json(force=True, silent=True) or {}
    risk_id = data.get("risk_id")
    control_id = data.get("control_id", "").strip()
    if not risk_id or not control_id:
        return jsonify({"e": "risk_id and control_id required"}), 400
    try:
        m = RiskControlMap.create(
            risk_id=int(risk_id), control_id=control_id,
            notes=data.get("notes", ""),
        )
        audit("GRC_CREATE_RISK_CONTROL_MAP", f"id={m.id} risk={risk_id} control={control_id}")
        return jsonify({"ok": True, "id": m.id})
    except Exception as e:
        return jsonify({"e": str(e)}), 400

@grc_bp.route("/api/grc/risk-control-map/<int:mid>", methods=["DELETE"])
@auth
@csrf_protect
def api_grc_delete_risk_control_map(mid):
    from core.database import RiskControlMap
    try:
        m = RiskControlMap.get_by_id(mid)
    except RiskControlMap.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    m.delete_instance()
    audit("GRC_DELETE_RISK_CONTROL_MAP", f"id={mid}")
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/risk-exposure")
@auth
def api_grc_risk_exposure():
    from core.grc import get_risk_exposure
    comp = ctx.get("compliance")
    controls = comp.run_assessment() if comp else []
    return jsonify(get_risk_exposure(controls))


# ══════════════════════════════════════════════════
# GRC — Third-Party / Vendors
# ══════════════════════════════════════════════════

@grc_bp.route("/api/grc/vendors")
@auth
def api_grc_vendors():
    from core.database import Vendor
    from core.grc import compute_vendor_score
    out = []
    for v in Vendor.select().order_by(Vendor.created_at.desc()):
        score_info = compute_vendor_score(v.id)
        out.append({
            "id": v.id, "name": v.name, "service": v.service or "",
            "criticality": v.criticality, "risk_level": v.risk_level,
            "contact": v.contact or "", "notes": v.notes or "",
            "last_assessed": v.last_assessed.isoformat() if v.last_assessed else None,
            "created_at": v.created_at.isoformat() if v.created_at else None,
            "updated_at": v.updated_at.isoformat() if v.updated_at else None,
            "created_by": v.created_by or "",
            "score": score_info,
        })
    return jsonify(out)

@grc_bp.route("/api/grc/vendors", methods=["POST"])
@auth
@csrf_protect
def api_grc_create_vendor():
    from core.grc import create_vendor_with_questions
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"e": "name required"}), 400
    try:
        vid = create_vendor_with_questions(data, session.get("username", ""))
        audit("GRC_CREATE_VENDOR", f"id={vid} name={name}")
        return jsonify({"ok": True, "id": vid})
    except Exception as e:
        return jsonify({"e": str(e)}), 400

@grc_bp.route("/api/grc/vendors/<int:vid>", methods=["PUT"])
@auth
@csrf_protect
def api_grc_update_vendor(vid):
    from core.database import Vendor
    data = request.get_json(force=True, silent=True) or {}
    try:
        v = Vendor.get_by_id(vid)
    except Vendor.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    for f in ("name", "service", "risk_level", "contact", "notes"):
        if f in data:
            setattr(v, f, data[f])
    if "criticality" in data:
        v.criticality = int(data["criticality"])
    if "last_assessed" in data and data["last_assessed"]:
        v.last_assessed = datetime.fromisoformat(data["last_assessed"])
    v.updated_at = datetime.now()
    v.save()
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/vendors/<int:vid>", methods=["DELETE"])
@auth
@csrf_protect
def api_grc_delete_vendor(vid):
    from core.database import Vendor, VendorQuestion
    try:
        v = Vendor.get_by_id(vid)
    except Vendor.DoesNotExist:
        return jsonify({"e": "not found"}), 404
    name = v.name
    VendorQuestion.delete().where(VendorQuestion.vendor_id == vid).execute()
    v.delete_instance()
    audit("GRC_DELETE_VENDOR", f"id={vid} name={name}")
    return jsonify({"ok": True})

@grc_bp.route("/api/grc/vendors/<int:vid>/questionnaire")
@auth
def api_grc_vendor_questionnaire(vid):
    from core.database import VendorQuestion
    return jsonify([{
        "id": q.id, "vendor_id": q.vendor_id, "question": q.question,
        "answer": q.answer, "notes": q.notes or "",
        "updated_at": q.updated_at.isoformat() if q.updated_at else None,
    } for q in VendorQuestion.select().where(VendorQuestion.vendor_id == vid)
         .order_by(VendorQuestion.id)])

@grc_bp.route("/api/grc/vendors/<int:vid>/questionnaire", methods=["PUT"])
@auth
@csrf_protect
def api_grc_update_vendor_questionnaire(vid):
    from core.database import VendorQuestion, Vendor
    data = request.get_json(force=True, silent=True) or {}
    answers = data.get("answers", [])
    for item in answers:
        try:
            q = VendorQuestion.get_by_id(int(item["id"]))
            if q.vendor_id != vid:
                continue
            if "answer" in item:
                q.answer = item["answer"]
            if "notes" in item:
                q.notes = item["notes"]
            q.updated_at = datetime.now()
            q.save()
        except (VendorQuestion.DoesNotExist, KeyError):
            continue
    try:
        v = Vendor.get_by_id(vid)
        v.last_assessed = datetime.now()
        v.updated_at = datetime.now()
        v.save()
    except Vendor.DoesNotExist:
        pass
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════
# GRC — Summary
# ══════════════════════════════════════════════════

@grc_bp.route("/api/grc/summary")
@auth
def api_grc_summary():
    from core.grc import get_grc_summary
    return jsonify(get_grc_summary())


# ══════════════════════════════════════════════════
# CSV Export
# ══════════════════════════════════════════════════

@grc_bp.route("/api/grc/risks/csv")
@auth
def api_grc_risks_csv():
    import csv, io
    from flask import send_file
    from core.database import Risk
    buf = io.BytesIO()
    wrapper = io.TextIOWrapper(buf, encoding="utf-8", newline="")
    w = csv.writer(wrapper)
    w.writerow(["id","title","description","category","likelihood","impact","risk_score",
                "owner","status","treatment","treatment_plan","review_date","created_at","created_by"])
    for r in Risk.select().order_by(Risk.created_at.desc()):
        w.writerow([r.id, r.title, r.description or "", r.category, r.likelihood, r.impact,
                    r.risk_score, r.owner or "", r.status, r.treatment,
                    r.treatment_plan or "",
                    r.review_date.isoformat() if r.review_date else "",
                    r.created_at.isoformat() if r.created_at else "",
                    r.created_by or ""])
    wrapper.flush(); wrapper.detach(); buf.seek(0)
    return send_file(buf, mimetype="text/csv", as_attachment=True,
                     download_name=f"cgs_risks_{datetime.now().strftime('%Y%m%d')}.csv")

@grc_bp.route("/api/grc/assets/csv")
@auth
def api_grc_assets_csv():
    import csv, io
    from flask import send_file
    from core.database import Asset
    buf = io.BytesIO()
    wrapper = io.TextIOWrapper(buf, encoding="utf-8", newline="")
    w = csv.writer(wrapper)
    w.writerow(["id","name","asset_type","owner","criticality","classification",
                "location","description","dependencies","host_id","created_at","created_by"])
    for a in Asset.select().order_by(Asset.created_at.desc()):
        w.writerow([a.id, a.name, a.asset_type, a.owner or "", a.criticality,
                    a.classification, a.location or "", a.description or "",
                    a.dependencies or "", a.host_id or "",
                    a.created_at.isoformat() if a.created_at else "",
                    a.created_by or ""])
    wrapper.flush(); wrapper.detach(); buf.seek(0)
    return send_file(buf, mimetype="text/csv", as_attachment=True,
                     download_name=f"cgs_assets_{datetime.now().strftime('%Y%m%d')}.csv")

@grc_bp.route("/api/grc/vendors/csv")
@auth
def api_grc_vendors_csv():
    import csv, io
    from flask import send_file
    from core.database import Vendor
    buf = io.BytesIO()
    wrapper = io.TextIOWrapper(buf, encoding="utf-8", newline="")
    w = csv.writer(wrapper)
    w.writerow(["id","name","service","criticality","risk_level","contact","notes",
                "last_assessed","created_at","created_by"])
    for v in Vendor.select().order_by(Vendor.created_at.desc()):
        w.writerow([v.id, v.name, v.service or "", v.criticality, v.risk_level,
                    v.contact or "", v.notes or "",
                    v.last_assessed.isoformat() if v.last_assessed else "",
                    v.created_at.isoformat() if v.created_at else "",
                    v.created_by or ""])
    wrapper.flush(); wrapper.detach(); buf.seek(0)
    return send_file(buf, mimetype="text/csv", as_attachment=True,
                     download_name=f"cgs_vendors_{datetime.now().strftime('%Y%m%d')}.csv")


# ══════════════════════════════════════════════════
# CSV Import
# ══════════════════════════════════════════════════

@grc_bp.route("/api/grc/risks/import", methods=["POST"])
@auth
@csrf_protect
def api_grc_risks_import():
    import csv, io
    from core.database import Risk
    f = request.files.get("file")
    if not f:
        return jsonify({"e": "no file"}), 400
    imported, skipped, errors = 0, 0, []
    try:
        text = io.TextIOWrapper(f.stream, encoding="utf-8")
        reader = csv.DictReader(text)
        for i, row in enumerate(reader, 1):
            title = (row.get("title") or "").strip()
            if not title:
                skipped += 1
                errors.append(f"Row {i}: missing title")
                continue
            try:
                likelihood = max(1, min(5, int(row.get("likelihood", 3))))
                impact = max(1, min(5, int(row.get("impact", 3))))
                Risk.create(
                    title=title,
                    description=row.get("description", ""),
                    category=row.get("category", "operational"),
                    likelihood=likelihood, impact=impact,
                    risk_score=likelihood * impact,
                    owner=row.get("owner", ""),
                    status=row.get("status", "open"),
                    treatment=row.get("treatment", "mitigate"),
                    treatment_plan=row.get("treatment_plan", ""),
                    created_by=session.get("username"),
                )
                imported += 1
            except Exception as ex:
                skipped += 1
                errors.append(f"Row {i}: {ex}")
    except Exception as ex:
        return jsonify({"e": str(ex)}), 400
    audit("GRC_IMPORT_RISKS", f"imported={imported} skipped={skipped}")
    return jsonify({"ok": True, "imported": imported, "skipped": skipped, "errors": errors[:20]})

@grc_bp.route("/api/grc/assets/import", methods=["POST"])
@auth
@csrf_protect
def api_grc_assets_import():
    import csv, io
    from core.database import Asset
    f = request.files.get("file")
    if not f:
        return jsonify({"e": "no file"}), 400
    imported, skipped, errors = 0, 0, []
    try:
        text = io.TextIOWrapper(f.stream, encoding="utf-8")
        reader = csv.DictReader(text)
        for i, row in enumerate(reader, 1):
            name = (row.get("name") or "").strip()
            if not name:
                skipped += 1
                errors.append(f"Row {i}: missing name")
                continue
            try:
                Asset.create(
                    name=name,
                    asset_type=row.get("asset_type", "server"),
                    owner=row.get("owner", ""),
                    criticality=int(row.get("criticality", 3)),
                    classification=row.get("classification", "internal"),
                    location=row.get("location", ""),
                    description=row.get("description", ""),
                    dependencies=row.get("dependencies", ""),
                    host_id=row.get("host_id") or None,
                    created_by=session.get("username"),
                )
                imported += 1
            except Exception as ex:
                skipped += 1
                errors.append(f"Row {i}: {ex}")
    except Exception as ex:
        return jsonify({"e": str(ex)}), 400
    audit("GRC_IMPORT_ASSETS", f"imported={imported} skipped={skipped}")
    return jsonify({"ok": True, "imported": imported, "skipped": skipped, "errors": errors[:20]})

@grc_bp.route("/api/grc/vendors/import", methods=["POST"])
@auth
@csrf_protect
def api_grc_vendors_import():
    import csv, io
    from core.database import Vendor
    f = request.files.get("file")
    if not f:
        return jsonify({"e": "no file"}), 400
    imported, skipped, errors = 0, 0, []
    try:
        text = io.TextIOWrapper(f.stream, encoding="utf-8")
        reader = csv.DictReader(text)
        for i, row in enumerate(reader, 1):
            name = (row.get("name") or "").strip()
            if not name:
                skipped += 1
                errors.append(f"Row {i}: missing name")
                continue
            try:
                Vendor.create(
                    name=name,
                    service=row.get("service", ""),
                    criticality=int(row.get("criticality", 3)),
                    risk_level=row.get("risk_level", "medium"),
                    contact=row.get("contact", ""),
                    notes=row.get("notes", ""),
                    created_by=session.get("username"),
                )
                imported += 1
            except Exception as ex:
                skipped += 1
                errors.append(f"Row {i}: {ex}")
    except Exception as ex:
        return jsonify({"e": str(ex)}), 400
    audit("GRC_IMPORT_VENDORS", f"imported={imported} skipped={skipped}")
    return jsonify({"ok": True, "imported": imported, "skipped": skipped, "errors": errors[:20]})
