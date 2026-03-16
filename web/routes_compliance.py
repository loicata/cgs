"""Compliance report routes Blueprint."""
import logging
from datetime import datetime
from flask import Blueprint, jsonify, request, session
from core.database import WebUser
from web.shared import ctx, config, auth, csrf_protect, audit

logger = logging.getLogger("cgs.web.compliance")

compliance_bp = Blueprint("compliance_bp", __name__)


def _get_company():
    """Get company name from current user."""
    try:
        u = WebUser.get_by_id(session.get("user_id"))
        return u.company or ""
    except Exception:
        return ""


@compliance_bp.route("/api/compliance")
@auth
def api_compliance():
    """Run compliance assessment. ?frameworks=nis2,iso27001,... to filter."""
    from core.compliance import ComplianceAssessor, ALL_FRAMEWORK_IDS
    from web.shared import config as _config
    cfg = ctx.get("config") or _config
    assessor = ComplianceAssessor(cfg, ctx)
    fw_param = request.args.get("frameworks", "")
    frameworks = [f.strip() for f in fw_param.split(",") if f.strip()] if fw_param else None
    result = assessor.assess(frameworks=frameworks)
    result["company"] = _get_company()
    return jsonify(result)

@compliance_bp.route("/api/compliance/answers", methods=["POST"])
@auth
@csrf_protect
def api_compliance_answer():
    """Save a declarative control answer. Any authenticated user can answer."""
    from core.database import ComplianceAnswer
    data = request.get_json(force=True, silent=True) or {}
    control_id = data.get("control_id", "").strip()
    answer = data.get("answer", "").strip()
    detail = data.get("detail", "").strip()

    if not control_id:
        return jsonify({"e": "control_id required"}), 400
    if answer not in ("yes", "no", "partial", "unanswered"):
        return jsonify({"e": "answer must be yes, no, partial, or unanswered"}), 400

    username = session.get("username", "unknown")

    try:
        obj, created = ComplianceAnswer.get_or_create(
            control_id=control_id,
            defaults={"answer": answer, "detail": detail, "answered_by": username})
        if not created:
            obj.answer = answer
            obj.detail = detail
            obj.answered_by = username
            obj.updated_at = datetime.now()
            obj.save()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"e": str(e)}), 500

@compliance_bp.route("/api/compliance/pdf")
@auth
def api_compliance_pdf():
    """Generate and download compliance PDF."""
    from core.compliance import ComplianceAssessor, generate_compliance_pdf
    from flask import send_file
    from web.shared import config as _config
    cfg = ctx.get("config") or _config
    assessor = ComplianceAssessor(cfg, ctx)
    assessment = assessor.assess()
    company = _get_company()
    fw_param = request.args.get("frameworks", "")
    frameworks = [f.strip() for f in fw_param.split(",") if f.strip()] if fw_param else None
    assessment = assessor.assess(frameworks=frameworks)
    assessment["company"] = company
    try:
        from core.grc import get_grc_summary
        assessment["grc"] = get_grc_summary()
    except Exception as e:
        logger.debug("Failed to get GRC summary: %s", e)
    pdf_bytes = generate_compliance_pdf(assessment, config=cfg, company=company)
    buf = __import__("io").BytesIO(pdf_bytes)
    filename = f"CGS_Compliance_{company.replace(' ','_')+'_' if company else ''}{datetime.now().strftime('%Y%m%d')}.pdf"
    return send_file(buf, mimetype="application/pdf",
                     as_attachment=True, download_name=filename)

@compliance_bp.route("/api/compliance/docx")
@auth
def api_compliance_docx():
    """Generate and download compliance DOCX (editable)."""
    from core.compliance import ComplianceAssessor, generate_compliance_docx
    from flask import send_file
    from web.shared import config as _config
    cfg = ctx.get("config") or _config
    assessor = ComplianceAssessor(cfg, ctx)
    fw_param = request.args.get("frameworks", "")
    frameworks = [f.strip() for f in fw_param.split(",") if f.strip()] if fw_param else None
    assessment = assessor.assess(frameworks=frameworks)
    company = _get_company()
    assessment["company"] = company
    try:
        from core.grc import get_grc_summary
        assessment["grc"] = get_grc_summary()
    except Exception as e:
        logger.debug("Failed to get GRC summary: %s", e)
    docx_bytes = generate_compliance_docx(assessment, config=cfg, company=company)
    buf = __import__("io").BytesIO(docx_bytes)
    filename = f"CGS_Compliance_{company.replace(' ','_')+'_' if company else ''}{datetime.now().strftime('%Y%m%d')}.docx"
    return send_file(buf, mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                     as_attachment=True, download_name=filename)

@compliance_bp.route("/api/compliance/email", methods=["POST"])
@auth
@csrf_protect
def api_compliance_email():
    """Generate PDF and send by email."""
    from core.compliance import ComplianceAssessor, generate_compliance_pdf
    from web.shared import config as _config
    cfg = ctx.get("config") or _config

    if not cfg.get("email.enabled"):
        return jsonify({"ok": False, "error": "Email not configured"})

    data = request.get_json(force=True, silent=True) or {}
    to = data.get("to", "")
    if not to:
        return jsonify({"ok": False, "error": "No recipient specified"})

    assessor = ComplianceAssessor(cfg, ctx)
    fw_param = request.args.get("frameworks", "")
    frameworks = [f.strip() for f in fw_param.split(",") if f.strip()] if fw_param else None
    assessment = assessor.assess(frameworks=frameworks)
    company = _get_company()
    assessment["company"] = company
    try:
        from core.grc import get_grc_summary
        assessment["grc"] = get_grc_summary()
    except Exception as e:
        logger.debug("Failed to get GRC summary: %s", e)
    pdf_bytes = generate_compliance_pdf(assessment, config=cfg, company=company)
    from core.compliance import generate_compliance_docx
    docx_bytes = generate_compliance_docx(assessment, config=cfg, company=company)

    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.application import MIMEApplication

        subj_company = f" — {company}" if company else ""
        msg = MIMEMultipart()
        msg["Subject"] = f"[CGS] Compliance Report{subj_company} — Score: {assessment['score']}/100"
        msg["From"] = cfg.get("email.from_address", "sentinel@local")
        msg["To"] = to

        datestamp = datetime.now().strftime('%Y%m%d')
        body = (f"CGS Compliance Report\n\n"
                f"Score: {assessment['score']}/100\n"
                f"Risk Level: {assessment['risk_level']}\n"
                f"Controls: {assessment['passed']}/{assessment['total_controls']} passed\n\n"
                f"Attached:\n"
                f"  - PDF version (print-ready)\n"
                f"  - DOCX version (editable)\n")
        msg.attach(MIMEText(body, "plain", "utf-8"))

        MAX_EMAIL = 10 * 1024 * 1024  # 10 MB

        pdf_part = MIMEApplication(pdf_bytes, _subtype="pdf")
        pdf_part.add_header("Content-Disposition", "attachment",
                           filename=f"CGS_Compliance_{datestamp}.pdf")
        docx_part = MIMEApplication(docx_bytes,
            _subtype="vnd.openxmlformats-officedocument.wordprocessingml.document")
        docx_part.add_header("Content-Disposition", "attachment",
                            filename=f"CGS_Compliance_{datestamp}.docx")

        # Check combined size
        msg.attach(pdf_part)
        msg.attach(docx_part)
        combined_size = len(msg.as_bytes())

        def _smtp_send(message):
            port = cfg.get("email.smtp_port", 587)
            if port == 465:
                srv = smtplib.SMTP_SSL(cfg.get("email.smtp_server"), port, timeout=15)
            else:
                srv = smtplib.SMTP(cfg.get("email.smtp_server"), port, timeout=15)
                if cfg.get("email.smtp_tls", True):
                    srv.starttls()
            user = cfg.get("email.smtp_user", "")
            if user:
                srv.login(user, cfg.get("email.smtp_password", ""))
            srv.send_message(message)
            srv.quit()

        if combined_size <= MAX_EMAIL:
            # Single email with both attachments
            _smtp_send(msg)
            audit("COMPLIANCE_EMAIL", f"to={to} score={assessment['score']} size={combined_size}")
            return jsonify({"ok": True, "to": to, "score": assessment["score"],
                           "emails": 1, "size_kb": round(combined_size / 1024)})
        else:
            # Too large: split into 2 emails
            msg_pdf = MIMEMultipart()
            msg_pdf["Subject"] = f"{subj_company} — Compliance Report (PDF) — Score: {assessment['score']}/100"
            msg_pdf["From"] = msg["From"]
            msg_pdf["To"] = to
            msg_pdf.attach(MIMEText(body + "\n\nNote: DOCX version sent in a separate email due to size.", "plain", "utf-8"))
            msg_pdf.attach(pdf_part)
            _smtp_send(msg_pdf)

            msg_docx = MIMEMultipart()
            msg_docx["Subject"] = f"{subj_company} — Compliance Report (DOCX) — Score: {assessment['score']}/100"
            msg_docx["From"] = msg["From"]
            msg_docx["To"] = to
            msg_docx.attach(MIMEText("Editable DOCX version of the compliance report (PDF sent separately).", "plain", "utf-8"))
            msg_docx.attach(docx_part)
            _smtp_send(msg_docx)

            audit("COMPLIANCE_EMAIL", f"to={to} score={assessment['score']} split=2 size={combined_size}")
            return jsonify({"ok": True, "to": to, "score": assessment["score"],
                           "emails": 2, "size_kb": round(combined_size / 1024),
                           "note": "Split into 2 emails (exceeded 10 MB)"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
