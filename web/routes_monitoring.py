"""Monitoring, alerts, hosts, defense, analysis routes Blueprint."""
import logging
import os
from datetime import datetime, timedelta

logger = logging.getLogger("cgs.web.monitoring")
from flask import Blueprint, jsonify, request, session
from core.database import Alert, Host, Port, Flow, DnsLog, BaselineStat, WebUser
from core.security import InputValidator
from web.shared import ctx, auth, admin_required, csrf_protect, audit

monitoring_bp = Blueprint("monitoring_bp", __name__)


# ══════════════════════════════════════════════════
# Overview
# ══════════════════════════════════════════════════

@monitoring_bp.route("/api/overview")
@auth
def api_overview():
    now = datetime.now(); td = now.replace(hour=0, minute=0, second=0); wk = now - timedelta(days=7)
    return jsonify({
        "ts": now.isoformat(),
        "alerts": {
            "today": Alert.select().where(Alert.ts >= td).count(),
            "crit": Alert.select().where(Alert.severity == 1, Alert.ts >= td).count(),
            "high": Alert.select().where(Alert.severity == 2, Alert.ts >= td).count(),
            "med": Alert.select().where(Alert.severity == 3, Alert.ts >= td).count(),
            "unack": Alert.select().where(Alert.ack == False).count(),
        },
        "network": {
            "hosts_up": Host.select().where(Host.status == "up").count(),
            "hosts_total": Host.select().count(),
            "new_week": Host.select().where(Host.first_seen >= wk).count(),
            "open_ports": Port.select().where(Port.state == "open").count(),
        },
        "sniffer": ctx["sniffer"].stats if "sniffer" in ctx else {},
        "threats": ctx["engine"].get_threat_summary() if "engine" in ctx else {},
    })


# ══════════════════════════════════════════════════
# Alerts
# ══════════════════════════════════════════════════

@monitoring_bp.route("/api/alerts")
@auth
def api_alerts():
    lim = min(request.args.get("limit", 200, type=int), 1000)
    sv = request.args.get("severity", 5, type=int)
    src = request.args.get("source")
    q = Alert.select().where(Alert.severity <= sv)
    if src: q = q.where(Alert.source == src)
    SL = {1: "CRIT", 2: "HIGH", 3: "MED", 4: "LOW", 5: "INFO"}
    return jsonify([{
        "id": a.id, "ts": a.ts.isoformat(), "severity": a.severity,
        "sev_label": SL.get(a.severity), "source": a.source, "category": a.category,
        "title": a.title, "detail": a.detail, "src_ip": a.src_ip, "dst_ip": a.dst_ip,
        "ioc": a.ioc, "ack": a.ack
    } for a in q.order_by(Alert.ts.desc()).limit(lim)])

@monitoring_bp.route("/api/alerts/<int:aid>/ack", methods=["POST"])
@auth
@csrf_protect
def api_ack(aid):
    try:
        a = Alert.get_by_id(aid); a.ack = True; a.save()
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"e": "not found"}), 404

@monitoring_bp.route("/api/alerts/csv")
@auth
def api_alerts_csv():
    import csv, io
    from flask import send_file
    SL = {1: "CRIT", 2: "HIGH", 3: "MED", 4: "LOW", 5: "INFO"}
    buf = io.BytesIO()
    wrapper = io.TextIOWrapper(buf, encoding="utf-8", newline="")
    w = csv.writer(wrapper)
    w.writerow(["id","timestamp","severity","sev_label","source","category",
                "title","detail","src_ip","dst_ip","ioc","ack"])
    for a in Alert.select().order_by(Alert.ts.desc()).limit(5000):
        w.writerow([a.id, a.ts.isoformat(), a.severity, SL.get(a.severity, ""),
                    a.source, a.category, a.title, a.detail or "",
                    a.src_ip or "", a.dst_ip or "", a.ioc or "", a.ack])
    wrapper.flush(); wrapper.detach(); buf.seek(0)
    return send_file(buf, mimetype="text/csv", as_attachment=True,
                     download_name=f"cgs_alerts_{datetime.now().strftime('%Y%m%d')}.csv")


# ══════════════════════════════════════════════════
# Hosts
# ══════════════════════════════════════════════════

@monitoring_bp.route("/api/hosts")
@auth
def api_hosts():
    out = []
    for h in Host.select().order_by(Host.risk_score.desc(), Host.last_seen.desc()):
        ps = list(Port.select().where(Port.host_ip == h.ip, Port.state == "open"))
        out.append({
            "ip": h.ip, "mac": h.mac, "hostname": h.hostname, "vendor": h.vendor,
            "os": h.os_hint, "status": h.status, "risk": h.risk_score,
            "first": h.first_seen.isoformat(), "last": h.last_seen.isoformat(),
            "ports": [{"port": p.port, "svc": p.service, "banner": (p.banner or "")[:80]} for p in ps],
        })
    return jsonify(out)


# ══════════════════════════════════════════════════
# DNS, Baseline, Health
# ══════════════════════════════════════════════════

@monitoring_bp.route("/api/dns")
@auth
def api_dns():
    lim = min(request.args.get("limit", 100, type=int), 1000)
    sus = request.args.get("suspicious")
    q = DnsLog.select().order_by(DnsLog.ts.desc())
    if sus: q = q.where(DnsLog.entropy >= 3.5)
    return jsonify([{
        "ts": d.ts.isoformat(), "src": d.src_ip, "query": d.query,
        "entropy": d.entropy, "suspicious": d.suspicious
    } for d in q.limit(lim)])

@monitoring_bp.route("/api/baseline")
@auth
def api_baseline():
    return jsonify([{
        "key": b.key, "value": round(b.value, 2), "std": round(b.std_dev, 2),
        "samples": b.samples
    } for b in BaselineStat.select()])

@monitoring_bp.route("/api/health")
@auth
def api_health():
    h = ctx.get("health")
    return jsonify(h.check_all()) if h else jsonify({})


# ══════════════════════════════════════════════════
# Defense
# ══════════════════════════════════════════════════

@monitoring_bp.route("/api/defense")
@auth
def api_defense():
    d = ctx.get("defense")
    if not d: return jsonify({})
    result = {"stats": d.get_stats(), "active": d.get_active_actions()}
    if d.netgate:
        result["netgate"] = d.netgate.stats
        result["netgate"]["status"] = d.netgate.get_status()
    return jsonify(result)

@monitoring_bp.route("/api/defense/block", methods=["POST"])
@admin_required
@csrf_protect
def api_block():
    d = ctx.get("defense")
    if not d: return jsonify({"e": "no defense"}), 503
    ip = request.json.get("ip", "")
    reason = request.json.get("reason", "Manual block")
    ttl = request.json.get("ttl", 3600)
    ok = d.block_ip(ip, reason=reason, ttl=ttl, auto=False)
    audit("BLOCK_IP", f"ip={ip}")
    return jsonify({"ok": ok, "ip": ip})

@monitoring_bp.route("/api/defense/unblock", methods=["POST"])
@admin_required
@csrf_protect
def api_unblock():
    d = ctx.get("defense")
    if not d: return jsonify({"e": "no defense"}), 503
    ip = request.json.get("ip", "")
    ok = d.unblock_ip(ip, reason="Manual unblock")
    audit("UNBLOCK_IP", f"ip={ip}")
    return jsonify({"ok": ok, "ip": ip})

@monitoring_bp.route("/api/defense/quarantine", methods=["POST"])
@admin_required
@csrf_protect
def api_quarantine():
    d = ctx.get("defense")
    if not d: return jsonify({"e": "no defense"}), 503
    ip = request.json.get("ip", "")
    ok = d.quarantine_host(ip, reason="Manual quarantine", auto=False)
    audit("QUARANTINE", f"ip={ip}")
    return jsonify({"ok": ok, "ip": ip})

@monitoring_bp.route("/api/defense/audit")
@auth
def api_audit_log():
    d = ctx.get("defense")
    return jsonify(d.get_audit_log(200) if d else [])


# ══════════════════════════════════════════════════
# Analysis
# ══════════════════════════════════════════════════

@monitoring_bp.route("/api/correlator")
@auth
def api_correlator():
    c = ctx.get("correlator")
    return jsonify(c.stats if c else {})

@monitoring_bp.route("/api/detectors")
@auth
def api_detectors():
    o = ctx.get("orchestrator")
    return jsonify(o.get_health() if o else {})

@monitoring_bp.route("/api/detectors/stats")
@auth
def api_detectors_stats():
    o = ctx.get("orchestrator")
    return jsonify(o.stats if o else {})

@monitoring_bp.route("/api/supervisor")
@admin_required
def api_supervisor():
    sv = ctx.get("supervisor")
    return jsonify(sv.stats if sv else {})

@monitoring_bp.route("/api/threat-feeds")
@auth
def api_threat_feeds():
    tf = ctx.get("threat_feeds")
    return jsonify(tf.stats if tf else {})

@monitoring_bp.route("/api/suricata")
@auth
def api_suricata():
    s = ctx.get("suricata")
    return jsonify(s.stats if s else {})

@monitoring_bp.route("/api/honeypot")
@admin_required
def api_honeypot():
    hp = ctx.get("honeypot")
    return jsonify(hp.stats if hp else {})


# ══════════════════════════════════════════════════
# Identity
# ══════════════════════════════════════════════════

@monitoring_bp.route("/api/identity")
@auth
def api_identity():
    i = ctx.get("identity")
    return jsonify(i.stats if i else {})

@monitoring_bp.route("/api/identity/verify/<ip>")
@auth
def api_identity_verify(ip):
    i = ctx.get("identity")
    if not i: return jsonify({"error": "module absent"})
    mr = ctx.get("mac_resolver")
    mac = mr.ip_to_mac(ip) if mr else ""
    if not mac:
        try:
            h = Host.get_or_none(Host.ip == ip)
            if h: mac = h.mac or ""
        except Exception as e: logger.debug("Failed to resolve MAC for identity check: %s", e)
    if not mac: return jsonify({"error": "MAC unknown for this IP"})
    return jsonify(i.verify_identity(ip, mac))

@monitoring_bp.route("/api/identity/fingerprint/<mac>")
@auth
def api_identity_fp(mac):
    i = ctx.get("identity")
    if not i: return jsonify({})
    fp = i.get_fingerprint(mac)
    return jsonify(fp) if fp else jsonify({"error": "unknown fingerprint"})

@monitoring_bp.route("/api/mac-table")
@auth
def api_mac_table():
    mr = ctx.get("mac_resolver")
    return jsonify(mr.stats if mr else {})

@monitoring_bp.route("/api/killchain")
@auth
def api_killchain():
    kc = ctx.get("killchain")
    return jsonify(kc.stats if kc else {})


# ══════════════════════════════════════════════════
# Resilience
# ══════════════════════════════════════════════════

@monitoring_bp.route("/api/resilience")
@auth
def api_resilience():
    sm = ctx.get("self_monitor")
    dg = ctx.get("degraded")
    result = {}
    if sm: result["server_health"] = sm.check()
    if dg: result["degraded_mode"] = dg.stats
    return jsonify(result)

@monitoring_bp.route("/api/resilience/degraded", methods=["POST"])
@admin_required
@csrf_protect
def api_degraded_toggle():
    dg = ctx.get("degraded")
    if not dg: return jsonify({"error": "not available"}), 503
    data = request.get_json(force=True, silent=True) or {}
    action = data.get("action", "")
    if action == "enter":
        dg.enter(reason="Manual activation by admin")
        return jsonify({"ok": True, "active": True})
    elif action == "exit":
        dg.exit()
        return jsonify({"ok": True, "active": False})
    return jsonify({"error": "action must be 'enter' or 'exit'"}), 400


# ══════════════════════════════════════════════════
# Notifications stats
# ══════════════════════════════════════════════════

@monitoring_bp.route("/api/notifications/stats")
@auth
def api_notification_stats():
    alerter = ctx.get("alerter")
    if alerter and getattr(alerter, "_notifier", None):
        return jsonify(alerter._notifier.stats)
    return jsonify({"slack": {"enabled": False, "sent": 0, "errors": 0, "rate_limited": 0},
                     "teams": {"enabled": False, "sent": 0, "errors": 0, "rate_limited": 0},
                     "telegram": {"enabled": False, "sent": 0, "errors": 0, "rate_limited": 0}})
