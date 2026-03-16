"""
CGS — Incident response engine.

Two operating modes:

  CONFIRMATION MODE (default):
    1. DETECTED         : Threat identified, actions planned
    2. AWAITING_ADMIN   : Email sent to admins (approve/reject buttons)
    3. APPROVED         : Admin approves → defense launches immediately
                          User notified in parallel (popup or email)
    4. MITIGATING       : Recon + defense + forensic executing
    5. RESOLVED         : Report sent to admins + user

  IMMEDIATE MODE:
    1. DETECTED         : Threat identified → defense launches instantly
                          User notified in parallel (popup or email)
    2. MITIGATING       : Recon + defense + forensic executing
    3. RESOLVED         : Report sent to admins (includes rollback option)

  A pre-defense snapshot is always taken before any action (both modes).
  Admin can rollback to previous state from TUI, web API, or email link.
"""

import json
import logging
import os
import re
import secrets
import smtplib
import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import Optional

from core.database import Alert, Host

logger = logging.getLogger("cgs.incident")

SEV_LABELS = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
SEV_COLORS = {1: "#DC2626", 2: "#EA580C", 3: "#D97706", 4: "#2563EB"}


@dataclass
class Incident:
    id: str = ""
    token: str = ""
    created_at: float = 0
    updated_at: float = 0

    # Cible
    target_ip: str = ""
    target_hostname: str = ""
    target_email: str = ""
    target_name: str = ""

    # Attaquant
    attacker_ip: str = ""

    # Threat
    severity: int = 2
    threat_type: str = ""
    threat_detail: str = ""
    suricata_sids: list = field(default_factory=list)
    iocs: list = field(default_factory=list)

    # Planned actions (not yet executed)
    proposed_actions: list = field(default_factory=list)

    # Lifecycle
    status: str = "DETECTED"
    # Confirmation mode: DETECTED → AWAITING_ADMIN → APPROVED → MITIGATING → RESOLVED / RISK_REMAINING
    # Immediate mode:    DETECTED → APPROVED → MITIGATING → RESOLVED / RISK_REMAINING
    # Both:              or REJECTED / EXPIRED

    admin_alert_sent: bool = False
    user_alert_sent: bool = False
    approved_by: str = ""
    approved_at: float = 0
    rejected_by: str = ""
    reminder_sent: bool = False

    # Execution
    actions_executed: list = field(default_factory=list)
    defense_start: float = 0
    defense_end: float = 0
    snapshot_path: str = ""            # Pre-defense state snapshot (for rollback)

    # Resolution
    resolved: bool = False
    resolution: str = ""
    risk_remaining: bool = False
    risk_detail: str = ""
    report_sent: bool = False

    def __post_init__(self):
        if not self.id:
            self.id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
        if not self.token:
            self.token = secrets.token_urlsafe(32)
        if not self.created_at:
            self.created_at = time.time()
        self.updated_at = self.created_at

    def to_dict(self) -> dict:
        return {
            "id": self.id, "status": self.status,
            "created": datetime.fromtimestamp(self.created_at).isoformat(),
            "target_ip": self.target_ip, "target_hostname": self.target_hostname,
            "target_email": self.target_email, "target_name": self.target_name,
            "attacker_ip": self.attacker_ip,
            "severity": self.severity, "threat_type": self.threat_type,
            "threat_detail": self.threat_detail,
            "proposed_actions": self.proposed_actions,
            "actions_executed": self.actions_executed,
            "approved_by": self.approved_by,
            "approved_at": datetime.fromtimestamp(self.approved_at).isoformat() if self.approved_at else None,
            "resolved": self.resolved, "resolution": self.resolution,
            "risk_remaining": self.risk_remaining,
            "admin_alert_sent": self.admin_alert_sent,
            "user_alert_sent": self.user_alert_sent,
            "report_sent": self.report_sent,
            "snapshot_path": self.snapshot_path,
        }



# ══════════════════════════════════════════════════
# Templates email
# ══════════════════════════════════════════════════

ADMIN_APPROVAL_EMAIL = """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background:#f5f5f5">
<div style="max-width:640px;margin:20px auto;background:white;border-radius:12px;overflow:hidden;
            box-shadow:0 2px 12px rgba(0,0,0,0.1)">
  <div style="background:linear-gradient(135deg,{sev_color},#1F2937);color:white;padding:24px 30px">
    <h1 style="margin:0;font-size:20px">⚠️ INCIDENT — Approval required</h1>
    <p style="margin:8px 0 0;opacity:0.85;font-size:13px">{incident_id} · {timestamp}</p>
  </div>
  <div style="padding:24px 30px">
    <div style="background:#FEF2F2;border:1px solid #FECACA;border-radius:8px;padding:16px;margin-bottom:20px">
      <p style="margin:0;color:#991B1B;font-weight:600;font-size:15px">
        Attaque detectede — No action until you approve
      </p>
      <p style="margin:10px 0 0;color:#DC2626;font-size:13px">
        If you approve, the user will be notified by email to shut down their computer,
        then Sentinel will wait for actual shutdown before acting.
      </p>
    </div>
    <h2 style="font-size:15px;color:#1F2937;margin:0 0 10px">Threat</h2>
    <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px">
      <tr><td style="padding:6px 0;color:#666;width:130px">Severity</td>
          <td><span style="background:{sev_color};color:white;padding:2px 12px;
              border-radius:12px;font-size:11px;font-weight:600">{sev_label}</span></td></tr>
      <tr><td style="padding:6px 0;color:#666">Type</td><td style="font-weight:600">{threat_type}</td></tr>
      <tr><td style="padding:6px 0;color:#666">Attaquant</td><td style="font-weight:600;color:#DC2626">{attacker_ip}</td></tr>
      <tr><td style="padding:6px 0;color:#666">Cible</td><td style="font-weight:600">{target_ip} ({target_hostname})</td></tr>
      <tr><td style="padding:6px 0;color:#666">Utilisateur</td><td>{target_name} &lt;{target_email}&gt;</td></tr>
      <tr><td style="padding:6px 0;color:#666">Detail</td><td>{threat_detail}</td></tr>
    </table>
    <h2 style="font-size:15px;color:#1F2937;margin:0 0 10px">Proposed actions</h2>
    <div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:14px;margin-bottom:24px">
      <ul style="padding-left:18px;margin:0;font-size:13px;color:#334155">{actions_html}</ul>
    </div>
    <h2 style="font-size:15px;color:#1F2937;margin:0 0 10px">Workflow if approved</h2>
    <ol style="padding-left:18px;margin:0 0 24px;font-size:13px;color:#666">
      <li style="margin-bottom:4px">User receives email asking to shut down their computer</li>
      <li style="margin-bottom:4px">Sentinel monitors the host et attend son extinction</li>
      <li style="margin-bottom:4px">Once the host is down, defense actions are executed</li>
      <li>A report is sent to everyone</li>
    </ol>
    <div style="text-align:center;margin:28px 0">
      <a href="{approve_url}" style="display:inline-block;padding:14px 40px;background:#16A34A;
         color:white;text-decoration:none;border-radius:8px;font-weight:700;font-size:15px;
         margin-right:16px">✅ APPROVE</a>
      <a href="{reject_url}" style="display:inline-block;padding:14px 40px;background:#DC2626;
         color:white;text-decoration:none;border-radius:8px;font-weight:700;font-size:15px">❌ REJECT</a>
    </div>
    <div style="background:#FFFBEB;border:1px solid #FDE68A;border-radius:8px;padding:12px;
                font-size:12px;color:#92400E">
      ⏱ Without response within <strong>{timeout_min} min</strong>,
      {timeout_action}.
    </div>
    <p style="color:#BBB;font-size:11px;margin:16px 0 0">— CGS</p>
  </div>
</div></body></html>"""


USER_SHUTDOWN_EMAIL = """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background:#f5f5f5">
<div style="max-width:600px;margin:20px auto;background:white;border-radius:12px;overflow:hidden;
            box-shadow:0 2px 12px rgba(0,0,0,0.1)">
  <div style="background:linear-gradient(135deg,#DC2626,#991B1B);color:white;padding:24px 30px">
    <h1 style="margin:0;font-size:20px">⚠️ SECURITY ALERT — Action required</h1>
  </div>
  <div style="padding:24px 30px">

    <div style="background:#FEF2F2;border:1px solid #FECACA;border-radius:8px;padding:20px;margin-bottom:24px">
      <p style="margin:0;color:#991B1B;font-weight:600;font-size:16px">
        A cyberattack has been detected.
      </p>
      <p style="margin:12px 0 0;color:#DC2626;font-size:14px;line-height:1.6">
        The security team asks you to
        <strong>shut down your computer</strong>.
      </p>
      <p style="margin:12px 0 0;color:#DC2626;font-size:14px;line-height:1.6">
        You will receive a new email once the attack has been eradicated.
      </p>
    </div>

    <div style="background:#FFF7ED;border:1px solid #FED7AA;border-radius:8px;padding:16px;margin-bottom:24px">
      <p style="margin:0;color:#9A3412;font-size:13px;line-height:1.6">
        <strong>Important:</strong> if your computer is the only way
        for you to access your emails, please contact directly
        the security team before restarting your computer.
      </p>
    </div>

    <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px">
      <tr><td style="padding:6px 0;color:#666;width:100px">Incident</td><td style="font-weight:600">{incident_id}</td></tr>
      <tr><td style="padding:6px 0;color:#666">Votre poste</td><td>{target_ip} ({target_hostname})</td></tr>
      <tr><td style="padding:6px 0;color:#666">Contact</td><td>{security_contact}</td></tr>
    </table>

    <p style="color:#999;font-size:11px;margin:16px 0 0">
      — CGS · Automated message
    </p>
  </div>
</div></body></html>"""


REPORT_EMAIL = """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background:#f5f5f5">
<div style="max-width:600px;margin:20px auto;background:white;border-radius:12px;overflow:hidden;
            box-shadow:0 2px 12px rgba(0,0,0,0.1)">
  <div style="background:linear-gradient(135deg,{hdr1},{hdr2});color:white;padding:24px 30px">
    <h1 style="margin:0;font-size:20px">{hdr_icon} RAPPORT — {incident_id}</h1>
  </div>
  <div style="padding:24px 30px">
    <div style="background:{v_bg};border:1px solid {v_bdr};border-radius:8px;padding:16px;margin-bottom:20px">
      <p style="margin:0;color:{v_color};font-weight:600;font-size:15px">{v_icon} {v_title}</p>
      <p style="margin:10px 0 0;color:{v_txt};font-size:13px;line-height:1.6">{v_msg}</p>
    </div>
    <h2 style="font-size:14px;color:#1F2937;margin:0 0 8px">Timeline</h2>
    <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px">
      <tr><td style="padding:5px 0;color:#666;width:150px">Detected</td><td>{detected_at}</td></tr>
      <tr><td style="padding:5px 0;color:#666">Approved by</td><td>{approved_by}</td></tr>
      <tr><td style="padding:5px 0;color:#666">Defense started at</td><td>{shutdown_at}</td></tr>
      <tr><td style="padding:5px 0;color:#666">Defense completed</td><td>{resolved_at}</td></tr>
      <tr><td style="padding:5px 0;color:#666">Total duration</td><td style="font-weight:600">{duration}</td></tr>
    </table>
    <h2 style="font-size:14px;color:#1F2937;margin:0 0 8px">Actions executed</h2>
    <ul style="padding-left:18px;margin:0 0 16px;font-size:13px;color:#374151">{actions_html}</ul>
    {reco_html}
    <p style="color:#999;font-size:11px;margin-top:16px">— CGS · {report_time}</p>
  </div>
</div></body></html>"""


# ══════════════════════════════════════════════════
# Incident response engine
# ══════════════════════════════════════════════════

class IncidentResponseEngine:
    """Admin approves → immediate defense + user notified in parallel → report."""

    def __init__(self, config, alert_fn, defense_engine, mac_resolver=None):
        self.cfg = config
        self._alert = alert_fn
        self.defense = defense_engine
        self.mac_resolver = mac_resolver

        # Client notification queue (zero-privilege: clients poll us)
        from core.client_queue import ClientNotificationQueue
        self.client_queue = ClientNotificationQueue(config)

        # Defense state snapshots (for rollback)
        from core.snapshot import DefenseSnapshot
        self.snapshots = DefenseSnapshot(config)

        # SMTP
        self.email_enabled = config.get("email.enabled", False)
        self.smtp_server = config.get("email.smtp_server", "")
        self.smtp_port = config.get("email.smtp_port", 587)
        self.smtp_tls = config.get("email.smtp_tls", True)
        self.smtp_user = config.get("email.smtp_user", "")
        self.smtp_password = config.get("email.smtp_password", "")
        self.from_addr = config.get("email.from_address", "sentinel@cgs.local")
        self.admin_emails = config.get("email.admin_emails", [])
        self.security_contact = config.get("email.security_contact", "the IT security team")
        self.include_legal_info = config.get("email.include_legal_info", True)
        self.attach_forensic_file = config.get("email.attach_forensic_file", True)
        self.country_code = config.get("email.country", "IE")

        # Defense mode: "confirmation" (admin approves first) or "immediate" (act first, inform after)
        self.defense_mode = config.get("defense.mode", "confirmation")

        # Token TTL for approval/rejection links (default: 1 hour)
        self.token_ttl = config.get("email.token_ttl_seconds", 3600)

        # Approval PIN (set by daemon after init)
        self.approval_pin = None

        self.timeout_min = config.get("email.approval_timeout_minutes", 15)
        self.timeout_auto = config.get("email.timeout_auto_approve", False)

        web_port = config.get("web.port", 8443)
        self.base_url = config.get("email.sentinel_url", f"https://localhost:{web_port}")
        # Force HTTPS — approval tokens must never be sent over HTTP
        if self.base_url.startswith("http://"):
            self.base_url = "https://" + self.base_url[7:]
            logger.warning("Forced HTTPS on sentinel_url (approval tokens must not be sent over HTTP)")

        # Directory: indexed by IP AND MAC to survive DHCP changes
        self.users_by_ip: dict[str, dict] = {}
        self.users_by_mac: dict[str, dict] = {}
        for e in config.get("email.user_directory", []):
            if e.get("ip"):
                self.users_by_ip[e["ip"]] = e
            if e.get("mac"):
                self.users_by_mac[e["mac"].lower()] = e

        self._incidents: dict[str, Incident] = {}
        self._by_token: dict[str, str] = {}
        self._lock = threading.Lock()
        self._stats = {"total": 0, "emails_sent": 0, "emails_failed": 0}
        self.MAX_INCIDENTS = 500  # Memory bound — evict oldest resolved

        threading.Thread(target=self._timeout_loop, daemon=True, name="inc-timeout").start()

    # ══════════════════════════════════════════════
    # 1. Create (admin email only)
    # ══════════════════════════════════════════════
    def create_incident(self, target_ip: str, attacker_ip: str, severity: int,
                        threat_type: str, threat_detail: str,
                        suricata_sids: list = None, iocs: list = None) -> Incident:

        user = self.users_by_ip.get(target_ip, {})

        # If not found by IP, search by MAC (survives DHCP)
        if not user and self.mac_resolver:
            mac = self.mac_resolver.ip_to_mac(target_ip)
            if mac:
                user = self.users_by_mac.get(mac, {})
            if not user:
                user = self.mac_resolver.get_user_email(target_ip)

        if not user:
            try:
                h = Host.get_or_none(Host.ip == target_ip)
                if h:
                    user = {"hostname": h.hostname or h.vendor or "", "name": "", "email": ""}
            except Exception as e:
                logger.warning("Failed to resolve target host info for %s: %s", target_ip, e)

        inc = Incident(
            target_ip=target_ip,
            target_hostname=user.get("hostname", target_ip),
            target_email=user.get("email", ""),
            target_name=user.get("name", ""),
            attacker_ip=attacker_ip, severity=severity,
            threat_type=threat_type, threat_detail=threat_detail,
            suricata_sids=suricata_sids or [], iocs=iocs or [],
        )
        inc.proposed_actions = self._plan(inc)

        with self._lock:
            self._incidents[inc.id] = inc
            self._by_token[inc.token] = inc.id
            # Evict oldest resolved incidents if cache full
            if len(self._incidents) > self.MAX_INCIDENTS:
                self._evict_oldest()
        self._stats["total"] += 1

        if self.defense_mode == "immediate":
            # ── IMMEDIATE MODE ──
            # Act first, inform after. No waiting for admin approval.
            logger.warning("⚡ Incident %s — IMMEDIATE MODE | %s → %s | sev=%d",
                           inc.id, attacker_ip, target_ip, severity)

            inc.status = "APPROVED"
            inc.approved_by = "auto (immediate mode)"
            inc.approved_at = time.time()

            # Notify user in parallel
            if inc.target_ip or inc.target_email:
                def _notify():
                    agent_active = (self.client_queue.enabled and inc.target_ip and
                                   self.client_queue.has_active_agent(inc.target_ip))
                    if agent_active:
                        msg_id = self.client_queue.enqueue_shutdown(
                            ip=inc.target_ip, incident_id=inc.id,
                            threat_type=inc.threat_type, detail=inc.threat_detail)
                        acked = self.client_queue.wait_for_ack(msg_id, inc.target_ip)
                        if not acked and inc.target_email:
                            self._send_user_shutdown_email(inc)
                            inc.user_alert_sent = True
                        else:
                            inc.user_alert_sent = acked
                    elif inc.target_email:
                        self._send_user_shutdown_email(inc)
                        inc.user_alert_sent = True
                threading.Thread(target=_notify, daemon=True,
                               name=f"notify-{inc.id}").start()

            # Launch defense immediately
            threading.Thread(target=self._execute_and_report, args=(inc,),
                             daemon=True, name=f"inc-defense-{inc.id}").start()

            self._alert(severity=severity, source="incident", category="immediate",
                        title=f"⚡ Incident {inc.id} — Immediate defense launched",
                        detail=f"Actions: {', '.join(inc.proposed_actions)}",
                        src_ip=attacker_ip, dst_ip=target_ip)

        else:
            # ── CONFIRMATION MODE (default) ──
            # Email admin and wait for approval before acting.
            logger.warning("📋 Incident %s — AWAITING ADMIN | %s → %s | sev=%d",
                           inc.id, attacker_ip, target_ip, severity)

            self._send_admin_email(inc)
            inc.status = "AWAITING_ADMIN"

            # Generate approval PIN (visible in dashboard only, never in email)
            if self.approval_pin:
                pin = self.approval_pin.generate(inc.id)
                logger.info("📌 Approval PIN for %s: %s (dashboard only)", inc.id, pin)

            self._alert(severity=severity, source="incident", category="awaiting",
                        title=f"Incident {inc.id} — Awaiting admin approval",
                        detail=f"Proposed actions: {', '.join(inc.proposed_actions)}",
                        src_ip=attacker_ip, dst_ip=target_ip)

        return inc

    # ══════════════════════════════════════════════
    # 2. Approbation → email user → surveillance
    # ══════════════════════════════════════════════
    def approve(self, token: str, approved_by: str = "admin") -> Optional[dict]:
        inc = self._get_by_token(token)
        if not inc:
            return None
        if inc.status != "AWAITING_ADMIN":
            return {"error": f"Already processed (status={inc.status})", "incident": inc.to_dict()}

        inc.status = "APPROVED"
        inc.approved_by = approved_by
        inc.approved_at = time.time()
        inc.updated_at = time.time()

        logger.warning("✅ Incident %s APPROVED by %s", inc.id, approved_by)

        self._alert(severity=5, source="incident", category="approved",
                    title=f"Incident {inc.id} approved by {approved_by}",
                    src_ip=inc.attacker_ip, dst_ip=inc.target_ip)

        # ── Notify user (in parallel — does NOT block defense) ──
        # This is a courtesy: we ask the user to shut down as a precaution.
        # Defense actions launch immediately regardless.
        if inc.target_ip or inc.target_email:
            def _notify_user():
                agent_active = (self.client_queue.enabled and inc.target_ip and
                               self.client_queue.has_active_agent(inc.target_ip))

                if agent_active:
                    msg_id = self.client_queue.enqueue_shutdown(
                        ip=inc.target_ip,
                        incident_id=inc.id,
                        threat_type=inc.threat_type,
                        detail=inc.threat_detail,
                    )
                    logger.info("📢 Popup queued for %s (agent active, waiting for ack...)",
                               inc.target_ip)
                    acked = self.client_queue.wait_for_ack(msg_id, inc.target_ip)
                    if acked:
                        inc.user_alert_sent = True
                        logger.info("📢 User acknowledged popup on %s", inc.target_ip)
                    else:
                        logger.info("📢 No popup ack from %s → sending email", inc.target_ip)
                        if inc.target_email:
                            self._send_user_shutdown_email(inc)
                            inc.user_alert_sent = True
                else:
                    if inc.target_email:
                        self._send_user_shutdown_email(inc)
                        inc.user_alert_sent = True
                        logger.info("📧 Shutdown email sent to %s", inc.target_email)

            threading.Thread(target=_notify_user, daemon=True,
                           name=f"notify-{inc.id}").start()

        # ── Launch defense IMMEDIATELY (no waiting for shutdown) ──
        threading.Thread(target=self._execute_and_report, args=(inc,),
                         daemon=True, name=f"inc-defense-{inc.id}").start()

        return {"ok": True, "incident": inc.to_dict()}

    def reject(self, token: str, rejected_by: str = "admin") -> Optional[dict]:
        inc = self._get_by_token(token)
        if not inc:
            return None
        if inc.status != "AWAITING_ADMIN":
            return {"error": f"Already processed (status={inc.status})", "incident": inc.to_dict()}

        inc.status = "REJECTED"
        inc.rejected_by = rejected_by
        inc.resolved = True
        inc.resolution = f"Rejected by {rejected_by}. No action."
        inc.updated_at = time.time()

        logger.info("❌ Incident %s REJECTED by %s", inc.id, rejected_by)
        self._alert(severity=5, source="incident", category="rejected",
                    title=f"Incident {inc.id} rejected", src_ip=inc.attacker_ip)
        return {"ok": True, "incident": inc.to_dict()}

    # ══════════════════════════════════════════════
    # 3. Notification sent to user as precaution (non-blocking)
    # ══════════════════════════════════════════════
    # ══════════════════════════════════════════════
    # 4. Execute actions + report
    # ══════════════════════════════════════════════
    def _execute_and_report(self, inc: Incident):
        """Approved → Deep recon → Aggressive defense → Forensic → Report."""
        inc.status = "MITIGATING"
        inc.defense_start = time.time()

        # ═══════════════════════════════════════════
        # SNAPSHOT: Save current state before any action (enables rollback)
        # ═══════════════════════════════════════════
        snapshot_path = ""
        try:
            snapshot_path = self.snapshots.take(
                incident_id=inc.id,
                reason=f"Pre-defense snapshot for {inc.threat_type}",
            )
            inc.snapshot_path = snapshot_path
            logger.info("📸 Pre-defense snapshot saved: %s", snapshot_path)
        except Exception as e:
            logger.warning("Snapshot failed (continuing without rollback capability): %s", e)

        # ═══════════════════════════════════════════
        # PHASE 1: Deep reconnaissance of the attacker
        # ═══════════════════════════════════════════
        recon_report = {}
        if inc.attacker_ip:
            self._alert(severity=5, source="incident", category="recon",
                        title=f"🔍 Reconnaissance of {inc.attacker_ip} in progress…",
                        src_ip=inc.attacker_ip)
            try:
                from core.recon import AttackerRecon
                recon = AttackerRecon(self.cfg)
                recon_report = recon.full_recon(inc.attacker_ip)

                # Enrich IOCs with recon results
                rdns = recon_report.get("reverse_dns")
                if rdns and rdns not in inc.iocs:
                    inc.iocs.append(rdns)

                # Summary in logs
                geo = recon_report.get("geolocation", {})
                whois = recon_report.get("whois", {})
                ports_found = len(recon_report.get("open_ports", []))
                logger.warning(
                    "🔍 Recon %s completed : %s, %s | AS%s %s | %d ports | OS=%s",
                    inc.attacker_ip,
                    geo.get("city", "?"), geo.get("country", "?"),
                    whois.get("asn", "?"), whois.get("org", "?"),
                    ports_found,
                    recon_report.get("os_fingerprint", "?"),
                )
            except Exception as e:
                logger.error("Recon failede pour %s : %s", inc.attacker_ip, e)
                recon_report = {"error": str(e)}

        # ═══════════════════════════════════════════
        # PHASE 2: Aggressive defense
        # ═══════════════════════════════════════════
        executed = []
        for action in inc.proposed_actions:
            try:
                if ("Block" in action or "Block" in action) and inc.attacker_ip:
                    ok = self.defense.block_ip(inc.attacker_ip, reason=f"Incident {inc.id}", auto=False)
                    executed.append(f"{'✓' if ok else '✗'} {action}")
                elif ("quarantine" in action.lower() or "quarantaine" in action.lower()) and inc.target_ip:
                    ok = self.defense.quarantine_host(inc.target_ip, reason=f"Incident {inc.id}", auto=False)
                    executed.append(f"{'✓' if ok else '✗'} {action}")
                elif "sinkhole" in action.lower():
                    domain = action.split("sur ")[-1] if "sur " in action else ""
                    if domain:
                        self.defense.dns_sinkhole(domain, reason=f"Incident {inc.id}")
                        executed.append(f"✓ {action}")
                elif "Rate-limit" in action and inc.attacker_ip:
                    ok = self.defense.rate_limit_ip(inc.attacker_ip, reason=f"Incident {inc.id}", auto=False)
                    executed.append(f"{'✓' if ok else '✗'} {action}")
                else:
                    executed.append(f"⚠ {action}")
            except Exception as e:
                executed.append(f"✗ {action} — {e}")

        # Auto-sinkhole domains found during recon
        for ioc in inc.iocs:
            if "." in ioc and not ioc.replace(".", "").isdigit():
                already = any(ioc in a for a in executed)
                if not already:
                    self.defense.dns_sinkhole(ioc, reason=f"IOC recon {inc.id}")
                    executed.append(f"✓ DNS sinkhole (recon) on {ioc}")

        inc.actions_executed = executed
        inc.defense_end = time.time()

        ok_count = sum(1 for a in executed if a.startswith("✓"))
        fail_count = sum(1 for a in executed if a.startswith("✗"))

        if ok_count > 0 and fail_count == 0:
            inc.status = "RESOLVED"
            inc.resolved = True
            inc.resolution = "All actions succeeded. Threat neutralized."
        else:
            inc.status = "RISK_REMAINING"
            inc.risk_remaining = True
            inc.risk_detail = f"{fail_count} action(s) failed."
            inc.resolution = f"Partial intervention : {ok_count}/{len(executed)} succeeded."

        inc.updated_at = time.time()
        logger.info("🛡️ Incident %s → %s (%d/%d actions OK)",
                     inc.id, inc.status, ok_count, len(executed))

        # ═══════════════════════════════════════════
        # PHASE 3: Forensic collection
        # ═══════════════════════════════════════════
        forensic_path = ""
        try:
            from core.forensic import ForensicCollector
            collector = ForensicCollector(self.cfg)
            forensic_path = collector.collect_and_save(
                incident_id=inc.id,
                incident_data=inc.to_dict(),
                attacker_ip=inc.attacker_ip,
                target_ip=inc.target_ip,
                recon_report=recon_report,
                defense_actions=executed,
                created_at=inc.created_at,
            )
            self._alert(severity=5, source="incident", category="forensic",
                        title=f"📁 Forensic evidence saved : {inc.id}",
                        detail=f"Fichier : {forensic_path}")
        except Exception as e:
            logger.error("Forensic collection failed : %s", e)

        # ═══════════════════════════════════════════
        # PHASE 3b: Complaint PDF (if enabled)
        # ═══════════════════════════════════════════
        complaint_pdf_path = ""
        if self.include_legal_info:
            try:
                from core.complaint_pdf import generate_complaint_pdf
                complaint_pdf_path = generate_complaint_pdf(
                    incident_data=inc.to_dict(),
                    recon_report=recon_report,
                    forensic_path=forensic_path,
                    config={},
                    output_dir=os.path.join(
                        self.cfg.get("general.log_dir", "/var/log/cgs"),
                        "forensics"
                    ),
                    country_code=self.country_code,
                )
                logger.info("📄 Complaint PDF generated : %s", complaint_pdf_path)
            except Exception as e:
                logger.warning("Complaint PDF generation failed : %s", e)

        # ═══════════════════════════════════════════
        # PHASE 4 : Rapport email
        # ═══════════════════════════════════════════
        time.sleep(2)
        self._send_report(inc, recon_report=recon_report, forensic_path=forensic_path,
                         complaint_pdf_path=complaint_pdf_path)

        # ═══════════════════════════════════════════
        # PHASE 5 : Client agent tasks (only if agent is deployed)
        # ═══════════════════════════════════════════
        # Without the agent installed on workstations:
        #   - No popup (email already sent as primary notification)
        #   - No local AV scan after reboot
        #   - No local forensic collection
        # The system works fully via email alone.
        if self.client_queue.enabled and inc.target_ip:
            # Queue forensic collection (agent will ask user's consent first)
            if self.cfg.get("client_agent.collect_after_incident", True):
                self.client_queue.enqueue_collect_forensic(
                    ip=inc.target_ip,
                    incident_id=inc.id,
                )
                logger.info("📋 Forensic collection queued for client agent on %s",
                           inc.target_ip)

            # Queue all-clear or risk warning popup
            self.client_queue.enqueue_all_clear(
                ip=inc.target_ip,
                incident_id=inc.id,
                resolved=inc.resolved and not inc.risk_remaining,
                risk_detail=inc.risk_detail or "",
            )

    # ══════════════════════════════════════════════
    # Planning (without execution)
    # ══════════════════════════════════════════════
    def _plan(self, inc: Incident) -> list[str]:
        actions = []
        if inc.attacker_ip and inc.attacker_ip not in self.defense.whitelist:
            actions.append(f"Block IP {inc.attacker_ip} (iptables, 1h)")
        if inc.severity <= 1:
            from core.netutils import ip_in_subnet
            for subnet in self.cfg.get("network.subnets", []):
                if ip_in_subnet(inc.target_ip, subnet):
                    actions.append(f"Network quarantine of {inc.target_ip}")
                    break
        for ioc in inc.iocs:
            if "." in ioc and not ioc.replace(".", "").isdigit():
                actions.append(f"DNS sinkhole on {ioc}")
        if not actions and inc.attacker_ip:
            actions.append(f"Rate-limit sur {inc.attacker_ip}")
        return actions

    # ══════════════════════════════════════════════
    # Timeout admin
    # ══════════════════════════════════════════════
    def _timeout_loop(self):
        while True:
            time.sleep(30)
            now = time.time()
            with self._lock:
                awaiting = [i for i in self._incidents.values() if i.status == "AWAITING_ADMIN"]
            for inc in awaiting:
                elapsed = now - inc.created_at
                timeout_s = self.timeout_min * 60
                if elapsed > timeout_s / 2 and not inc.reminder_sent:
                    inc.reminder_sent = True
                    self._send_admin_email(inc, reminder=True)
                if elapsed > timeout_s:
                    if self.timeout_auto:
                        logger.warning("⏱ Timeout %s — auto-approval", inc.id)
                        self.approve(inc.token, approved_by="auto-timeout")
                    else:
                        inc.status = "EXPIRED"
                        inc.resolution = f"No response within {self.timeout_min} min."
                        self._alert(severity=1, source="incident", category="expired",
                                    title=f"⏱ Incident {inc.id} expired without admin response !",
                                    src_ip=inc.attacker_ip, dst_ip=inc.target_ip)

    # ══════════════════════════════════════════════
    # Emails
    # ══════════════════════════════════════════════
    def _send_admin_email(self, inc: Incident, reminder=False):
        if not self.email_enabled or not self.admin_emails:
            return
        actions_html = "".join(f"<li style='margin-bottom:6px'>🔹 {a}</li>" for a in inc.proposed_actions)
        timeout_action = ("actions will be executed automatically" if self.timeout_auto
                         else "the incident will expire without action")
        subject = f"{'🔁 REMINDER — ' if reminder else ''}⚠️ [CGS] {inc.id} — Approval required"
        html = ADMIN_APPROVAL_EMAIL.format(
            incident_id=inc.id,
            timestamp=datetime.fromtimestamp(inc.created_at).strftime("%d/%m/%Y %H:%M"),
            sev_color=SEV_COLORS.get(inc.severity, "#666"),
            sev_label=SEV_LABELS.get(inc.severity, "?"),
            threat_type=inc.threat_type, threat_detail=inc.threat_detail[:500],
            attacker_ip=inc.attacker_ip, target_ip=inc.target_ip,
            target_hostname=inc.target_hostname,
            target_name=inc.target_name or "—",
            target_email=inc.target_email or "—",
            actions_html=actions_html or "<li>None</li>",
            approve_url=f"{self.base_url}/incident/{inc.id}/approve?token={inc.token}",
            reject_url=f"{self.base_url}/incident/{inc.id}/reject?token={inc.token}",
            timeout_min=self.timeout_min, timeout_action=timeout_action,
        )
        ok = self._smtp(self.admin_emails, subject, html)
        if not reminder:
            inc.admin_alert_sent = ok

    def _send_user_shutdown_email(self, inc: Incident):
        if not self.email_enabled or not inc.target_email:
            return
        html = USER_SHUTDOWN_EMAIL.format(
            incident_id=inc.id, target_ip=inc.target_ip,
            target_hostname=inc.target_hostname,
            security_contact=self.security_contact,
        )
        self._smtp([inc.target_email],
                   "🔴 [CGS] Security alert — Please shut down your computer",
                   html)

    def _send_report(self, inc: Incident, recon_report: dict = None, forensic_path: str = "",
                     complaint_pdf_path: str = ""):
        if not self.email_enabled:
            return

        # Separate admins and user — only admins receive full report
        admin_recipients = list(self.admin_emails)
        user_recipient = inc.target_email if inc.target_email and inc.target_email not in admin_recipients else ""

        is_ok = inc.resolved and not inc.risk_remaining
        if is_ok:
            hdr = ("#16A34A", "#15803D", "✅")
            v = ("#F0FDF4", "#BBF7D0", "#15803D", "#166534", "✅",
                 "Threat successfully eradicated",
                 "All defense actions succeeded. You can turn your computer back on and resume work normally.")
        else:
            hdr = ("#EA580C", "#C2410C", "⚠️")
            v = ("#FFF7ED", "#FED7AA", "#C2410C", "#9A3412", "⚠️",
                 "Residual risk — Do not turn your computer back on",
                 inc.risk_detail or "Please contact the security team before turning your computer back on.")

        actions_html = "".join(f"<li style='margin-bottom:4px'>{a}</li>" for a in inc.actions_executed) or "<li>None</li>"

        # ── Section recon attaquant ──
        recon_html = ""
        if recon_report and recon_report.get("target_ip"):
            geo = recon_report.get("geolocation", {})
            whois = recon_report.get("whois", {})
            rep = recon_report.get("reputation", {})
            ports = recon_report.get("open_ports", [])
            recon_html = f"""
            <h2 style="font-size:14px;color:#1F2937;margin:16px 0 8px">Attacker intelligence</h2>
            <div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:14px;font-size:12px;margin-bottom:16px">
              <table style="width:100%;border-collapse:collapse">
                <tr><td style="padding:3px 0;color:#666;width:120px">IP</td><td style="font-weight:600">{recon_report.get('target_ip','')}</td></tr>
                <tr><td style="padding:3px 0;color:#666">Reverse DNS</td><td>{recon_report.get('reverse_dns','—')}</td></tr>
                <tr><td style="padding:3px 0;color:#666">Pays</td><td>{geo.get('country','')} ({geo.get('country_code','')})</td></tr>
                <tr><td style="padding:3px 0;color:#666">Ville</td><td>{geo.get('city','')}, {geo.get('region','')}</td></tr>
                <tr><td style="padding:3px 0;color:#666">GPS coordinates</td><td>{geo.get('lat','')}, {geo.get('lon','')}</td></tr>
                <tr><td style="padding:3px 0;color:#666">Timezone</td><td>{geo.get('timezone','')}</td></tr>
                <tr><td style="padding:3px 0;color:#666">FAI</td><td>{geo.get('isp','')}</td></tr>
                <tr><td style="padding:3px 0;color:#666">Organisation</td><td>{whois.get('org','')}</td></tr>
                <tr><td style="padding:3px 0;color:#666">ASN</td><td>AS{whois.get('asn','?')}</td></tr>
                <tr><td style="padding:3px 0;color:#666">Network range</td><td>{whois.get('netrange','')}</td></tr>
                <tr><td style="padding:3px 0;color:#666">Abuse contact</td><td><a href="mailto:{whois.get('abuse_contact','')}">{whois.get('abuse_contact','—')}</a></td></tr>
                <tr><td style="padding:3px 0;color:#666">Estimated OS</td><td>{recon_report.get('os_fingerprint','')}</td></tr>
                <tr><td style="padding:3px 0;color:#666">Open ports</td><td>{', '.join(str(p['port'])+'/'+p.get('service','') for p in ports[:15])}</td></tr>
                <tr><td style="padding:3px 0;color:#666">Proxy/VPN/Tor</td><td>{'Yes ⚠️' if geo.get('proxy') or geo.get('hosting') else 'Not detected'}</td></tr>
                <tr><td style="padding:3px 0;color:#666">Hosting provider</td><td>{'Yes (datacenter)' if geo.get('hosting') else 'No (residential/business)'}</td></tr>
                <tr><td style="padding:3px 0;color:#666">Reputation</td><td>{rep.get('summary','—')}</td></tr>
              </table>
            </div>"""

        # ── Section recommandations ──
        reco_html = ""
        if not is_ok:
            reco_html = """<h2 style="font-size:14px;color:#1F2937;margin:16px 0 8px">Immediate recommendations</h2>
            <div style="background:#FFF7ED;border:1px solid #FED7AA;border-radius:8px;padding:12px;font-size:13px;color:#9A3412">
            <ul style="padding-left:18px;margin:0">
              <li>Do not turn your computer back on</li>
              <li>Contact the security team</li>
              <li>An antivirus scan will be needed before restarting before returning to service</li>
              <li>Change your passwords from another device</li>
            </ul></div>"""

        # ── Forensic attachment section ──
        forensic_html = ""
        attached_files = []
        if forensic_path and self.attach_forensic_file:
            attached_files.append(f"📁 Forensic JSON report ({os.path.basename(forensic_path)})")
        if complaint_pdf_path and self.include_legal_info:
            attached_files.append(f"📄 PDF complaint form ({os.path.basename(complaint_pdf_path)})")

        if attached_files:
            files_list = "<br>".join(attached_files)
            forensic_html = f"""<div style="background:#EFF6FF;border:1px solid #BFDBFE;border-radius:8px;
                padding:12px;font-size:12px;color:#1E40AF;margin-top:16px">
                <strong>Attachments :</strong><br>
                {files_list}<br>
                <span style="font-size:11px;color:#6B7280">
                Keep these files safely — they constitute digital evidence
                for a potential complaint filing.
                </span>
            </div>"""
        elif forensic_path:
            forensic_html = f"""<div style="background:#EFF6FF;border:1px solid #BFDBFE;border-radius:8px;
                padding:12px;font-size:12px;color:#1E40AF;margin-top:16px">
                📁 Forensic report saved on server :<br>
                <code style="font-size:11px">{forensic_path}</code>
            </div>"""

        # ═══════════════════════════════════════════════════
        # COMPLAINT FILING SECTION (optional)
        # ═══════════════════════════════════════════════════
        legal_html = ""
        if self.include_legal_info:
            from core.legal_data import get_country
            ctry = get_country(self.country_code)
            police = ctry["police"]
            csirt = ctry["csirt"]
            dpa = ctry["dpa"]

            legal_html = f"""
        <h2 style="font-size:14px;color:#1F2937;margin:20px 0 8px">🏛️ {"File a Complaint" if self.country_code == "US" else "File a complaint"} — {ctry['flag']} {ctry['name']}</h2>
        <div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:16px;font-size:12px;margin-bottom:16px">

          <p style="margin:0 0 12px;color:#374151;font-size:13px;font-weight:600">
            {"It is strongly recommended to report this cyberattack to the authorities." if self.country_code == "US"
             else "It is strongly recommended to report this cyberattack to the authorities."}
          </p>

          <h3 style="font-size:13px;color:#1E40AF;margin:14px 0 6px;border-bottom:1px solid #E2E8F0;padding-bottom:4px">
            {"1. Law Enforcement" if self.country_code == "US" else "1. " + police['name']}
          </h3>
          <table style="width:100%;border-collapse:collapse;margin-bottom:10px">
            <tr><td style="padding:2px 0;color:#666;width:110px">{"Unit" if self.country_code == "US" else "Unit"}</td>
                <td><strong>{police['unit']}</strong></td></tr>
            <tr><td style="padding:2px 0;color:#666">{"How" if self.country_code == "US" else "Comment"}</td>
                <td>{police['how']}</td></tr>
            <tr><td style="padding:2px 0;color:#666">{"Phone" if self.country_code == "US" else "Phone"}</td>
                <td><strong>{police.get('phone', '')}</strong></td></tr>
            <tr><td style="padding:2px 0;color:#666">{"Website" if self.country_code == "US" else "Site"}</td>
                <td><a href="{police['url']}" style="color:#2563EB">{police['url']}</a></td></tr>
          </table>"""

            if police.get("url_online"):
                label = "Online report" if self.country_code == "US" else "Online complaint"
                legal_html += f"""
          <p style="margin:0 0 10px;color:#374151">
            {label} : <a href="{police['url_online']}" style="color:#2563EB">{police['url_online']}</a>
          </p>"""

            legal_html += f"""
          <h3 style="font-size:13px;color:#1E40AF;margin:14px 0 6px;border-bottom:1px solid #E2E8F0;padding-bottom:4px">
            2. {csirt['name']}
          </h3>
          <table style="width:100%;border-collapse:collapse;margin-bottom:10px">
            <tr><td style="padding:2px 0;color:#666;width:110px">{"Role" if self.country_code == "US" else "Role"}</td>
                <td>{csirt['role']}</td></tr>
            <tr><td style="padding:2px 0;color:#666">Email</td>
                <td><a href="mailto:{csirt['email']}" style="color:#2563EB"><strong>{csirt['email']}</strong></a></td></tr>
            <tr><td style="padding:2px 0;color:#666">{"Phone" if self.country_code == "US" else "Phone"}</td>
                <td>{csirt.get('phone', '')}</td></tr>
            <tr><td style="padding:2px 0;color:#666">{"Website" if self.country_code == "US" else "Site"}</td>
                <td><a href="{csirt['url']}" style="color:#2563EB">{csirt['url']}</a></td></tr>
          </table>"""

            # NIS2 if applicable
            nis2 = ctry.get("nis2", {})
            if nis2.get("applicable"):
                label_nis = "NIS2 Obligation" if self.country_code == "US" else "Obligation NIS2"
                legal_html += f"""
          <h3 style="font-size:13px;color:#1E40AF;margin:14px 0 6px;border-bottom:1px solid #E2E8F0;padding-bottom:4px">
            3. {label_nis}
          </h3>
          <table style="width:100%;border-collapse:collapse;margin-bottom:10px">
            <tr><td style="padding:2px 0;color:#666;width:110px">{"Deadlines" if self.country_code == "US" else "Deadlines"}</td>
                <td>{nis2['deadlines']}</td></tr>
            <tr><td style="padding:2px 0;color:#666">Contact</td>
                <td><a href="mailto:{nis2['contact']}" style="color:#2563EB">{nis2['contact']}</a></td></tr>
          </table>"""

            # DPA
            legal_html += f"""
          <h3 style="font-size:13px;color:#1E40AF;margin:14px 0 6px;border-bottom:1px solid #E2E8F0;padding-bottom:4px">
            {"Data Protection" if self.country_code == "US" else "Data protection"}
          </h3>
          <table style="width:100%;border-collapse:collapse;margin-bottom:10px">
            <tr><td style="padding:2px 0;color:#666;width:110px">{"Authority" if self.country_code == "US" else "Authority"}</td>
                <td>{dpa['name']}</td></tr>
            <tr><td style="padding:2px 0;color:#666">{"Deadline" if self.country_code == "US" else "Deadline"}</td>
                <td>{dpa.get('deadline', '')}</td></tr>
            <tr><td style="padding:2px 0;color:#666">URL</td>
                <td><a href="{dpa['url']}" style="color:#2563EB">{dpa['url']}</a></td></tr>
          </table>"""

            # EU portal
            eu = ctry.get("eu_portal")
            if eu:
                legal_html += f"""
          <p style="margin:4px 0;color:#374151;font-size:12px">
            <strong>Europol EC3</strong> :
            <a href="{eu['url']}" style="color:#2563EB">{eu['url']}</a>
          </p>"""

            # Extra resources (Cybermalveillance, Secret Service, etc.)
            extras = ctry.get("extra_resources", {})
            for k, r in extras.items():
                legal_html += f"""
          <p style="margin:4px 0;color:#374151;font-size:12px">
            <strong>{r['name']}</strong> : <a href="{r.get('url','')}" style="color:#2563EB">{r.get('url','')}</a>
            <br><span style="color:#999;font-size:11px">{r.get('note','')}</span>
          </p>"""

            # Abuse contact
            legal_html += f"""
          <h3 style="font-size:13px;color:#1E40AF;margin:14px 0 6px;border-bottom:1px solid #E2E8F0;padding-bottom:4px">
            📧 {"Report to attacker's ISP" if self.country_code == "US" else "Report to attacker's ISP"}
          </h3>
          <p style="margin:0;color:#374151">"""

            if recon_report and recon_report.get("whois", {}).get("abuse_contact"):
                abuse = recon_report["whois"]["abuse_contact"]
                legal_html += f"""
            <a href="mailto:{abuse}" style="color:#2563EB"><strong>{abuse}</strong></a>"""
            else:
                legal_html += """—"""

            legal_html += """
          </p>
        </div>"""

        dur_s = (inc.defense_end or time.time()) - inc.created_at
        dur = f"{int(dur_s)}s" if dur_s < 60 else f"{int(dur_s/60)} min"
        fmt_ts = lambda t: datetime.fromtimestamp(t).strftime("%d/%m/%Y %H:%M") if t else "—"

        # ── Rollback section (both modes) ──
        rollback_html = ""
        if inc.snapshot_path:
            if self.defense_mode == "immediate":
                intro = "These actions were executed automatically (immediate mode)."
            else:
                intro = "These actions were executed after your approval."
            rollback_html = f"""
            <h2 style="font-size:14px;color:#1F2937;margin:16px 0 8px">⏪ Rollback</h2>
            <div style="background:#FEF3C7;border:1px solid #FDE68A;border-radius:8px;
                        padding:14px;font-size:12px;margin-bottom:16px">
              <p style="margin:0 0 8px;color:#92400E;font-weight:600">
                {intro}
              </p>
              <p style="margin:0 0 8px;color:#92400E">
                A pre-defense snapshot was saved before any action was taken.
                If these actions caused problems, you can restore the previous state.
              </p>
              <p style="margin:0 0 12px;color:#374151">
                <strong>Rollback options:</strong>
              </p>
              <ul style="padding-left:18px;margin:0;color:#374151;line-height:1.8">
                <li>SSH: <code>sudo cgs console</code> → Active defense → Rollback</li>
                <li>API: <code>POST /api/snapshots/rollback</code></li>
                <li>Snapshot: <code style="font-size:10px">{inc.snapshot_path}</code></li>
              </ul>
            </div>"""

        html = REPORT_EMAIL.format(
            hdr1=hdr[0], hdr2=hdr[1], hdr_icon=hdr[2], incident_id=inc.id,
            v_bg=v[0], v_bdr=v[1], v_color=v[2], v_txt=v[3], v_icon=v[4], v_title=v[5], v_msg=v[6],
            detected_at=fmt_ts(inc.created_at), approved_by=inc.approved_by or "—",
            shutdown_at=fmt_ts(inc.approved_at),
            resolved_at=fmt_ts(inc.defense_end), duration=dur,
            actions_html=actions_html,
            reco_html=recon_html + reco_html + forensic_html + rollback_html + legal_html,
            report_time=datetime.now().strftime("%d/%m/%Y %H:%M"),
        )

        if self.defense_mode == "immediate":
            subject = f"{'✅' if is_ok else '⚠️'} [CGS] {inc.id} — {'Threat neutralized' if is_ok else 'Action taken — review needed'}"
        else:
            subject = f"{'✅' if is_ok else '⚠️'} [CGS] Report {inc.id} — {v[5]}"

        # Send to admins — with attachments if enabled
        if admin_recipients:
            attachments = []
            if forensic_path and self.attach_forensic_file:
                attachments.append(forensic_path)
            if complaint_pdf_path and self.include_legal_info:
                attachments.append(complaint_pdf_path)
            ok = self._smtp_with_attachment(admin_recipients, subject, html,
                                            attachments=attachments)
            inc.report_sent = ok

        # Send to user WITHOUT attachment and WITHOUT legal section
        if user_recipient:
            # Simplified version for user
            user_html = REPORT_EMAIL.format(
                hdr1=hdr[0], hdr2=hdr[1], hdr_icon=hdr[2], incident_id=inc.id,
                v_bg=v[0], v_bdr=v[1], v_color=v[2], v_txt=v[3], v_icon=v[4], v_title=v[5], v_msg=v[6],
                detected_at=fmt_ts(inc.created_at), approved_by=inc.approved_by or "—",
                shutdown_at=fmt_ts(inc.approved_at),
                resolved_at=fmt_ts(inc.defense_end), duration=dur,
                actions_html=actions_html,
                reco_html=reco_html,
                report_time=datetime.now().strftime("%d/%m/%Y %H:%M"),
            )
            self._smtp([user_recipient], subject, user_html)

    def _smtp(self, to: list[str], subject: str, html: str) -> bool:
        """Send simple HTML email (no attachment)."""
        return self._smtp_with_attachment(to, subject, html, attachments=[])

    def _smtp_with_attachment(self, to: list[str], subject: str, html: str,
                               attachments: list = None) -> bool:
        """Send HTML email with optional attachments."""
        if not self.smtp_server or not to:
            return False
        attachments = attachments or []

        msg = MIMEMultipart("mixed")
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(to)

        # Message body
        body = MIMEMultipart("alternative")
        text = re.sub(r"<[^>]+>", "", html)
        text = re.sub(r"\s+", " ", text).strip()
        body.attach(MIMEText(text, "plain", "utf-8"))
        body.attach(MIMEText(html, "html", "utf-8"))
        msg.attach(body)

        # Attachments
        for filepath in attachments:
            if not filepath or not os.path.exists(filepath):
                continue
            try:
                fname = os.path.basename(filepath)
                # Detect MIME type
                if fname.endswith(".pdf"):
                    mime_main, mime_sub = "application", "pdf"
                elif fname.endswith(".json"):
                    mime_main, mime_sub = "application", "json"
                else:
                    mime_main, mime_sub = "application", "octet-stream"

                with open(filepath, "rb") as f:
                    part = MIMEBase(mime_main, mime_sub)
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={fname}")
                msg.attach(part)
                logger.info("📎 Attachment : %s (%.1f Ko)",
                           fname, os.path.getsize(filepath) / 1024)
            except Exception as e:
                logger.warning("Attachment '%s' failede : %s", filepath, e)

        try:
            if self.smtp_port == 465:
                srv = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, timeout=15)
            else:
                srv = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=15)
                if self.smtp_tls:
                    srv.starttls()
            if self.smtp_user:
                srv.login(self.smtp_user, self.smtp_password)
            srv.send_message(msg)
            srv.quit()
            self._stats["emails_sent"] += 1
            return True
        except Exception as e:
            logger.error("SMTP: %s", e)
            self._stats["emails_failed"] += 1
            return False

    # ══════════════════════════════════════════════
    # API
    # ══════════════════════════════════════════════
    def _evict_oldest(self):
        """Remove oldest resolved incidents when cache exceeds MAX_INCIDENTS. Must hold _lock."""
        resolved = sorted(
            [(iid, inc) for iid, inc in self._incidents.items()
             if inc.status in ("RESOLVED", "RISK_REMAINING", "REJECTED", "EXPIRED")],
            key=lambda x: x[1].created_at,
        )
        to_remove = len(self._incidents) - self.MAX_INCIDENTS
        for i in range(min(to_remove, len(resolved))):
            iid = resolved[i][0]
            inc = self._incidents.pop(iid, None)
            if inc:
                self._by_token.pop(inc.token, None)
        if to_remove > 0:
            logger.info("Evicted %d oldest resolved incidents (cache: %d/%d)",
                       min(to_remove, len(resolved)), len(self._incidents), self.MAX_INCIDENTS)

    def _get_by_token(self, token):
        iid = self._by_token.get(token)
        if not iid:
            return None
        inc = self._incidents.get(iid)
        if not inc:
            return None
        # Check token expiration
        if inc.created_at and (time.time() - inc.created_at) > self.token_ttl:
            logger.warning("Token expired for incident %s (age=%ds, ttl=%ds)",
                          inc.id, int(time.time() - inc.created_at), self.token_ttl)
            return None
        return inc

    def get_active_incidents(self):
        with self._lock:
            return [i.to_dict() for i in self._incidents.values()
                    if i.status in ("AWAITING_ADMIN", "MITIGATING")]

    def get_all_incidents(self, limit=50):
        with self._lock:
            s = sorted(self._incidents.values(), key=lambda i: i.created_at, reverse=True)
            return [i.to_dict() for i in s[:limit]]

    def get_incident(self, iid):
        inc = self._incidents.get(iid)
        return inc.to_dict() if inc else None

    @property
    def stats(self):
        with self._lock:
            by_s = {}
            for i in self._incidents.values():
                by_s[i.status] = by_s.get(i.status, 0) + 1
        return {**self._stats, "by_status": by_s,
                "timeout_min": self.timeout_min, "auto_approve": self.timeout_auto,
                "email_ok": self.email_enabled and bool(self.smtp_server)}
