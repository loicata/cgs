"""CGS — Daemon with active defense."""
import logging, os, signal, ssl, sys, threading, time
from datetime import datetime, timedelta
import schedule
from core.config import Config
from core.database import init_db, Alert, Flow, DnsLog, db
from core.alerts import AlertEngine
from core.discovery import NetworkDiscovery
from core.sniffer import PacketSniffer
from core.health import HealthChecker
from core.defense import DefenseEngine
from analyzers.threat_engine import ThreatEngine
from analyzers.correlator import Correlator

class Daemon:
    def __init__(self, cfg_path=None):
        self.cfg = Config(cfg_path)
        self._log_setup()
        self.log = logging.getLogger("cgs.daemon")
        self.log.info("=" * 50)
        self.log.info("  CGS v2.2.3 - Active Defense")
        self.log.info("=" * 50)
        init_db(self.cfg.get("general.data_dir"))
        self.alerter = AlertEngine(self.cfg)

        # Dynamic MAC ↔ IP table (survives DHCP changes)
        from core.mac_resolver import MacIpResolver
        self.mac_resolver = MacIpResolver(self.cfg, self.alerter.fire)

        # Multi-factor identity (resists MAC spoofing)
        from core.host_identity import HostIdentityEngine
        self.identity = HostIdentityEngine(self.cfg, self.alerter.fire)

        self.defense = DefenseEngine(self.cfg, self.alerter.fire, self.mac_resolver)
        self.engine = ThreatEngine(self.cfg, self.alerter.fire)

        from core.incident import IncidentResponseEngine
        self.incident = IncidentResponseEngine(self.cfg, self.alerter.fire, self.defense, self.mac_resolver)

        self.correlator = Correlator(self.cfg, self.alerter.fire, self.defense, self.engine, self.incident)
        self.discovery = NetworkDiscovery(self.cfg, self.alerter.fire, self.mac_resolver, self.identity)

        # Advanced detection orchestrator (wraps ThreatEngine with plugin detectors)
        from analyzers.orchestrator import DetectorOrchestrator
        self.orchestrator = DetectorOrchestrator(
            self.cfg, self.alerter.fire, self.engine,
            getattr(self, 'false_positives', None),
            getattr(self, 'threat_intel', None))

        # Sniffer feeds the orchestrator (which delegates to ThreatEngine + advanced detectors)
        self.sniffer = PacketSniffer(self.cfg, self.orchestrator.on_event, self.identity)
        self.health = HealthChecker(self.cfg, self.alerter.fire)

        # Kill chain detector
        from core.killchain import KillChainDetector
        self.killchain = KillChainDetector(self.cfg, self.alerter.fire, self.incident.create_incident)

        # Hash-chained audit log (tamper-proof)
        from core.extended import HashChainAudit, SIEMExporter, ThreatIntel, FalsePositiveManager, HotRules, WeeklyReport, BackupManager
        self.audit_chain = HashChainAudit(self.cfg)
        self.siem = SIEMExporter(self.cfg)
        self.threat_intel = ThreatIntel(self.cfg)
        self.false_positives = FalsePositiveManager(self.cfg)
        self.hot_rules = HotRules(self.cfg)
        self.weekly_report = WeeklyReport(self.cfg)
        self.backup_mgr = BackupManager(self.cfg)

        # ── Threat intelligence feeds (auto-download, bloom filter) ──
        from core.threat_feeds import ThreatFeedManager, HoneypotService
        self.threat_feeds = ThreatFeedManager(self.cfg)
        self.honeypot = HoneypotService(self.cfg, self.alerter.fire)

        # ── Resilience: self-protection under load ──
        from core.resilience import DegradedMode, SelfMonitor, BufferGuard, SafeBackup, enable_wal_mode

        # SQLite WAL mode: allows concurrent reads during writes
        db_path = os.path.join(self.cfg.get("general.data_dir", "/var/lib/cgs/data"), "cgs.db")
        enable_wal_mode(db_path)

        self.degraded = DegradedMode(self.cfg, self.alerter.fire)
        self.self_monitor = SelfMonitor(self.cfg, self.alerter.fire, self.degraded)
        self.buffer_guard = BufferGuard(self.cfg, self.alerter.fire)
        self.safe_backup = SafeBackup(self.cfg, self.backup_mgr, self.degraded)

        # ── Advanced hardening ──
        from core.hardening import TLSAutoGen, LoginGuard, ApprovalPIN, IntegrityCheck, FirewallVerifier, SSHHardener

        # Verify code integrity at startup
        integrity = IntegrityCheck.verify(alert_fn=self.alerter.fire)
        if not integrity.get("ok") and not integrity.get("note"):
            self.log.error("⚠️ CODE INTEGRITY CHECK FAILED — possible tampering!")

        # SSH hardening: verify password auth is disabled if keys exist
        ssh_hardener = SSHHardener(alert_fn=self.alerter.fire)
        ssh_status = ssh_hardener.verify()
        if not ssh_status.get("secure", True):
            self.log.error("⚠️ SSH SECURITY DEGRADED: %s", "; ".join(ssh_status.get("issues", [])))
        self.ssh_hardener = ssh_hardener

        # OS-level hardening verification
        from core.os_hardening import OSHardener
        self.os_hardener = OSHardener(alert_fn=self.alerter.fire)
        os_status = self.os_hardener.verify()
        if not os_status.get("secure", True):
            self.log.warning("OS hardening drift: %d issues", len(os_status.get("issues", [])))

        self.login_guard = LoginGuard(self.cfg)
        self.approval_pin = ApprovalPIN()
        self.incident.approval_pin = self.approval_pin  # Wire into incident engine
        self.firewall_verifier = FirewallVerifier(self.cfg, self.alerter.fire, self.defense)

        # TLS cert for web server
        self._tls_cert, self._tls_key = TLSAutoGen.ensure_cert(self.cfg)

        # Wire audit chain and SIEM into alert engine
        orig_fire = self.alerter.fire
        def _enhanced_fire(**kwargs):
            orig_fire(**kwargs)
            self.audit_chain.log(
                event=kwargs.get("title", ""),
                detail=kwargs.get("detail", ""),
                source=kwargs.get("source", ""),
                severity=kwargs.get("severity", 5),
                ip=kwargs.get("src_ip", "") or kwargs.get("dst_ip", ""),
            )
            self.siem.export(
                severity=kwargs.get("severity", 5),
                category=kwargs.get("category", ""),
                title=kwargs.get("title", ""),
                src_ip=kwargs.get("src_ip", ""),
                dst_ip=kwargs.get("dst_ip", ""),
                detail=kwargs.get("detail", ""),
            )
            # Feed kill chain detector
            self.killchain.on_alert(
                src_ip=kwargs.get("src_ip", ""),
                category=kwargs.get("category", ""),
                detail=kwargs.get("detail", ""),
                dst_ip=kwargs.get("dst_ip", ""),
                severity=kwargs.get("severity", 5),
            )
        self.alerter.fire = _enhanced_fire

        # Suricata — optional, only if a channel is configured
        self._suricata_enabled = bool(
            self.cfg.get("suricata.eve_file") or
            self.cfg.get("suricata.syslog_port") or
            self.cfg.get("suricata.tcp_port")
        )
        self.suricata = None
        if self._suricata_enabled:
            from core.suricata_ingest import SuricataIngester
            self.suricata = SuricataIngester(self.cfg, self.correlator.on_suricata_event)
            self.log.info("Suricata module enabled.")
        else:
            self.log.info("Suricata module disabled (no channel configured).")

        self._running = False

    def _log_setup(self):
        """Configure logging with sanitized formatter."""
        ld = self.cfg.get("general.log_dir")
        os.makedirs(ld, exist_ok=True)
        lv = getattr(logging, self.cfg.get("general.log_level", "INFO").upper(), logging.INFO)
        from core.security import SanitizedFormatter
        fmt = SanitizedFormatter(
            "%(asctime)s │ %(levelname)-8s │ %(name)-24s │ %(message)s", datefmt="%H:%M:%S")
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        fh = logging.FileHandler(os.path.join(ld, "cgs.log"), encoding="utf-8")
        fh.setFormatter(fmt)
        root = logging.getLogger("cgs")
        root.setLevel(lv)
        root.addHandler(sh)
        root.addHandler(fh)
        logging.getLogger("werkzeug").setLevel(logging.WARNING)

    def start(self):
        """Start the daemon and all subsystems."""
        self._running = True
        signal.signal(signal.SIGTERM, self._sig)
        signal.signal(signal.SIGINT, self._sig)
        from core.security import harden_permissions
        harden_permissions()

        # Layer 2: Thread supervisor
        from core.safety import Supervisor
        self.supervisor = Supervisor(alert_fn=self.alerter.fire)

        self.sniffer.start()
        # Register sniffer thread for supervision (critical = restart if dies)
        if self.sniffer._thread:
            self.supervisor.watch("sniffer", self.sniffer._thread,
                                 target=self.sniffer._sniff_loop, critical=True)
        # Start honeypot decoy services
        self.honeypot.start()
        if self._suricata_enabled:
            self.suricata.start()
        # Drop root privileges after binding raw sockets
        from core.security import drop_privileges
        drop_privileges(self.cfg.get("general.run_as_user", "cgs"))
        self._safe("arp_sweep", self.discovery.arp_sweep)
        self._safe("port_scan", self.discovery.port_scan)
        ai = self.cfg.get("discovery.arp_interval", 300)
        pi = self.cfg.get("discovery.port_scan_interval", 3600)

        # ── Scheduled tasks (degraded-mode-aware) ──
        # Essential tasks: always run, even under load
        schedule.every(5).minutes.do(self._safe, "health", self.health.check_all)
        schedule.every(60).seconds.do(self._safe, "self_monitor", self.self_monitor.check)
        schedule.every(60).seconds.do(self._safe, "buffer_guard", self.buffer_guard.check)
        schedule.every(2).minutes.do(self._safe, "fw_verify", self._verify_firewall)
        schedule.every(30).minutes.do(self._safe, "ssh_verify", lambda: self.ssh_hardener.verify())
        schedule.every().hour.do(self._safe, "os_verify", lambda: self.os_hardener.verify())
        schedule.every(5).minutes.do(self._safe, "detector_health", self.orchestrator.check_health)

        # Non-essential tasks: suspended in degraded mode
        schedule.every(ai).seconds.do(self._guarded, "arp", self.discovery.arp_sweep)
        schedule.every(pi).seconds.do(self._guarded, "ports", self.discovery.port_scan)
        schedule.every(15).minutes.do(self._guarded, "baseline", self.engine.update_baseline)
        schedule.every(5).minutes.do(self._guarded, "anomaly", self.engine.check_anomalies)
        schedule.every().day.at("02:00").do(self._guarded, "compliance_snapshot", self._capture_compliance_snapshot)
        schedule.every().day.at("03:00").do(self._guarded, "cleanup", self._cleanup)
        schedule.every().day.at("04:00").do(self._guarded, "backup", self._safe_backup)
        schedule.every().monday.at("08:00").do(self._guarded, "weekly", self._send_weekly_report)
        if self.cfg.get("web.enabled", True):
            self._start_web()
        modes = []
        if self.cfg.get("suricata.eve_file"):
            modes.append(f"eve:{self.cfg.get('suricata.eve_file')}")
        if self.cfg.get("suricata.syslog_port"):
            modes.append(f"syslog:{self.cfg.get('suricata.syslog_port')}")
        if self.cfg.get("suricata.tcp_port"):
            modes.append(f"tcp:{self.cfg.get('suricata.tcp_port')}")
        self.alerter.fire(severity=5, source="system", category="startup",
            title="Sentinel started",
            detail=f"FW={self.defense._fw_backend} Defense={'ON' if self.defense.enabled else 'OFF'} Suricata={'|'.join(modes) if modes else 'disabled'}",
            notify=False)
        self.log.info("Sentinel operational.")
        # Capture initial firewall state for tamper detection
        self.firewall_verifier.snapshot_expected()
        while self._running:
            try:
                schedule.run_pending()
                time.sleep(1)
            except Exception as e:
                self.log.error("Scheduler: %s", e)
                time.sleep(5)

    def _safe(self, name, fn, *a):
        def r():
            try:
                fn(*a)
            except Exception as e:
                self.log.error("[%s] %s", name, e)
                from core.safety import _CrashTracker
                _CrashTracker.record(f"task:{name}")
        threading.Thread(target=r, daemon=True, name=name).start()

    def _guarded(self, name, fn, *a):
        """Like _safe but skips task if in degraded mode."""
        if not self.degraded.should_run(name):
            return
        self._safe(name, fn, *a)

    def _safe_backup(self):
        """Run backup at low I/O priority, skip if degraded."""
        self.safe_backup.run()

    def _verify_firewall(self):
        """Periodically check firewall rules haven't been tampered with."""
        self.firewall_verifier.verify()

    def _start_web(self):
        from web.app import init_app
        mods = {"discovery":self.discovery,"sniffer":self.sniffer,"engine":self.engine,
                "health":self.health,"alerter":self.alerter,"defense":self.defense,
                "correlator":self.correlator,"incident":self.incident,
                "identity":self.identity,"mac_resolver":self.mac_resolver,
                "client_queue":self.incident.client_queue,
                "killchain":self.killchain,"audit_chain":self.audit_chain,
                "siem":self.siem,"threat_intel":self.threat_intel,
                "false_positives":self.false_positives,"hot_rules":self.hot_rules,
                "backup":self.backup_mgr,"weekly_report":self.weekly_report,
                "degraded":self.degraded,"self_monitor":self.self_monitor,
                "orchestrator":self.orchestrator,
                "supervisor":self.supervisor,
                "threat_feeds":self.threat_feeds,
                "honeypot":self.honeypot,
                "login_guard":self.login_guard,"approval_pin":self.approval_pin,
                "firewall_verifier":self.firewall_verifier,
                "os_hardener":self.os_hardener,
                "config":self.cfg}
        if self.suricata:
            mods["suricata"] = self.suricata
        flask_app, sio = init_app(self.cfg, mods)
        h, p = self.cfg.get("web.host","127.0.0.1"), self.cfg.get("web.port",8443)
        def run():
            ctx = None
            c, k = self._tls_cert, self._tls_key
            if not c or not k:
                c, k = self.cfg.get("web.ssl_cert"), self.cfg.get("web.ssl_key")
            if c and k and os.path.exists(c) and os.path.exists(k):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(c, k)
            self.log.info("Dashboard: http%s://%s:%d", "s" if ctx else "", h, p)
            sio.run(flask_app, host=h, port=p, ssl_context=ctx, debug=False, use_reloader=False, log_output=False)
        threading.Thread(target=run, daemon=True, name="web").start()

    def _capture_compliance_snapshot(self):
        """Daily compliance score snapshot for trend tracking."""
        from core.grc import capture_compliance_snapshot
        mods = {
            "sniffer": self.sniffer, "engine": self.engine, "health": self.health,
            "defense": self.defense, "orchestrator": self.orchestrator,
            "threat_feeds": self.threat_feeds, "honeypot": self.honeypot,
            "audit_chain": self.audit_chain, "killchain": self.killchain,
            "false_positives": self.false_positives, "config": self.cfg,
        }
        capture_compliance_snapshot(self.cfg, mods)

    def _cleanup(self):
        """Purge old data based on retention settings."""
        now = datetime.now()
        with db.atomic():
            a = Alert.delete().where(
                Alert.ts < now - timedelta(days=self.cfg.get("retention.alerts_days", 90))).execute()
            f = Flow.delete().where(
                Flow.ts < now - timedelta(days=self.cfg.get("retention.flows_days", 14))).execute()
            d = DnsLog.delete().where(
                DnsLog.ts < now - timedelta(days=self.cfg.get("retention.events_days", 30))).execute()
        if a or f or d:
            self.log.info("Purge: %d alerts, %d flows, %d DNS", a, f, d)

    def _send_weekly_report(self):
        if not self.weekly_report.enabled:
            return
        try:
            html = self.weekly_report.generate_html(7)
            admins = self.cfg.get("email.admin_recipients", [])
            if admins and self.cfg.get("email.enabled"):
                self.incident._smtp(admins, "[CGS] Weekly Security Report", html)
                self.log.info("Weekly report sent to %d admins", len(admins))
        except Exception as e:
            self.log.error("Weekly report failed: %s", e)

    def _sig(self, sig, _):
        self.log.info("Signal %d", sig)
        # Force exit after 5s if clean shutdown hangs
        def _force_exit():
            self.log.warning("Clean shutdown timed out — forcing exit")
            os._exit(1)
        t = threading.Timer(5.0, _force_exit)
        t.daemon = True
        t.start()
        self.stop()
    def stop(self):
        self._running = False
        self.sniffer.stop()
        if self.suricata:
            self.suricata.stop()
        self.identity.save_all()
        self.alerter.fire(severity=5,source="system",category="shutdown",title="Sentinel stopped",notify=False)
        self.log.info("Clean shutdown.")
        sys.exit(0)
