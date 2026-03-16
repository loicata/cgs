"""
CGS — Ingestion Suricata EVE JSON.

Three reception modes:
  1. Tail eve.json file (if NFS/sshfs mounted from firewall)
  2. Syslog UDP/TCP (the firewall sends its logs here)
  3. HTTP webhook (the firewall POSTs the alerts)

Normalizes each alert and injects it into the correlation engine.
"""

import json
import logging
import os
import select
import socket
import struct
import threading
import time
from datetime import datetime
from typing import Callable, Optional

logger = logging.getLogger("cgs.suricata")

# Mapping severity Suricata → Sentinel (1=crit … 5=info)
SURICATA_SEV = {1: 1, 2: 2, 3: 3, 4: 4}

# Suricata categories to monitor closely
HIGH_CATEGORIES = {
    "Attempted Administrator Privilege Gain", "Attempted User Privilege Gain",
    "Executable Code was Detected", "A Network Trojan was Detected",
    "Successful Administrator Privilege Gain", "Successful User Privilege Gain",
    "Web Application Attack", "Potentially Bad Traffic",
    "Attempted Denial of Service", "Misc Attack",
    "A suspicious filename was detected", "A suspicious string was detected",
}

# Actions Suricata
ACTION_ALLOWED = "allowed"
ACTION_BLOCKED = "blocked"


class SuricataEvent:
    """Normalized Suricata event."""
    __slots__ = (
        "timestamp", "event_type", "src_ip", "src_port", "dst_ip", "dst_port",
        "proto", "alert_signature", "alert_sid", "alert_severity", "alert_category",
        "alert_action", "app_proto", "http_hostname", "http_url", "http_method",
        "dns_query", "dns_type", "tls_sni", "tls_version", "tls_subject",
        "flow_bytes_toserver", "flow_bytes_toclient",
        "fileinfo_filename", "fileinfo_size",
        "raw",
    )

    def __init__(self, data: dict):
        self.raw = data
        self.timestamp = data.get("timestamp", "")
        self.event_type = data.get("event_type", "")
        self.src_ip = data.get("src_ip", "")
        self.src_port = data.get("src_port", 0)
        self.dst_ip = data.get("dest_ip", "")
        self.dst_port = data.get("dest_port", 0)
        self.proto = data.get("proto", "")
        self.app_proto = data.get("app_proto", "")

        # Alert
        alert = data.get("alert", {})
        self.alert_signature = alert.get("signature", "")
        self.alert_sid = alert.get("signature_id", 0)
        self.alert_severity = alert.get("severity", 4)
        self.alert_category = alert.get("category", "")
        self.alert_action = alert.get("action", "")

        # HTTP
        http = data.get("http", {})
        self.http_hostname = http.get("hostname", "")
        self.http_url = http.get("url", "")
        self.http_method = http.get("http_method", "")

        # DNS
        dns = data.get("dns", {})
        self.dns_query = dns.get("rrname", "") or dns.get("query", "")
        self.dns_type = dns.get("rrtype", "")

        # TLS
        tls = data.get("tls", {})
        self.tls_sni = tls.get("sni", "")
        self.tls_version = tls.get("version", "")
        self.tls_subject = tls.get("subject", "")

        # Flow
        flow = data.get("flow", {})
        self.flow_bytes_toserver = flow.get("bytes_toserver", 0)
        self.flow_bytes_toclient = flow.get("bytes_toclient", 0)

        # Fileinfo
        fi = data.get("fileinfo", {})
        self.fileinfo_filename = fi.get("filename", "")
        self.fileinfo_size = fi.get("size", 0)

    @property
    def is_alert(self) -> bool:
        return self.event_type == "alert"

    @property
    def is_high_risk(self) -> bool:
        return (self.alert_severity <= 2 or
                self.alert_category in HIGH_CATEGORIES)

    @property
    def sentinel_severity(self) -> int:
        return SURICATA_SEV.get(self.alert_severity, 3)

    def to_dict(self) -> dict:
        return {
            "ts": self.timestamp, "type": self.event_type,
            "src_ip": self.src_ip, "src_port": self.src_port,
            "dst_ip": self.dst_ip, "dst_port": self.dst_port,
            "proto": self.proto, "app_proto": self.app_proto,
            "sig": self.alert_signature, "sid": self.alert_sid,
            "severity": self.alert_severity, "category": self.alert_category,
            "action": self.alert_action,
            "http_host": self.http_hostname, "http_url": self.http_url,
            "dns_query": self.dns_query, "tls_sni": self.tls_sni,
        }


class SuricataIngester:
    """Ingests Suricata events through multiple channels."""

    def __init__(self, config, on_event: Callable[[SuricataEvent], None]):
        self.cfg = config
        self._on_event = on_event
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()

        self._stats = {
            "events_received": 0,
            "alerts_received": 0,
            "parse_errors": 0,
            "running": False,
        }

    def start(self):
        self._stop.clear()

        # Mode 1: Tail eve.json file
        eve_path = self.cfg.get("suricata.eve_file")
        if eve_path and os.path.exists(eve_path):
            t = threading.Thread(target=self._tail_file, args=(eve_path,),
                                 daemon=True, name="suri-file")
            t.start()
            self._threads.append(t)
            logger.info("Suricata ingestion: file %s", eve_path)

        # Mode 2: Syslog UDP
        syslog_port = self.cfg.get("suricata.syslog_port")
        if syslog_port:
            t = threading.Thread(target=self._syslog_udp, args=(int(syslog_port),),
                                 daemon=True, name="suri-syslog")
            t.start()
            self._threads.append(t)
            logger.info("Suricata ingestion: syslog UDP :%d", syslog_port)

        # Mode 3: TCP JSON stream
        tcp_port = self.cfg.get("suricata.tcp_port")
        if tcp_port:
            t = threading.Thread(target=self._tcp_listener, args=(int(tcp_port),),
                                 daemon=True, name="suri-tcp")
            t.start()
            self._threads.append(t)
            logger.info("Suricata ingestion: TCP :%d", tcp_port)

        if not self._threads:
            logger.warning("No Suricata channel configured. "
                           "Configure suricata.eve_file, suricata.syslog_port or suricata.tcp_port")
            return

        self._stats["running"] = True

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        self._stats["running"] = False
        logger.info("Suricata ingestion stopped (%d events received).",
                     self._stats["events_received"])

    # ──────────────────────────────────────────────
    # Mode 1: Tail file
    # ──────────────────────────────────────────────
    def _tail_file(self, path: str):
        """Follows the eve.json file in real-time."""
        try:
            with open(path, "r") as f:
                f.seek(0, 2)  # end of file
                while not self._stop.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.3)
                        # Check if file was rotated
                        try:
                            if os.fstat(f.fileno()).st_ino != os.stat(path).st_ino:
                                f.close()
                                time.sleep(1)
                                f = open(path, "r")
                        except Exception as e:
                            logger.warning("Failed to check eve.json file rotation: %s", e)
                        continue
                    self._process_line(line)
        except Exception as e:
            logger.error("Tail eve.json : %s", e)

    # ──────────────────────────────────────────────
    # Mode 2: Syslog UDP
    # ──────────────────────────────────────────────
    def _syslog_udp(self, port: int):
        """Receives Suricata logs via syslog UDP."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))  # nosec B104 — must listen on all interfaces for syslog
            sock.settimeout(2.0)
            logger.info("Syslog UDP listening on :%d", port)

            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                    message = data.decode("utf-8", errors="replace")
                    # Syslog may have a header — find the JSON
                    json_start = message.find("{")
                    if json_start >= 0:
                        self._process_line(message[json_start:])
                except socket.timeout:
                    continue
            sock.close()
        except Exception as e:
            logger.error("Syslog UDP : %s", e)

    # ──────────────────────────────────────────────
    # Mode 3: TCP JSON stream
    # ──────────────────────────────────────────────
    def _tcp_listener(self, port: int):
        """Receives JSON stream via TCP (one JSON object per line)."""
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))  # nosec B104 — must listen on all interfaces for TCP ingest
            srv.listen(5)
            srv.settimeout(2.0)
            logger.info("TCP listener listening on :%d", port)

            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                    logger.info("TCP connection from %s", addr)
                    t = threading.Thread(
                        target=self._handle_tcp_client, args=(conn,),
                        daemon=True)
                    t.start()
                except socket.timeout:
                    continue
            srv.close()
        except Exception as e:
            logger.error("TCP listener : %s", e)

    def _handle_tcp_client(self, conn: socket.socket):
        buf = b""
        conn.settimeout(5.0)
        try:
            while not self._stop.is_set():
                try:
                    data = conn.recv(8192)
                    if not data:
                        break
                    buf += data
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        self._process_line(line.decode("utf-8", errors="replace"))
                except socket.timeout:
                    continue
        except Exception as e:
            logger.debug("TCP client : %s", e)
        finally:
            conn.close()

    # ──────────────────────────────────────────────
    # Common processing
    # ──────────────────────────────────────────────
    def _process_line(self, line: str):
        line = line.strip()
        if not line:
            return
        try:
            data = json.loads(line)
            evt = SuricataEvent(data)
            self._stats["events_received"] += 1
            if evt.is_alert:
                self._stats["alerts_received"] += 1
            self._on_event(evt)
        except json.JSONDecodeError:
            self._stats["parse_errors"] += 1
        except Exception as e:
            logger.debug("Error process event : %s", e)

    @property
    def stats(self) -> dict:
        return dict(self._stats)
