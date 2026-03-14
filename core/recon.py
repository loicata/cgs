"""
CyberGuard Sentinel — Deep attacker reconnaissance d'attaque.

Collecte le maximum d'informations sur l'IP attaquante :
  - Reverse DNS (PTR)
  - WHOIS / RDAP (owner, AS, range, country, abuse contact)
  - Geolocation (via ip-api.com, free, no key)
  - Traceroute (chemin network complet)
  - Aggressive port scan (top 100 + banners)
  - Fingerprint OS (TTL + signatures)
  - Reputation lookup (AbuseIPDB, VirusTotal if keys provided)
  - Headers HTTP/TLS si serveur web detected

All data is returned in a structured dict
pour injection dans le rapport forensique.
"""

import json
import logging
import re
import socket
import struct
import subprocess
import time
from datetime import datetime
from typing import Optional

logger = logging.getLogger("cyberguard.recon")

# Ports to scan aggressively
AGGRESSIVE_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 4444, 5432, 5555,
    5900, 6379, 6667, 8080, 8443, 8888, 9090, 9200, 9999, 27017,
    31337, 12345, 4443, 6697, 8000, 8888, 10000,
]

BANNER_SIGS = [
    (re.compile(rb"^SSH-(\S+)", re.I), "ssh"),
    (re.compile(rb"^220[- ](.{0,80})", re.I), "ftp/smtp"),
    (re.compile(rb"HTTP/(\d\.\d)\s+(\d+)", re.I), "http"),
    (re.compile(rb"^\* OK (.{0,80})", re.I), "imap"),
    (re.compile(rb"^\+OK (.{0,60})", re.I), "pop3"),
    (re.compile(rb"mysql|MariaDB", re.I), "mysql"),
    (re.compile(rb"PostgreSQL", re.I), "postgresql"),
    (re.compile(rb"redis_version:(\S+)", re.I), "redis"),
    (re.compile(rb"MongoDB", re.I), "mongodb"),
    (re.compile(rb"Apache|nginx|IIS|LiteSpeed", re.I), "webserver"),
]


class AttackerRecon:
    """Reconnaissance approfondie d'une IP attaquante."""

    def __init__(self, config):
        self.cfg = config
        self.abuseipdb_key = config.get("recon.abuseipdb_key", "")
        self.virustotal_key = config.get("recon.virustotal_key", "")

    def full_recon(self, ip: str, timeout: int = 120) -> dict:
        """Performs complete reconnaissance. Returns a structured dict."""
        logger.warning("🔍 Reconnaissance approfondie de %s…", ip)
        t0 = time.time()

        report = {
            "target_ip": ip,
            "recon_start": datetime.now().isoformat(),
            "reverse_dns": None,
            "whois": {},
            "geolocation": {},
            "traceroute": [],
            "open_ports": [],
            "os_fingerprint": "",
            "reputation": {},
            "http_headers": {},
            "tls_info": {},
            "raw_whois": "",
            "recon_duration_s": 0,
        }

        # ── 1. Reverse DNS ──
        report["reverse_dns"] = self._reverse_dns(ip)
        logger.info("  PTR: %s", report["reverse_dns"])

        # ── 2. WHOIS / RDAP ──
        report["whois"] = self._whois(ip)
        report["raw_whois"] = report["whois"].get("raw", "")
        logger.info("  WHOIS: AS%s %s (%s)",
                     report["whois"].get("asn", "?"),
                     report["whois"].get("org", "?"),
                     report["whois"].get("country", "?"))

        # ── 3. Geolocation ──
        report["geolocation"] = self._geolocate(ip)
        geo = report["geolocation"]
        logger.info("  GEO: %s, %s (%s) — lat=%s lon=%s",
                     geo.get("city", "?"), geo.get("country", "?"),
                     geo.get("isp", "?"),
                     geo.get("lat", "?"), geo.get("lon", "?"))

        # ── 4. Traceroute ──
        report["traceroute"] = self._traceroute(ip)
        logger.info("  Traceroute: %d hops", len(report["traceroute"]))

        # ── 5. Scan de ports agressif ──
        report["open_ports"] = self._aggressive_scan(ip)
        logger.info("  Open ports: %d", len(report["open_ports"]))

        # ── 6. OS fingerprint ──
        report["os_fingerprint"] = self._os_fingerprint(ip)
        logger.info("  OS: %s", report["os_fingerprint"])

        # ── 7. HTTP headers si port 80/443 ouvert ──
        open_port_nums = {p["port"] for p in report["open_ports"]}
        if 80 in open_port_nums or 8080 in open_port_nums:
            port = 80 if 80 in open_port_nums else 8080
            report["http_headers"] = self._http_headers(ip, port, ssl=False)
        if 443 in open_port_nums or 8443 in open_port_nums:
            port = 443 if 443 in open_port_nums else 8443
            report["tls_info"] = self._tls_info(ip, port)
            if not report["http_headers"]:
                report["http_headers"] = self._http_headers(ip, port, ssl=True)

        # ── 8. Reputation (AbuseIPDB, VirusTotal) ──
        report["reputation"] = self._check_reputation(ip)
        if report["reputation"]:
            logger.info("  Reputation: %s", report["reputation"].get("summary", ""))

        report["recon_duration_s"] = round(time.time() - t0, 1)
        report["recon_end"] = datetime.now().isoformat()
        logger.warning("🔍 Recon %s completed en %.1fs — %d ports, AS%s, %s",
                       ip, report["recon_duration_s"],
                       len(report["open_ports"]),
                       report["whois"].get("asn", "?"),
                       report["geolocation"].get("country", "?"))
        return report

    # ──────────────────────────────────────────────
    # 1. Reverse DNS
    # ──────────────────────────────────────────────
    @staticmethod
    def _reverse_dns(ip: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None

    # ──────────────────────────────────────────────
    # 2. WHOIS via system command + RDAP fallback
    # ──────────────────────────────────────────────
    @staticmethod
    def _whois(ip: str) -> dict:
        result = {"raw": "", "org": "", "asn": "", "country": "",
                  "netrange": "", "abuse_contact": "", "description": ""}
        # Commande whois
        try:
            proc = subprocess.run(["whois", ip], capture_output=True,
                                  text=True, timeout=15)
            raw = proc.stdout
            result["raw"] = raw

            for line in raw.splitlines():
                ll = line.lower().strip()
                if ll.startswith("orgname:") or ll.startswith("org-name:"):
                    result["org"] = line.split(":", 1)[1].strip()
                elif ll.startswith("country:") and not result["country"]:
                    result["country"] = line.split(":", 1)[1].strip().upper()
                elif "origin" in ll and "as" in ll.lower():
                    m = re.search(r"AS(\d+)", line, re.I)
                    if m:
                        result["asn"] = m.group(1)
                elif ll.startswith("netrange:") or ll.startswith("inetnum:"):
                    result["netrange"] = line.split(":", 1)[1].strip()
                elif "abuse" in ll and "@" in line:
                    email = re.search(r"[\w.+-]+@[\w.-]+\.\w+", line)
                    if email:
                        result["abuse_contact"] = email.group()
                elif ll.startswith("descr:") and not result["description"]:
                    result["description"] = line.split(":", 1)[1].strip()
        except FileNotFoundError:
            logger.debug("whois not installed")
        except Exception as e:
            logger.debug("WHOIS erreur: %s", e)

        # RDAP fallback si pas d'ASN
        if not result["asn"]:
            try:
                import requests
                r = requests.get(f"https://rdap.arin.net/registry/ip/{ip}",
                                timeout=10, headers={"Accept": "application/json"})
                if r.status_code == 200:
                    data = r.json()
                    result["org"] = result["org"] or data.get("name", "")
                    result["country"] = result["country"] or data.get("country", "")
            except Exception:
                pass

        return result

    # ──────────────────────────────────────────────
    # 3. Geolocation (ip-api.com, free)
    # ──────────────────────────────────────────────
    @staticmethod
    def _geolocate(ip: str) -> dict:
        try:
            import requests
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719",
                            timeout=8)
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    return {
                        "country": d.get("country", ""),
                        "country_code": d.get("countryCode", ""),
                        "region": d.get("regionName", ""),
                        "city": d.get("city", ""),
                        "zip": d.get("zip", ""),
                        "lat": d.get("lat"),
                        "lon": d.get("lon"),
                        "timezone": d.get("timezone", ""),
                        "isp": d.get("isp", ""),
                        "org": d.get("org", ""),
                        "as": d.get("as", ""),
                        "mobile": d.get("mobile", False),
                        "proxy": d.get("proxy", False),
                        "hosting": d.get("hosting", False),
                    }
        except Exception as e:
            logger.debug("GeoIP erreur: %s", e)
        return {}

    # ──────────────────────────────────────────────
    # 4. Traceroute
    # ──────────────────────────────────────────────
    @staticmethod
    def _traceroute(ip: str, max_hops: int = 30) -> list[dict]:
        hops = []
        try:
            proc = subprocess.run(
                ["traceroute", "-n", "-m", str(max_hops), "-w", "2", ip],
                capture_output=True, text=True, timeout=60)
            for line in proc.stdout.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2:
                    hop_num = parts[0]
                    hop_ip = parts[1] if parts[1] != "*" else None
                    rtt = None
                    for p in parts[2:]:
                        try:
                            rtt = float(p)
                            break
                        except ValueError:
                            continue
                    hops.append({
                        "hop": int(hop_num) if hop_num.isdigit() else 0,
                        "ip": hop_ip,
                        "rtt_ms": rtt,
                    })
        except FileNotFoundError:
            # Fallback scapy traceroute
            try:
                from scapy.all import traceroute as scapy_tr, conf
                conf.verb = 0
                ans, _ = scapy_tr(ip, maxttl=max_hops, timeout=2)
                for snd, rcv in ans:
                    hops.append({
                        "hop": snd.ttl,
                        "ip": rcv.src,
                        "rtt_ms": round((rcv.time - snd.sent_time) * 1000, 1),
                    })
            except Exception:
                pass
        except Exception as e:
            logger.debug("Traceroute erreur: %s", e)
        return hops

    # ──────────────────────────────────────────────
    # 5. Aggressive port scan + banners
    # ──────────────────────────────────────────────
    def _aggressive_scan(self, ip: str) -> list[dict]:
        """Scan SYN via scapy + banner grabbing sur les ports ouverts."""
        open_ports = []
        try:
            from scapy.all import IP, TCP, RandShort, sr, conf
            conf.verb = 0

            pkt = IP(dst=ip) / TCP(sport=RandShort(), dport=AGGRESSIVE_PORTS, flags="S")
            ans, _ = sr(pkt, timeout=3, retry=0)

            for snd, rcv in ans:
                if rcv.haslayer(TCP) and rcv[TCP].flags == 0x12:
                    port = rcv[TCP].sport
                    svc, banner = self._grab_banner(ip, port)
                    open_ports.append({
                        "port": port,
                        "service": svc,
                        "banner": banner[:300],
                    })
                    # RST
                    from scapy.all import sr1
                    sr1(IP(dst=ip) / TCP(sport=snd[TCP].sport, dport=port, flags="R"),
                        timeout=0.3)

        except Exception as e:
            logger.debug("Scan agressif erreur: %s", e)
            # Fallback nmap
            try:
                import nmap
                nm = nmap.PortScanner()
                port_str = ",".join(str(p) for p in AGGRESSIVE_PORTS)
                nm.scan(hosts=ip, arguments=f"-sS -sV -T4 -p {port_str}")
                if ip in nm.all_hosts():
                    for proto in nm[ip].all_protocols():
                        for port in nm[ip][proto]:
                            info = nm[ip][proto][port]
                            if info["state"] == "open":
                                open_ports.append({
                                    "port": port,
                                    "service": info.get("name", ""),
                                    "banner": f"{info.get('product', '')} {info.get('version', '')}".strip(),
                                })
            except Exception:
                pass

        return open_ports

    @staticmethod
    def _grab_banner(ip: str, port: int, timeout: float = 3.0) -> tuple[str, str]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = b""
            try:
                banner = s.recv(1024)
            except socket.timeout:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n")
                try:
                    banner = s.recv(1024)
                except socket.timeout:
                    pass
            s.close()
            if banner:
                for regex, svc in BANNER_SIGS:
                    if regex.search(banner):
                        return svc, banner[:300].decode("utf-8", errors="replace")
            return "unknown", banner[:300].decode("utf-8", errors="replace") if banner else ""
        except Exception:
            return "unknown", ""

    # ──────────────────────────────────────────────
    # 6. OS fingerprint
    # ──────────────────────────────────────────────
    @staticmethod
    def _os_fingerprint(ip: str) -> str:
        try:
            from scapy.all import IP, ICMP, TCP, sr1, conf
            conf.verb = 0
            # ICMP TTL
            reply = sr1(IP(dst=ip) / ICMP(), timeout=2)
            if reply:
                ttl = reply.ttl
                if ttl <= 32:
                    os_g = "Windows 9x/ME"
                elif ttl <= 64:
                    os_g = "Linux/Unix/macOS"
                elif ttl <= 128:
                    os_g = "Windows"
                else:
                    os_g = "Cisco/Solaris/Autre"

                # TCP window size pour affiner
                syn_reply = sr1(IP(dst=ip) / TCP(dport=80, flags="S"), timeout=2)
                win = ""
                if syn_reply and syn_reply.haslayer(TCP):
                    w = syn_reply[TCP].window
                    if w == 65535:
                        win = " (FreeBSD/macOS probable)"
                    elif w == 64240:
                        win = " (Windows 10/11 probable)"
                    elif w == 29200:
                        win = " (Recent Linux probable)"

                return f"{os_g} (TTL={ttl}){win}"
        except Exception:
            pass

        # Fallback nmap
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments="-O --osscan-guess")
            if ip in nm.all_hosts():
                osm = nm[ip].get("osmatch", [])
                if osm:
                    return f"{osm[0]['name']} ({osm[0].get('accuracy', '?')}%)"
        except Exception:
            pass
        return "Unknown"

    # ──────────────────────────────────────────────
    # 7. HTTP headers
    # ──────────────────────────────────────────────
    @staticmethod
    def _http_headers(ip: str, port: int, ssl: bool = False) -> dict:
        try:
            import requests
            proto = "https" if ssl else "http"
            r = requests.get(f"{proto}://{ip}:{port}/", timeout=5,
                            verify=False, allow_redirects=False,
                            headers={"User-Agent": "CyberGuard-Sentinel/1.0"})
            return {
                "status_code": r.status_code,
                "server": r.headers.get("Server", ""),
                "powered_by": r.headers.get("X-Powered-By", ""),
                "content_type": r.headers.get("Content-Type", ""),
                "all_headers": dict(r.headers),
            }
        except Exception:
            return {}

    # ──────────────────────────────────────────────
    # 8. TLS info
    # ──────────────────────────────────────────────
    @staticmethod
    def _tls_info(ip: str, port: int = 443) -> dict:
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    cert = s.getpeercert(binary_form=False)
                    cipher = s.cipher()
                    return {
                        "version": s.version(),
                        "cipher": cipher[0] if cipher else "",
                        "cipher_bits": cipher[2] if cipher else 0,
                        "subject": str(cert.get("subject", "")) if cert else "",
                        "issuer": str(cert.get("issuer", "")) if cert else "",
                        "not_after": str(cert.get("notAfter", "")) if cert else "",
                        "san": str(cert.get("subjectAltName", "")) if cert else "",
                    }
        except Exception:
            return {}

    # ──────────────────────────────────────────────
    # 9. Reputation
    # ──────────────────────────────────────────────
    def _check_reputation(self, ip: str) -> dict:
        result = {"summary": "", "abuseipdb": {}, "virustotal": {}}

        # AbuseIPDB
        if self.abuseipdb_key:
            try:
                import requests
                r = requests.get("https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                    headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                    timeout=10)
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    result["abuseipdb"] = {
                        "score": d.get("abuseConfidenceScore", 0),
                        "total_reports": d.get("totalReports", 0),
                        "last_reported": d.get("lastReportedAt", ""),
                        "isp": d.get("isp", ""),
                        "usage_type": d.get("usageType", ""),
                        "domain": d.get("domain", ""),
                        "country": d.get("countryCode", ""),
                        "is_tor": d.get("isTor", False),
                    }
                    score = d.get("abuseConfidenceScore", 0)
                    result["summary"] += f"AbuseIPDB: {score}% malveillant, {d.get('totalReports',0)} signalements. "
            except Exception as e:
                logger.debug("AbuseIPDB: %s", e)

        # VirusTotal
        if self.virustotal_key:
            try:
                import requests
                r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": self.virustotal_key}, timeout=10)
                if r.status_code == 200:
                    attrs = r.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    result["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "reputation": attrs.get("reputation", 0),
                        "as_owner": attrs.get("as_owner", ""),
                        "country": attrs.get("country", ""),
                    }
                    mal = stats.get("malicious", 0)
                    result["summary"] += f"VirusTotal: {mal} malicious detections."
            except Exception as e:
                logger.debug("VirusTotal: %s", e)

        if not result["summary"]:
            result["summary"] = "No reputation source configured (optional API keys)."

        return result
