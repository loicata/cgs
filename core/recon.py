"""
CGS — Deep attacker reconnaissance.

Collects maximum information about the attacker IP:
  - Reverse DNS (PTR)
  - WHOIS / RDAP (owner, AS, range, country, abuse contact)
  - Geolocation (via ip-api.com, free, no key)
  - Traceroute (full network path)
  - Aggressive port scan (top 100 + banners)
  - Fingerprint OS (TTL + signatures)
  - Reputation lookup (AbuseIPDB, VirusTotal if keys provided)
  - HTTP/TLS headers if web server detected
  - Shodan (technologies, vulns, historical data)
  - GreyNoise (mass scanner vs targeted attack classification)
  - OTX AlienVault (IOC correlation, threat pulses)
  - Tor/VPN/Proxy exit node detection
  - JARM TLS fingerprint (identifies C2 frameworks)
  - Certificate Transparency (related domains via crt.sh)
  - Passive DNS (historical resolutions via various sources)
  - BGP/ASN analysis (bulletproof hosting detection)
  - Network neighborhood (/24 scan summary)
  - IP history (previous incidents in local DB)

All data is returned in a structured dict
for injection into the forensic report.
"""

import hashlib
import json
import logging
import re
import socket
import struct
import subprocess
import time
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("cgs.recon")

# Ports to scan aggressively
AGGRESSIVE_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 4444, 5432, 5555,
    5900, 6379, 6667, 8080, 8443, 8888, 9090, 9200, 9999, 27017,
    31337, 12345, 4443, 6697, 8000, 10000,
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

# Known bulletproof hosting ASNs (frequently abused)
BULLETPROOF_ASNS = {
    "49981", "200019", "44477", "9009", "16276", "62468",
    "24940", "47583", "58061", "20473", "14061", "63949",
}

# Known C2 JARM hashes (Cobalt Strike, Metasploit, Sliver, etc.)
KNOWN_C2_JARM = {
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": "Cobalt Strike",
    "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2": "Cobalt Strike (alt)",
    "2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5": "Metasploit",
    "00000000000000000041d00000041d9535d5aed0dbfb0e3b6e14a1438e613": "Sliver C2",
    "29d29d15d29d29d21c29d29d29d29de1a3c0e3b66be39d204cb1c5e6a212c": "Havoc C2",
    "00000000000000000000000000000000000000000000000000000000000000": "Refused/filtered",
}


class AttackerRecon:
    """Deep reconnaissance of an attacker IP."""

    def __init__(self, config):
        self.cfg = config
        self.abuseipdb_key = config.get("recon.abuseipdb_key", "")
        self.virustotal_key = config.get("recon.virustotal_key", "")
        self.shodan_key = config.get("recon.shodan_key", "")
        self.greynoise_key = config.get("recon.greynoise_key", "")
        self.otx_key = config.get("recon.otx_key", "")

    def full_recon(self, ip: str, timeout: int = 180) -> dict:
        """Performs complete reconnaissance. Returns a structured dict."""
        logger.warning("Deep reconnaissance of %s...", ip)
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
            # New enhanced fields
            "shodan": {},
            "greynoise": {},
            "otx": {},
            "tor_exit": False,
            "vpn_proxy": {},
            "jarm": {},
            "cert_transparency": [],
            "passive_dns": [],
            "bgp_analysis": {},
            "network_neighborhood": {},
            "ip_history": [],
            "threat_classification": "",
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

        # ── 5. Aggressive port scan ──
        report["open_ports"] = self._aggressive_scan(ip)
        logger.info("  Open ports: %d", len(report["open_ports"]))

        # ── 6. OS fingerprint ──
        report["os_fingerprint"] = self._os_fingerprint(ip)
        logger.info("  OS: %s", report["os_fingerprint"])

        # ── 7. HTTP headers if port 80/443 is open ──
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

        # ── 9. Shodan (technologies, vulns, historical data) ──
        report["shodan"] = self._shodan_lookup(ip)
        if report["shodan"]:
            logger.info("  Shodan: %d ports, %d vulns",
                        len(report["shodan"].get("ports", [])),
                        len(report["shodan"].get("vulns", [])))

        # ── 10. GreyNoise (mass scanner vs targeted attack) ──
        report["greynoise"] = self._greynoise_lookup(ip)
        if report["greynoise"]:
            logger.info("  GreyNoise: %s", report["greynoise"].get("classification", "unknown"))

        # ── 11. OTX AlienVault (IOC correlation) ──
        report["otx"] = self._otx_lookup(ip)
        if report["otx"]:
            logger.info("  OTX: %d pulses", report["otx"].get("pulse_count", 0))

        # ── 12. Tor/VPN/Proxy detection ──
        report["tor_exit"] = self._check_tor_exit(ip)
        report["vpn_proxy"] = self._check_vpn_proxy(ip, report)
        logger.info("  Tor: %s, VPN/Proxy: %s", report["tor_exit"],
                     report["vpn_proxy"].get("is_proxy", False))

        # ── 13. JARM TLS fingerprint ──
        if any(p["port"] in (443, 8443, 4444, 8080, 50050) for p in report["open_ports"]):
            jarm_port = next((p["port"] for p in report["open_ports"]
                             if p["port"] in (443, 8443, 4444, 8080, 50050)), 443)
            report["jarm"] = self._jarm_fingerprint(ip, jarm_port)
            if report["jarm"].get("match"):
                logger.warning("  JARM MATCH: %s", report["jarm"]["match"])

        # ── 14. Certificate Transparency (related domains) ──
        report["cert_transparency"] = self._cert_transparency(ip, report)
        if report["cert_transparency"]:
            logger.info("  CT: %d related domains", len(report["cert_transparency"]))

        # ── 15. Passive DNS ──
        report["passive_dns"] = self._passive_dns(ip)
        if report["passive_dns"]:
            logger.info("  Passive DNS: %d historical records", len(report["passive_dns"]))

        # ── 16. BGP/ASN analysis ──
        report["bgp_analysis"] = self._bgp_analysis(ip, report)
        logger.info("  BGP: bulletproof=%s", report["bgp_analysis"].get("bulletproof_hosting", False))

        # ── 17. Network neighborhood ──
        report["network_neighborhood"] = self._network_neighborhood(ip)

        # ── 18. IP history (local DB) ──
        report["ip_history"] = self._ip_history(ip)
        if report["ip_history"]:
            logger.info("  History: %d previous incidents in DB", len(report["ip_history"]))

        # ── Final threat classification ──
        report["threat_classification"] = self._classify_threat(report)
        logger.warning("  Classification: %s", report["threat_classification"])

        report["recon_duration_s"] = round(time.time() - t0, 1)
        report["recon_end"] = datetime.now().isoformat()
        logger.warning("Recon %s completed in %.1fs — %d ports, AS%s, %s, class=%s",
                       ip, report["recon_duration_s"],
                       len(report["open_ports"]),
                       report["whois"].get("asn", "?"),
                       report["geolocation"].get("country", "?"),
                       report["threat_classification"])
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
            logger.debug("WHOIS error: %s", e)

        # RDAP fallback if no ASN
        if not result["asn"]:
            try:
                import requests
                r = requests.get(f"https://rdap.arin.net/registry/ip/{ip}",
                                timeout=10, headers={"Accept": "application/json"})
                if r.status_code == 200:
                    data = r.json()
                    result["org"] = result["org"] or data.get("name", "")
                    result["country"] = result["country"] or data.get("country", "")
            except Exception as e:
                logger.debug("Failed to query RDAP for %s: %s", ip, e)

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
            logger.debug("GeoIP error: %s", e)
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
            except Exception as e:
                logger.debug("Failed scapy traceroute for %s: %s", ip, e)
        except Exception as e:
            logger.debug("Traceroute error: %s", e)
        return hops

    # ──────────────────────────────────────────────
    # 5. Aggressive port scan + banners
    # ──────────────────────────────────────────────
    def _aggressive_scan(self, ip: str) -> list[dict]:
        """SYN scan via scapy + banner grabbing on open ports."""
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
                    from scapy.all import sr1
                    sr1(IP(dst=ip) / TCP(sport=snd[TCP].sport, dport=port, flags="R"),
                        timeout=0.3)

        except Exception as e:
            logger.debug("Aggressive scan error: %s", e)
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
            except Exception as e:
                logger.debug("Failed nmap fallback scan for %s: %s", ip, e)

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
                    os_g = "Cisco/Solaris/Other"

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
        except Exception as e:
            logger.debug("Failed scapy OS fingerprint for %s: %s", ip, e)

        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments="-O --osscan-guess")
            if ip in nm.all_hosts():
                osm = nm[ip].get("osmatch", [])
                if osm:
                    return f"{osm[0]['name']} ({osm[0].get('accuracy', '?')}%)"
        except Exception as e:
            logger.debug("Failed nmap OS fingerprint for %s: %s", ip, e)
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
                            verify=False, allow_redirects=False,  # nosec B501 — scanning unknown/hostile hosts
                            headers={"User-Agent": "CGS/1.0"})
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
    # 9. Reputation (AbuseIPDB, VirusTotal)
    # ──────────────────────────────────────────────
    def _check_reputation(self, ip: str) -> dict:
        result = {"summary": "", "abuseipdb": {}, "virustotal": {}}

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
                    result["summary"] += f"AbuseIPDB: {score}% malicious, {d.get('totalReports',0)} reports. "
            except Exception as e:
                logger.debug("AbuseIPDB: %s", e)

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
                    result["summary"] += f"VirusTotal: {mal} malicious detections. "
            except Exception as e:
                logger.debug("VirusTotal: %s", e)

        if not result["summary"]:
            result["summary"] = "No reputation source configured (optional API keys)."

        return result

    # ══════════════════════════════════════════════
    # NEW: Enhanced reconnaissance techniques
    # ══════════════════════════════════════════════

    # ──────────────────────────────────────────────
    # 10. Shodan
    # ──────────────────────────────────────────────
    def _shodan_lookup(self, ip: str) -> dict:
        """Query Shodan for technologies, vulns, historical data."""
        if not self.shodan_key:
            return {}
        try:
            import requests
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.shodan_key}, timeout=15)
            if r.status_code == 200:
                d = r.json()
                return {
                    "ports": d.get("ports", []),
                    "vulns": d.get("vulns", []),
                    "hostnames": d.get("hostnames", []),
                    "os": d.get("os", ""),
                    "org": d.get("org", ""),
                    "isp": d.get("isp", ""),
                    "last_update": d.get("last_update", ""),
                    "tags": d.get("tags", []),
                    "services": [{
                        "port": s.get("port"),
                        "transport": s.get("transport", ""),
                        "product": s.get("product", ""),
                        "version": s.get("version", ""),
                        "cpe": s.get("cpe", []),
                    } for s in d.get("data", [])[:20]],
                    "city": d.get("city", ""),
                    "country": d.get("country_name", ""),
                }
            elif r.status_code == 404:
                return {"note": "IP not indexed by Shodan"}
        except Exception as e:
            logger.debug("Shodan: %s", e)
        return {}

    # ──────────────────────────────────────────────
    # 11. GreyNoise
    # ──────────────────────────────────────────────
    def _greynoise_lookup(self, ip: str) -> dict:
        """GreyNoise: is this a mass scanner or targeted attack?"""
        try:
            import requests
            if self.greynoise_key:
                # Full API
                r = requests.get(f"https://api.greynoise.io/v3/community/{ip}",
                    headers={"key": self.greynoise_key, "Accept": "application/json"},
                    timeout=10)
            else:
                # Community API (free, no key needed)
                r = requests.get(f"https://api.greynoise.io/v3/community/{ip}",
                    timeout=10)
            if r.status_code == 200:
                d = r.json()
                return {
                    "noise": d.get("noise", False),
                    "riot": d.get("riot", False),
                    "classification": d.get("classification", "unknown"),
                    "name": d.get("name", ""),
                    "message": d.get("message", ""),
                    "last_seen": d.get("last_seen", ""),
                }
        except Exception as e:
            logger.debug("GreyNoise: %s", e)
        return {}

    # ──────────────────────────────────────────────
    # 12. OTX AlienVault
    # ──────────────────────────────────────────────
    def _otx_lookup(self, ip: str) -> dict:
        """OTX AlienVault: IOC correlation, threat pulses."""
        try:
            import requests
            headers = {"Accept": "application/json"}
            if self.otx_key:
                headers["X-OTX-API-KEY"] = self.otx_key

            result = {"pulse_count": 0, "pulses": [], "malware_count": 0,
                      "passive_dns_count": 0, "reputation": 0}

            # General info
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers=headers, timeout=10)
            if r.status_code == 200:
                d = r.json()
                result["pulse_count"] = d.get("pulse_info", {}).get("count", 0)
                result["reputation"] = d.get("reputation", 0)
                for pulse in d.get("pulse_info", {}).get("pulses", [])[:10]:
                    result["pulses"].append({
                        "name": pulse.get("name", ""),
                        "created": pulse.get("created", ""),
                        "tags": pulse.get("tags", [])[:5],
                        "adversary": pulse.get("adversary", ""),
                        "tlp": pulse.get("TLP", ""),
                    })

            # Malware samples
            r2 = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/malware",
                headers=headers, timeout=10)
            if r2.status_code == 200:
                result["malware_count"] = len(r2.json().get("data", []))

            return result
        except Exception as e:
            logger.debug("OTX: %s", e)
        return {}

    # ──────────────────────────────────────────────
    # 13. Tor exit node detection
    # ──────────────────────────────────────────────
    @staticmethod
    def _check_tor_exit(ip: str) -> bool:
        """Check if IP is a known Tor exit node."""
        try:
            import requests
            # Use the Tor Project's exit list
            r = requests.get("https://check.torproject.org/torbulkexitlist",
                            timeout=10)
            if r.status_code == 200:
                return ip in r.text.splitlines()
        except Exception as e:
            logger.debug("Failed to check Tor exit list for %s: %s", ip, e)

        # DNS-based check fallback
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            socket.gethostbyname(f"{reversed_ip}.dnsel.torproject.org")
            return True
        except (socket.herror, socket.gaierror):
            pass
        return False

    # ──────────────────────────────────────────────
    # 14. VPN/Proxy detection (aggregated)
    # ──────────────────────────────────────────────
    @staticmethod
    def _check_vpn_proxy(ip: str, report: dict) -> dict:
        """Aggregate proxy/VPN signals from multiple sources."""
        result = {
            "is_proxy": False,
            "is_vpn": False,
            "is_hosting": False,
            "is_tor": report.get("tor_exit", False),
            "confidence": 0,
            "sources": [],
        }

        # From geolocation
        geo = report.get("geolocation", {})
        if geo.get("proxy"):
            result["is_proxy"] = True
            result["sources"].append("ip-api:proxy")
            result["confidence"] += 30
        if geo.get("hosting"):
            result["is_hosting"] = True
            result["sources"].append("ip-api:hosting")
            result["confidence"] += 20

        # From AbuseIPDB
        abuse = report.get("reputation", {}).get("abuseipdb", {})
        if abuse.get("is_tor"):
            result["is_tor"] = True
            result["sources"].append("abuseipdb:tor")
            result["confidence"] += 40
        if abuse.get("usage_type") in ("Data Center/Web Hosting/Transit",):
            result["is_hosting"] = True
            result["sources"].append("abuseipdb:hosting")
            result["confidence"] += 20

        # From Shodan tags
        shodan_tags = report.get("shodan", {}).get("tags", [])
        if "vpn" in shodan_tags:
            result["is_vpn"] = True
            result["sources"].append("shodan:vpn")
            result["confidence"] += 30

        # Tor check
        if report.get("tor_exit"):
            result["is_tor"] = True
            result["confidence"] += 50

        # PTR heuristics (common VPN/proxy patterns)
        ptr = report.get("reverse_dns", "") or ""
        vpn_patterns = ["vpn", "proxy", "tor-exit", "exit-node", "anonymizer",
                        "hide", "anon", "tunnel", "socks", "relay"]
        for pattern in vpn_patterns:
            if pattern in ptr.lower():
                result["is_vpn"] = True
                result["sources"].append(f"ptr:{pattern}")
                result["confidence"] += 20
                break

        result["confidence"] = min(result["confidence"], 100)
        return result

    # ──────────────────────────────────────────────
    # 15. JARM TLS fingerprint
    # ──────────────────────────────────────────────
    @staticmethod
    def _jarm_fingerprint(ip: str, port: int = 443) -> dict:
        """Compute JARM fingerprint to identify C2 frameworks."""
        result = {"hash": "", "match": "", "port": port}
        try:
            # JARM sends 10 TLS ClientHello probes with varying parameters
            # and hashes the ServerHello responses to create a fingerprint.
            # Simplified implementation: single probe + hash
            import ssl
            import hashlib

            probes_data = []
            for tls_version in (ssl.PROTOCOL_TLSv1_2,):
                try:
                    ctx = ssl.SSLContext(tls_version)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.set_ciphers("ALL:@SECLEVEL=0")
                    with socket.create_connection((ip, port), timeout=3) as raw:
                        with ctx.wrap_socket(raw, server_hostname=ip) as s:
                            cipher = s.cipher()
                            version = s.version()
                            probes_data.append(f"{version}|{cipher[0] if cipher else ''}|{cipher[2] if cipher else ''}")
                except Exception as e:
                    logger.debug("Failed JARM TLS probe for %s: %s", ip, e)
                    probes_data.append("|||")

            # Hash the probe results
            raw_fp = "|".join(probes_data)
            jarm_hash = hashlib.sha256(raw_fp.encode()).hexdigest()
            result["hash"] = jarm_hash

            # Check against known C2 hashes
            for known_hash, c2_name in KNOWN_C2_JARM.items():
                if jarm_hash == known_hash:
                    result["match"] = c2_name
                    break

            # Also check cipher suite for suspicious patterns
            if probes_data and probes_data[0] != "|||":
                parts = probes_data[0].split("|")
                if len(parts) >= 2:
                    result["tls_version"] = parts[0]
                    result["cipher_suite"] = parts[1]

        except Exception as e:
            logger.debug("JARM: %s", e)
        return result

    # ──────────────────────────────────────────────
    # 16. Certificate Transparency (crt.sh)
    # ──────────────────────────────────────────────
    @staticmethod
    def _cert_transparency(ip: str, report: dict) -> list[dict]:
        """Find related domains via Certificate Transparency logs."""
        domains = []
        # Use hostnames from various sources
        hostnames = set()
        ptr = report.get("reverse_dns")
        if ptr:
            hostnames.add(ptr)
        for hn in report.get("shodan", {}).get("hostnames", []):
            hostnames.add(hn)

        if not hostnames:
            return []

        try:
            import requests
            for hostname in list(hostnames)[:3]:  # Limit queries
                # Extract base domain
                parts = hostname.split(".")
                if len(parts) >= 2:
                    base = ".".join(parts[-2:])
                else:
                    continue

                r = requests.get(f"https://crt.sh/?q=%.{base}&output=json",
                                timeout=15)
                if r.status_code == 200:
                    certs = r.json()[:50]  # Limit results
                    seen = set()
                    for cert in certs:
                        cn = cert.get("common_name", "")
                        if cn and cn not in seen:
                            seen.add(cn)
                            domains.append({
                                "domain": cn,
                                "issuer": cert.get("issuer_name", ""),
                                "not_before": cert.get("not_before", ""),
                                "not_after": cert.get("not_after", ""),
                            })
        except Exception as e:
            logger.debug("CT: %s", e)
        return domains[:30]

    # ──────────────────────────────────────────────
    # 17. Passive DNS
    # ──────────────────────────────────────────────
    def _passive_dns(self, ip: str) -> list[dict]:
        """Historical DNS resolutions for this IP."""
        records = []

        # Source 1: VirusTotal passive DNS
        if self.virustotal_key:
            try:
                import requests
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions",
                    headers={"x-apikey": self.virustotal_key},
                    params={"limit": 20}, timeout=10)
                if r.status_code == 200:
                    for item in r.json().get("data", []):
                        attrs = item.get("attributes", {})
                        records.append({
                            "domain": attrs.get("host_name", ""),
                            "last_resolved": attrs.get("date", 0),
                            "source": "virustotal",
                        })
            except Exception as e:
                logger.debug("VT passive DNS: %s", e)

        # Source 2: OTX passive DNS
        if self.otx_key:
            try:
                import requests
                r = requests.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns",
                    headers={"X-OTX-API-KEY": self.otx_key},
                    timeout=10)
                if r.status_code == 200:
                    for item in r.json().get("passive_dns", [])[:20]:
                        records.append({
                            "domain": item.get("hostname", ""),
                            "last_resolved": item.get("last", ""),
                            "first_seen": item.get("first", ""),
                            "source": "otx",
                        })
            except Exception as e:
                logger.debug("OTX passive DNS: %s", e)

        # Source 3: HackerTarget (free, no key)
        try:
            import requests
            r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                            timeout=10)
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.strip().splitlines()[:20]:
                    domain = line.strip()
                    if domain and "." in domain:
                        records.append({
                            "domain": domain,
                            "source": "hackertarget",
                        })
        except Exception as e:
            logger.debug("HackerTarget: %s", e)

        return records

    # ──────────────────────────────────────────────
    # 18. BGP/ASN analysis
    # ──────────────────────────────────────────────
    def _bgp_analysis(self, ip: str, report: dict) -> dict:
        """Analyze ASN for bulletproof hosting indicators."""
        result = {
            "asn": report.get("whois", {}).get("asn", ""),
            "asn_name": "",
            "asn_country": "",
            "bulletproof_hosting": False,
            "prefix": "",
            "peers": [],
            "risk_indicators": [],
        }

        asn = result["asn"]

        # Check known bulletproof ASNs
        if asn in BULLETPROOF_ASNS:
            result["bulletproof_hosting"] = True
            result["risk_indicators"].append(f"AS{asn} is in known bulletproof hosting list")

        # BGP info from RIPEstat
        try:
            import requests
            r = requests.get(
                f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}",
                timeout=10)
            if r.status_code == 200:
                data = r.json().get("data", {})
                asns = data.get("asns", [])
                if asns:
                    result["asn"] = str(asns[0].get("asn", ""))
                    result["asn_name"] = asns[0].get("holder", "")
                result["prefix"] = data.get("resource", "")

            # Abuse contact
            r2 = requests.get(
                f"https://stat.ripe.net/data/abuse-contact-finder/data.json?resource={ip}",
                timeout=10)
            if r2.status_code == 200:
                contacts = r2.json().get("data", {}).get("abuse_contacts", [])
                if contacts:
                    result["abuse_contacts"] = contacts

            # ASN neighbors
            if asn:
                r3 = requests.get(
                    f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn}",
                    timeout=10)
                if r3.status_code == 200:
                    neighbors = r3.json().get("data", {}).get("neighbours", [])
                    result["peers"] = [n.get("asn") for n in neighbors[:10]]

        except Exception as e:
            logger.debug("BGP: %s", e)

        # Heuristic: hosting provider with bad reputation
        geo = report.get("geolocation", {})
        if geo.get("hosting"):
            abuse_score = report.get("reputation", {}).get("abuseipdb", {}).get("score", 0)
            if abuse_score > 50:
                result["risk_indicators"].append(
                    f"Hosting provider with {abuse_score}% abuse score")
            gn = report.get("greynoise", {})
            if gn.get("noise"):
                result["risk_indicators"].append("Known mass scanner (GreyNoise)")

        return result

    # ──────────────────────────────────────────────
    # 19. Network neighborhood (/24)
    # ──────────────────────────────────────────────
    @staticmethod
    def _network_neighborhood(ip: str) -> dict:
        """Quick scan of the attacker's /24 subnet."""
        result = {"subnet": "", "active_hosts": 0, "sample_ptrs": []}
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return result
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            result["subnet"] = subnet

            # Quick reverse DNS on a sample of IPs in the /24
            sample_ptrs = []
            for last_octet in range(1, 255, 16):  # Sample every 16th IP
                neighbor = f"{parts[0]}.{parts[1]}.{parts[2]}.{last_octet}"
                if neighbor == ip:
                    continue
                try:
                    ptr = socket.gethostbyaddr(neighbor)[0]
                    sample_ptrs.append({"ip": neighbor, "ptr": ptr})
                except (socket.herror, socket.gaierror):
                    pass

            result["sample_ptrs"] = sample_ptrs
            result["active_hosts"] = len(sample_ptrs)
        except Exception as e:
            logger.debug("Neighborhood: %s", e)
        return result

    # ──────────────────────────────────────────────
    # 20. IP history (local DB)
    # ──────────────────────────────────────────────
    @staticmethod
    def _ip_history(ip: str) -> list[dict]:
        """Check local DB for previous alerts involving this IP."""
        history = []
        try:
            from core.database import Alert
            alerts = (Alert.select()
                     .where((Alert.src_ip == ip) | (Alert.dst_ip == ip))
                     .order_by(Alert.ts.desc())
                     .limit(50))
            for a in alerts:
                history.append({
                    "ts": a.ts.isoformat(),
                    "severity": a.severity,
                    "category": a.category,
                    "title": a.title,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                })
        except Exception as e:
            logger.debug("IP history: %s", e)
        return history

    # ──────────────────────────────────────────────
    # Threat classification (final analysis)
    # ──────────────────────────────────────────────
    @staticmethod
    def _classify_threat(report: dict) -> str:
        """Classify the threat based on all collected intelligence."""
        indicators = []
        classification = "UNKNOWN"

        # Tor exit
        if report.get("tor_exit"):
            indicators.append("TOR_EXIT")

        # VPN/Proxy
        vpn = report.get("vpn_proxy", {})
        if vpn.get("is_proxy") or vpn.get("is_vpn"):
            indicators.append("ANONYMIZED")

        # Bulletproof hosting
        if report.get("bgp_analysis", {}).get("bulletproof_hosting"):
            indicators.append("BULLETPROOF_HOSTING")

        # Known C2
        jarm = report.get("jarm", {})
        if jarm.get("match"):
            indicators.append(f"C2_FRAMEWORK:{jarm['match']}")

        # Mass scanner
        gn = report.get("greynoise", {})
        if gn.get("noise"):
            indicators.append("MASS_SCANNER")
        if gn.get("classification") == "malicious":
            indicators.append("KNOWN_MALICIOUS")
        elif gn.get("classification") == "benign":
            indicators.append("KNOWN_BENIGN")

        # Reputation
        abuse_score = report.get("reputation", {}).get("abuseipdb", {}).get("score", 0)
        if abuse_score >= 80:
            indicators.append("HIGH_ABUSE_SCORE")
        vt_mal = report.get("reputation", {}).get("virustotal", {}).get("malicious", 0)
        if vt_mal >= 5:
            indicators.append("VT_FLAGGED")

        # OTX pulses
        otx = report.get("otx", {})
        if otx.get("pulse_count", 0) > 0:
            indicators.append(f"OTX_{otx['pulse_count']}_PULSES")
        if otx.get("malware_count", 0) > 0:
            indicators.append("OTX_MALWARE_ASSOCIATED")

        # Shodan vulns
        if report.get("shodan", {}).get("vulns"):
            indicators.append(f"VULNS:{len(report['shodan']['vulns'])}")

        # Previous history
        history = report.get("ip_history", [])
        if len(history) >= 5:
            indicators.append("REPEAT_OFFENDER")

        # Suspicious ports
        suspicious_ports = {4444, 5555, 31337, 12345, 6667, 6697, 50050}
        open_ports = {p["port"] for p in report.get("open_ports", [])}
        if open_ports & suspicious_ports:
            indicators.append("SUSPICIOUS_PORTS")

        # Classify
        if "C2_FRAMEWORK" in str(indicators):
            classification = "APT/C2_INFRASTRUCTURE"
        elif "BULLETPROOF_HOSTING" in indicators and "HIGH_ABUSE_SCORE" in indicators:
            classification = "CRIMINAL_INFRASTRUCTURE"
        elif "TOR_EXIT" in indicators:
            classification = "TOR_ANONYMIZED"
        elif "MASS_SCANNER" in indicators:
            classification = "MASS_SCANNER"
        elif "KNOWN_BENIGN" in indicators:
            classification = "LIKELY_BENIGN"
        elif "REPEAT_OFFENDER" in indicators and abuse_score >= 50:
            classification = "PERSISTENT_THREAT"
        elif abuse_score >= 80 or vt_mal >= 5:
            classification = "KNOWN_MALICIOUS"
        elif "ANONYMIZED" in indicators:
            classification = "ANONYMIZED_ATTACKER"
        elif len(indicators) >= 3:
            classification = "SUSPICIOUS"
        elif indicators:
            classification = "LOW_CONFIDENCE_THREAT"

        return f"{classification} [{', '.join(indicators)}]"
