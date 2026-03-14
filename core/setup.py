"""
CyberGuard Sentinel — Interactive setup wizard.

Used during installation (postinst) and accessible via:
  sudo cyberguard setup

Configure toutes les options :
  1. Network (sous-networkx, interface, exclusions)
  2. Suricata (optional — alert reception mode)
  3. Email (SMTP, admins, user directory)
  4. Active defense (thresholds, TTL, whitelist)
  5. Reconnaissance (API keys)
  6. Web interface (port, mot de passe)
  7. Data retention
"""

import getpass
import os
import re
import socket
import sys

import bcrypt
import yaml


# ═══════════════════════════════════════════════════
# Utilitaires d'affichage
# ═══════════════════════════════════════════════════

C = "\033[0;36m"
G = "\033[0;32m"
Y = "\033[0;33m"
R = "\033[0;31m"
B = "\033[1m"
N = "\033[0m"
DIM = "\033[2m"


def _banner(text: str):
    print(f"\n{C}{B}{'═' * 56}")
    print(f"  {text}")
    print(f"{'═' * 56}{N}\n")


def _section(num: int, total: int, title: str):
    print(f"\n{C}[{num}/{total}]{N} {B}{title}{N}")
    print(f"{DIM}{'─' * 50}{N}")


def _ask(prompt: str, default: str = "", required: bool = False) -> str:
    """Asks a question with a default value."""
    if default:
        display = f"  {prompt} [{B}{default}{N}] : "
    else:
        display = f"  {prompt} : "
    while True:
        val = input(display).strip()
        if not val:
            if default:
                return default
            if required:
                print(f"  {R}This value is required.{N}")
                continue
            return ""
        return val


def _ask_yn(prompt: str, default: bool = True) -> bool:
    """Yes/no question."""
    yn = "O/n" if default else "o/N"
    val = input(f"  {prompt} [{yn}] : ").strip().lower()
    if not val:
        return default
    return val in ("o", "oui", "y", "yes", "1")


def _ask_password(prompt: str) -> str:
    """Asks for a password (masked)."""
    while True:
        p1 = getpass.getpass(f"  {prompt} : ")
        if len(p1) < 4:
            print(f"  {R}Minimum 4 characters.{N}")
            continue
        p2 = getpass.getpass(f"  Confirmez : ")
        if p1 != p2:
            print(f"  {R}Passwords do not match.{N}")
            continue
        return p1


def _ask_choice(prompt: str, choices: list[str], default: int = 0) -> int:
    """Numbered choice."""
    for i, c in enumerate(choices):
        marker = f"{G}>{N}" if i == default else " "
        print(f"  {marker} {i + 1}. {c}")
    while True:
        val = input(f"  {prompt} [1-{len(choices)}, default={default + 1}] : ").strip()
        if not val:
            return default
        try:
            idx = int(val) - 1
            if 0 <= idx < len(choices):
                return idx
        except ValueError:
            pass
        print(f"  {R}Choix invalide.{N}")


def _ask_list(prompt: str, current: list = None) -> list[str]:
    """Saisie d'une liste (une valeur par ligne, vide pour terminer)."""
    print(f"  {prompt}")
    if current:
        print(f"  {DIM}Currently: {', '.join(current)}{N}")
    print(f"  {DIM}(one value per line, empty line to finish){N}")
    items = []
    while True:
        val = input(f"    > ").strip()
        if not val:
            break
        items.append(val)
    return items if items else (current or [])


def _validate_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def _validate_subnet(subnet: str) -> bool:
    try:
        parts = subnet.split("/")
        socket.inet_aton(parts[0])
        prefix = int(parts[1])
        return 0 <= prefix <= 32
    except (ValueError, IndexError, socket.error):
        return False


def _detect_interfaces() -> list[str]:
    """Detects available network interfaces."""
    try:
        return [i for i in os.listdir("/sys/class/net") if i != "lo"]
    except Exception:
        return []


def _detect_default_subnet() -> str:
    """Tente de deviner le sous-network local."""
    try:
        with open("/proc/net/route") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    iface = parts[0]
                    # Lire l'IP
                    import fcntl
                    import struct
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915,
                        struct.pack("256s", iface.encode()[:15]))[20:24])
                    s.close()
                    # Supposer /24
                    parts = ip.split(".")
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass
    return "192.168.1.0/24"


def _detect_server_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.100"


# ═══════════════════════════════════════════════════
# Assistant de configuration
# ═══════════════════════════════════════════════════

def _discover_hosts(subnets: list[str], iface: str, excludes: list[str],
                    server_ip: str) -> list[dict]:
    """
    ARP scan of network to discover all hosts.
    Used during installation AND from the TUI console.
    Returns une liste de {ip, mac, vendor, hostname, os_hint}.
    """
    hosts = []
    try:
        from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, conf
        conf.verb = 0
        from core.netutils import vendor_from_mac, guess_os_from_ttl
    except ImportError:
        print(f"  {R}scapy not available — scanning impossible.{N}")
        return []

    for subnet in subnets:
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            real_iface = iface if iface != "auto" else None
            answered, _ = srp(pkt, iface=real_iface, timeout=3, retry=1)

            for sent, rcv in answered:
                ip = rcv[ARP].psrc
                mac = rcv[ARP].hwsrc

                # Exclure le serveur Sentinel et les IPs exclues
                if ip == server_ip or ip in excludes:
                    continue

                vendor = vendor_from_mac(mac)
                os_hint = ""

                # Fingerprint OS par TTL
                try:
                    reply = sr1(IP(dst=ip) / ICMP(), timeout=1)
                    if reply and reply.haslayer(IP):
                        os_hint = guess_os_from_ttl(reply[IP].ttl)
                except Exception:
                    pass

                # Resolvedtion DNS inverse
                hostname = ""
                try:
                    import socket as _sock
                    hostname = _sock.gethostbyaddr(ip)[0]
                except Exception:
                    pass

                hosts.append({
                    "ip": ip, "mac": mac, "vendor": vendor,
                    "hostname": hostname, "os_hint": os_hint,
                })

        except PermissionError:
            print(f"  {R}Permission denied — run as root (sudo).{N}")
            return []
        except Exception as e:
            print(f"  {Y}Error scan {subnet} : {e}{N}")

    # Trier par IP
    hosts.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
    return hosts


# ═══════════════════════════════════════════════════
# Assistant de configuration
# ═══════════════════════════════════════════════════

def run_setup(config_path: str = "/etc/cyberguard/config.yaml",
              first_install: bool = False) -> dict:
    """
    Lance l'assistant interactive.
    Returns le dict de config complet.
    """
    _banner("⛨  CyberGuard Sentinel — Configuration")

    if first_install:
        print(f"  {G}Welcome! This wizard will configure your Sentinel.{N}")
        print(f"  {DIM}Press Enter to accept default values [in brackets].{N}")
    else:
        print(f"  {Y}Modifying existing configuration.{N}")
        print(f"  {DIM}Enter = keep current value.{N}")

    # Charger la config existante
    cfg = {}
    if os.path.exists(config_path):
        with open(config_path) as f:
            cfg = yaml.safe_load(f) or {}

    def _get(dotted, default=""):
        keys = dotted.split(".")
        v = cfg
        for k in keys:
            if isinstance(v, dict):
                v = v.get(k, None)
            else:
                return default
            if v is None:
                return default
        return v

    TOTAL = 9
    server_ip = _detect_server_ip()
    default_subnet = _detect_default_subnet()
    interfaces = _detect_interfaces()

    # ═══════════════════════════════════════════
    # 1. NETWORK
    # ═══════════════════════════════════════════
    _section(1, TOTAL, "Network to monitor")

    print(f"  {DIM}Subnet detected : {default_subnet}{N}")
    current_subnets = _get("network.subnets", [default_subnet])
    subnets = _ask_list(
        "Subnets to monitor (CIDR) :",
        current_subnets,
    )

    if interfaces:
        print(f"\n  Detected interfaces : {B}{', '.join(interfaces)}{N}")
    iface = _ask("Capture interface", _get("network.interface", "auto"))

    print(f"\n  {DIM}This server's IP : {server_ip}{N}")
    exclude_default = _get("network.exclude_ips", [server_ip])
    excludes = _ask_list("IPs to exclude from scans :", exclude_default)

    # ── Nmap ──
    nmap_installed = os.system("command -v nmap >/dev/null 2>&1") == 0
    use_nmap_default = _get("discovery.use_nmap", True)

    if nmap_installed:
        print(f"\n  {G}✓ Nmap detected.{N} Used for advanced service and OS detection.")
        use_nmap = _ask_yn("Keep nmap for advanced scans ?", use_nmap_default)
    else:
        print(f"\n  {DIM}Nmap not installed. It will be installed automatically.{N}")
        use_nmap = _ask_yn("Install nmap for advanced scans ?", use_nmap_default)

    if not use_nmap:
        print(f"  {Y}→ Nmap will be removed. Port scanning in scapy-only mode.{N}")

    # ═══════════════════════════════════════════
    # 2. SURICATA
    # ═══════════════════════════════════════════
    _section(2, TOTAL, "Suricata ingestion (optional)")

    print(f"  {DIM}Suricata enriches analysis but is not required.{N}")
    print(f"  {DIM}Without Suricata, Sentinel uses its own engine (scapy).{N}")
    print(f"  How does Sentinel receive Suricata alerts?")
    suri_mode = _ask_choice("Reception mode", [
        "Syslog UDP (firewall sends logs here)",
        "eve.json file (NFS/sshfs mount)",
        "TCP stream (via filebeat/logstash)",
        "No Suricata (local analysis only)",
    ], default=3)

    eve_file = ""
    syslog_port = ""
    tcp_port = ""

    if suri_mode == 0:
        syslog_port = _ask("Port syslog UDP", _get("suricata.syslog_port", "5514"))
    elif suri_mode == 1:
        eve_file = _ask("Chemin du fichier eve.json", _get("suricata.eve_file", "/mnt/firewall/eve.json"))
    elif suri_mode == 2:
        tcp_port = _ask("Port TCP", _get("suricata.tcp_port", "5515"))

    # ═══════════════════════════════════════════
    # 3. EMAIL
    # ═══════════════════════════════════════════
    _section(3, TOTAL, "Email notifications (incident response)")

    email_enabled = _ask_yn("Enable email notifications?",
                            _get("email.enabled", False))

    email_cfg = {
        "enabled": email_enabled,
        "smtp_server": _get("email.smtp_server", ""),
        "smtp_port": int(_get("email.smtp_port", 587)),
        "smtp_tls": True,
        "smtp_user": _get("email.smtp_user", ""),
        "smtp_password": _get("email.smtp_password", ""),
        "from_address": _get("email.from_address", ""),
        "sentinel_url": _get("email.sentinel_url", f"https://{server_ip}:8443"),
        "approval_timeout_minutes": int(_get("email.approval_timeout_minutes", 15)),
        "timeout_auto_approve": False,
        "shutdown_check_interval": 10,
        "shutdown_max_wait_minutes": 30,
        "security_contact": _get("email.security_contact", "the IT security team"),
        "include_legal_info": _get("email.include_legal_info", True),
        "attach_forensic_file": _get("email.attach_forensic_file", True),
        "country": _get("email.country", "IE"),
        "admin_emails": _get("email.admin_emails", []),
        "user_directory": _get("email.user_directory", []),
    }

    if email_enabled:
        email_cfg["smtp_server"] = _ask("SMTP server", email_cfg["smtp_server"], required=True)
        email_cfg["smtp_port"] = int(_ask("SMTP port (587=STARTTLS, 465=SSL)", str(email_cfg["smtp_port"])))
        email_cfg["smtp_tls"] = _ask_yn("Use TLS/STARTTLS?", True)
        email_cfg["smtp_user"] = _ask("SMTP user", email_cfg["smtp_user"])
        if email_cfg["smtp_user"]:
            pw = _ask("SMTP password (Enter = keep)", "")
            if pw:
                email_cfg["smtp_password"] = pw
        email_cfg["from_address"] = _ask("From address",
            email_cfg["from_address"] or f"sentinel@{email_cfg['smtp_server'].split('.')[-2] + '.' + email_cfg['smtp_server'].split('.')[-1]}" if "." in email_cfg["smtp_server"] else "sentinel@local")
        email_cfg["sentinel_url"] = _ask("Sentinel URL (for email links)",
            email_cfg["sentinel_url"])

        print(f"\n  {B}Administrators{N} (receive all alerts)")
        email_cfg["admin_emails"] = _ask_list(
            "Admin emails :", email_cfg["admin_emails"])

        email_cfg["approval_timeout_minutes"] = int(_ask(
            "Admin approval timeout (minutes)", str(email_cfg["approval_timeout_minutes"])))
        email_cfg["timeout_auto_approve"] = _ask_yn(
            "Auto-action if no admin response?", False)
        email_cfg["shutdown_max_wait_minutes"] = int(_ask(
            "Deadline max d'waiting for shutdown poste (minutes)", str(email_cfg["shutdown_max_wait_minutes"])))
        email_cfg["security_contact"] = _ask(
            "Security contact (shown in user email)", email_cfg["security_contact"])

        # Options du rapport admin
        print(f"\n  {B}Incident report content (admin email){N}")

        # Choix du pays
        from core.legal_data import get_supported_countries
        countries = get_supported_countries()
        print(f"\n  {B}Country for legal information and complaint PDF :{N}")
        current_country = _get("email.country", "IE")
        default_idx = next((i for i, (c, _, _) in enumerate(countries) if c == current_country), 0)
        country_idx = _ask_choice("Pays", [f"{flag} {name}" for _, flag, name in countries], default=default_idx)
        email_cfg["country"] = countries[country_idx][0]

        country_name = countries[country_idx][2]
        email_cfg["include_legal_info"] = _ask_yn(
            f"Include complaint filing information ({country_name}) ?",
            _get("email.include_legal_info", True))
        email_cfg["attach_forensic_file"] = _ask_yn(
            "Attach forensic JSON file?",
            _get("email.attach_forensic_file", True))

        # User directory — based on network discovery
        print(f"\n  {B}User directory{N}")
        print(f"  {DIM}Sentinel will scan the network to discover machines,{N}")
        print(f"  {DIM}then you can assign a name and email to each one.{N}")

        existing_users = {e["ip"]: e for e in email_cfg["user_directory"] if e.get("ip")}
        # Also index by MAC
        existing_by_mac = {e["mac"].lower(): e for e in email_cfg["user_directory"]
                          if e.get("mac")}

        if _ask_yn("Scan the network now to discover hosts?", True):
            print(f"\n  {C}Scan ARP in progress…{N}")
            discovered = _discover_hosts(subnets, iface, excludes, server_ip)

            if discovered:
                print(f"\n  {G}✓ {len(discovered)} host(s) detected on the network{N}\n")
                print(f"  {DIM}For each host, enter the user's name and email.{N}")
                print(f"  {DIM}Leave empty to skip a host (server, printer...).{N}\n")

                users = []
                for i, host in enumerate(discovered, 1):
                    h_ip = host["ip"]
                    h_mac = host.get("mac", "")
                    h_vendor = host.get("vendor", "")
                    h_hostname = host.get("hostname", "")
                    h_os = host.get("os_hint", "")

                    # Pre-fill from existing directory (by IP or MAC)
                    existing = existing_users.get(h_ip, {})
                    if not existing and h_mac:
                        existing = existing_by_mac.get(h_mac.lower(), {})

                    # Afficher les infos du poste
                    print(f"  {C}──── Host {i}/{len(discovered)} ────{N}")
                    print(f"  IP       : {B}{h_ip}{N}")
                    if h_mac:
                        print(f"  MAC      : {h_mac}  {DIM}{h_vendor}{N}")
                    if h_hostname:
                        print(f"  Hostname : {h_hostname}")
                    if h_os:
                        print(f"  OS       : {DIM}{h_os}{N}")

                    # Ask user info
                    default_name = existing.get("name", "")
                    default_email = existing.get("email", "")
                    default_pcname = existing.get("hostname", h_hostname)

                    name = _ask("User name", default_name)
                    if name:
                        email_addr = _ask("Email", default_email)
                        pc_name = _ask("PC name", default_pcname)
                        entry = {
                            "ip": h_ip,
                            "mac": h_mac,
                            "name": name,
                            "email": email_addr,
                            "hostname": pc_name,
                            "vendor": h_vendor,
                            "os": h_os,
                        }
                        users.append(entry)
                        print(f"  {G}✓ {name}{N}")
                    else:
                        print(f"  {DIM}— skipped{N}")
                    print()

                if users:
                    email_cfg["user_directory"] = users
                    print(f"  {G}✓ {len(users)} user(s) configured{N}")
                else:
                    print(f"  {Y}No users configured. You can do this later :{N}")
                    print(f"  {Y}  sudo cyberguard console → User directory{N}")
            else:
                print(f"  {Y}No hosts detected. Check the subnet and permissions.{N}")
                print(f"  {DIM}Tip: ARP scan requires being on the same network segment.{N}")

        elif email_cfg["user_directory"]:
            print(f"  {G}✓ Existing directory kept ({len(email_cfg['user_directory'])} entries){N}")
        else:
            print(f"  {DIM}You can configure the directory later :{N}")
            print(f"  {DIM}  sudo cyberguard console → User directory{N}")

    # ═══════════════════════════════════════════
    # 4. CLIENT AGENT (zero-privilege)
    # ═══════════════════════════════════════════
    _section(4, TOTAL, "Client agent (optional — zero-privilege popup & forensic)")

    print(f"  {B}Zero-privilege architecture (optional):{N}")
    print(f"  {DIM}Without the agent: notifications are sent by email only.{N}")
    print(f"  {DIM}No AV scan, no forensic collection from workstations.{N}")
    print(f"  {DIM}The system works fully without the agent.{N}")
    print(f"")
    print(f"  {DIM}With the agent: a lightweight script (cyberguard-agent.py) runs on{N}")
    print(f"  {DIM}each workstation and polls Sentinel for notifications.{N}")
    print(f"  {DIM}It displays popups, runs local AV scans, and collects forensic{N}")
    print(f"  {DIM}evidence — all locally, with user consent.{N}")
    print(f"  {DIM}Sentinel NEVER connects to clients. No credentials stored.{N}")

    agent_enabled = _ask_yn("Enable client agent support?",
                            _get("client_agent.enabled", True))

    client_agent_cfg = {
        "enabled": agent_enabled,
        "message_ttl_minutes": int(_get("client_agent.message_ttl_minutes", 120)),
        "collect_after_incident": True,
        "ack_timeout_seconds": int(_get("client_agent.ack_timeout_seconds", 120)),
        "shared_secret": _get("client_agent.shared_secret", ""),
    }

    if agent_enabled:
        # Generate or keep shared secret
        existing_secret = client_agent_cfg["shared_secret"]
        if not existing_secret:
            import secrets
            client_agent_cfg["shared_secret"] = secrets.token_hex(32)
            print(f"\n  {B}Shared secret generated automatically.{N}")
        else:
            print(f"\n  {DIM}Shared secret already configured.{N}")

        if _ask_yn("Regenerate shared secret?", not existing_secret):
            import secrets
            client_agent_cfg["shared_secret"] = secrets.token_hex(32)

        print(f"\n  {B}Agent deploy command:{N}")
        print(f"  {DIM}  python3 cyberguard-agent.py --server https://SENTINEL_IP:8443 \\{N}")
        print(f"  {DIM}    --secret {client_agent_cfg['shared_secret'][:16]}...{N}")
        print(f"  {DIM}  (no admin privileges needed on the workstation){N}")

        client_agent_cfg["collect_after_incident"] = _ask_yn(
            "Request forensic collection from client after incident?",
            _get("client_agent.collect_after_incident", True))
        client_agent_cfg["ack_timeout_seconds"] = int(_ask(
            "Popup ack timeout before email fallback (seconds)",
            str(client_agent_cfg["ack_timeout_seconds"])))
        client_agent_cfg["message_ttl_minutes"] = int(_ask(
            "Notification queue TTL (minutes)",
            str(client_agent_cfg["message_ttl_minutes"])))

        print(f"\n  {B}Deploy the agent on each workstation:{N}")
        print(f"  {DIM}  python3 cyberguard-agent.py --server https://SENTINEL_IP:8443{N}")
        print(f"  {DIM}  (no admin privileges needed on the workstation){N}")

    # ═══════════════════════════════════════════
    # 5. DEFENSE
    # ═══════════════════════════════════════════
    _section(5, TOTAL, "Active defense")

    defense_enabled = _ask_yn("Enable active defense?", _get("defense.enabled", True))
    auto_block = False
    block_ttl = 3600
    whitelist = [server_ip]
    defense_mode = "confirmation"

    if defense_enabled:
        print(f"\n  {B}Defense operating mode:{N}")
        print(f"  {DIM}  Confirmation: admin must approve before Sentinel acts (safest){N}")
        print(f"  {DIM}  Immediate:    Sentinel acts instantly, informs admin with rollback option{N}")
        mode_idx = _ask_choice("Mode", [
            "Confirmation (admin approves first)",
            "Immediate (act first, inform after)",
        ], default=0 if _get("defense.mode", "confirmation") == "confirmation" else 1)
        defense_mode = "confirmation" if mode_idx == 0 else "immediate"

        auto_block = _ask_yn("Automatic blocking of critical IPs?",
                            _get("defense.auto_block", True))
        block_ttl = int(_ask("Default block duration (seconds)",
                            str(_get("defense.block_ttl_seconds", 3600))))

        print(f"\n  {B}Whitelist{N} (IPs that will NEVER be blocked)")
        wl_default = _get("defense.whitelist_ips", [server_ip, "8.8.8.8", "1.1.1.1"])
        whitelist = _ask_list("Whitelist IPs :", wl_default)

    # ═══════════════════════════════════════════
    # 5. RECONNAISSANCE
    # ═══════════════════════════════════════════
    _section(6, TOTAL, "Attacker reconnaissance (optional API keys)")

    print(f"  {DIM}These keys are optional but enhance recon.{N}")
    abuseipdb_key = _ask("AbuseIPDB API key (gratuit : abuseipdb.com)",
                         _get("recon.abuseipdb_key", ""))
    virustotal_key = _ask("VirusTotal API key (gratuit : virustotal.com)",
                          _get("recon.virustotal_key", ""))

    # ═══════════════════════════════════════════
    # 6. NETGATE (pfSense / OPNsense)
    # ═══════════════════════════════════════════
    _section(7, TOTAL, "Netgate firewall (optional — pfSense / OPNsense)")

    print(f"  {DIM}If you have a Netgate firewall, Sentinel can push{N}")
    print(f"  {DIM}blocks directly via its REST API.{N}")

    netgate_enabled = _ask_yn("Connect a Netgate firewall?",
                              _get("netgate.enabled", False))

    netgate_cfg = {
        "enabled": netgate_enabled,
        "type": _get("netgate.type", ""),
        "host": _get("netgate.host", ""),
        "port": int(_get("netgate.port", 443)),
        "verify_ssl": False,
        "block_alias": _get("netgate.block_alias", "CyberGuard_Block"),
        "timeout": 15,
        "pfsense_api_client": _get("netgate.pfsense_api_client", ""),
        "pfsense_api_key": _get("netgate.pfsense_api_key", ""),
        "opnsense_key": _get("netgate.opnsense_key", ""),
        "opnsense_secret": _get("netgate.opnsense_secret", ""),
    }

    if netgate_enabled:
        fw_choice = _ask_choice("Firmware type", ["pfSense", "OPNsense"], default=0)
        netgate_cfg["type"] = "pfsense" if fw_choice == 0 else "opnsense"
        netgate_cfg["host"] = _ask("Netgate firewall IP", netgate_cfg["host"], required=True)
        netgate_cfg["port"] = int(_ask("HTTPS port", str(netgate_cfg["port"])))
        netgate_cfg["block_alias"] = _ask("Block alias name", netgate_cfg["block_alias"])

        print(f"\n  {DIM}Prerequisites on the firewall :{N}")
        print(f"  {DIM}  1. Create an alias '{netgate_cfg['block_alias']}' (type Host){N}")
        print(f"  {DIM}  2. Create a WAN rule : Block source = {netgate_cfg['block_alias']}{N}")
        print(f"  {DIM}  3. Generate an API key{N}")

        if netgate_cfg["type"] == "pfsense":
            print(f"\n  {B}pfSense API{N} (installer pfSense-pkg-API)")
            netgate_cfg["pfsense_api_client"] = _ask("API Client ID", netgate_cfg["pfsense_api_client"])
            netgate_cfg["pfsense_api_key"] = _ask("API Key", netgate_cfg["pfsense_api_key"])
        else:
            print(f"\n  {B}OPNsense API{N} (System > Access > Users > API keys)")
            netgate_cfg["opnsense_key"] = _ask("API Key", netgate_cfg["opnsense_key"])
            netgate_cfg["opnsense_secret"] = _ask("API Secret", netgate_cfg["opnsense_secret"])

    # ═══════════════════════════════════════════
    # 7. INTERFACE WEB
    # ═══════════════════════════════════════════
    _section(8, TOTAL, "Web interface (dashboard)")

    web_port = int(_ask("Dashboard port", str(_get("web.port", 8443))))

    print(f"\n  {B}Dashboard admin account{N}")
    web_user = _ask("Username", _get("web.username", "admin"))

    current_hash = _get("web.password_hash", "")
    if first_install or not current_hash:
        print(f"  {Y}Setting password :{N}")
        web_password = _ask_password("Dashboard password")
        web_hash = bcrypt.hashpw(web_password.encode(), bcrypt.gensalt()).decode()
    else:
        if _ask_yn("Change dashboard password?", False):
            web_password = _ask_password("New password")
            web_hash = bcrypt.hashpw(web_password.encode(), bcrypt.gensalt()).decode()
        else:
            web_hash = current_hash

    # ═══════════════════════════════════════════
    # 7. RETENTION
    # ═══════════════════════════════════════════
    _section(9, TOTAL, "Data retention")

    alerts_days = int(_ask("Alert retention (days)",
                          str(_get("retention.alerts_days", 90))))
    events_days = int(_ask("Event retention (days)",
                          str(_get("retention.events_days", 30))))
    flows_days = int(_ask("Network flow retention (days)",
                         str(_get("retention.flows_days", 14))))

    # ═══════════════════════════════════════════
    # ASSEMBLER LA CONFIG
    # ═══════════════════════════════════════════

    config = {
        "general": {
            "data_dir": _get("general.data_dir", "/var/lib/cyberguard/data"),
            "log_dir": _get("general.log_dir", "/var/log/cyberguard"),
            "log_level": _get("general.log_level", "INFO"),
        },
        "network": {
            "subnets": subnets,
            "interface": iface,
            "exclude_ips": excludes,
        },
        "suricata": {
            "eve_file": eve_file,
            "syslog_port": int(syslog_port) if syslog_port else "",
            "tcp_port": int(tcp_port) if tcp_port else "",
        },
        "discovery": {
            "arp_interval": int(_get("discovery.arp_interval", 300)),
            "port_scan_interval": int(_get("discovery.port_scan_interval", 3600)),
            "top_ports": _get("discovery.top_ports", [21,22,23,25,53,80,110,135,139,143,443,445,993,995,
                          1433,1521,3306,3389,5432,5900,6379,8080,8443,27017]),
            "service_detection": True, "os_fingerprint": True,
            "use_nmap": use_nmap,
        },
        "sniffer": _get("sniffer", {
            "enabled": True, "promiscuous": True, "bpf_filter": "",
        }),
        "analysis": _get("analysis", {
            "portscan_threshold": 15, "bruteforce_threshold": 10,
            "bruteforce_window": 60, "beacon_tolerance": 0.15,
            "dns_entropy_threshold": 3.5, "exfil_mb": 100,
            "new_service_alert": True,
        }),
        "defense": {
            "enabled": defense_enabled,
            "mode": defense_mode,
            "auto_block": auto_block,
            "auto_block_severity": int(_get("defense.auto_block_severity", 1)),
            "alert_count_threshold": int(_get("defense.alert_count_threshold", 5)),
            "alert_count_window": int(_get("defense.alert_count_window", 300)),
            "block_ttl_seconds": block_ttl,
            "rate_limit_ttl_seconds": int(_get("defense.rate_limit_ttl_seconds", 1800)),
            "quarantine_ttl_seconds": int(_get("defense.quarantine_ttl_seconds", 7200)),
            "whitelist_ips": whitelist,
        },
        "email": email_cfg,
        "recon": {
            "abuseipdb_key": abuseipdb_key,
            "virustotal_key": virustotal_key,
        },
        "netgate": netgate_cfg,
        "client_agent": client_agent_cfg,
        "web": {
            "enabled": True,
            "host": "0.0.0.0",
            "port": web_port,
            "secret": _get("web.secret", os.urandom(24).hex()),
            "username": web_user,
            "password_hash": web_hash,
            "ssl_cert": _get("web.ssl_cert", ""),
            "ssl_key": _get("web.ssl_key", ""),
        },
        "retention": {
            "alerts_days": alerts_days,
            "events_days": events_days,
            "flows_days": flows_days,
        },
        "alerts": _get("alerts", {
            "cooldown_seconds": 300, "max_per_hour": 120,
            "webhook": {"enabled": False},
            "syslog": {"enabled": True},
        }),
    }

    # ═══════════════════════════════════════════
    # OS HARDENING
    # ═══════════════════════════════════════════
    print(f"\n  {B}OS security hardening{N}")
    print(f"  {DIM}Applies kernel, network, filesystem and service hardening.{N}")
    print(f"  {DIM}Uses drop-in files only — fully reversible, forward-compatible.{N}")
    try:
        from core.os_hardening import OSHardener
        os_h = OSHardener()
        os_result = os_h.harden(interactive=True)
        if os_result["changes"]:
            print(f"\n  {G}Applied {len(os_result['changes'])} hardening changes.{N}")
        if os_result["skipped"]:
            print(f"  {DIM}Skipped: {len(os_result['skipped'])} steps{N}")
    except Exception as e:
        print(f"    {DIM}OS hardening skipped: {e}{N}")

    # ═══════════════════════════════════════════
    # SSH HARDENING
    # ═══════════════════════════════════════════
    print(f"\n  {B}SSH security check{N}")
    try:
        from core.hardening import SSHHardener
        ssh = SSHHardener()
        ssh_result = ssh.harden(interactive=True)
        if ssh_result["changes"]:
            for c in ssh_result["changes"]:
                print(f"    {G}✓{N} {c}")
        if ssh_result["warnings"]:
            for w in ssh_result["warnings"]:
                print(f"    {Y}⚠{N} {w}")
    except Exception as e:
        print(f"    {DIM}SSH check skipped: {e}{N}")

    # ═══════════════════════════════════════════
    # SUMMARY AND SAVE
    # ═══════════════════════════════════════════

    _banner("Configuration summary")
    print(f"  Network        : {B}{', '.join(subnets)}{N} (iface={iface})")
    print(f"  Exclusions     : {', '.join(excludes)}")
    print(f"  Nmap           : {B}{'Enabled' if use_nmap else 'Disabled (scapy only)'}{N}")
    suri_desc = "Syslog UDP:" + str(syslog_port) if syslog_port else \
                "File:" + eve_file if eve_file else \
                "TCP:" + str(tcp_port) if tcp_port else "Disabled"
    print(f"  Suricata       : {B}{suri_desc}{N}")
    print(f"  Email          : {B}{'Enabled' if email_enabled else 'Disabled'}{N}")
    if email_enabled:
        print(f"    SMTP         : {email_cfg['smtp_server']}:{email_cfg['smtp_port']}")
        print(f"    Admins       : {', '.join(email_cfg['admin_emails'])}")
        print(f"    Directory    : {len(email_cfg['user_directory'])} user(s)")
        legal = "Yes" if email_cfg.get("include_legal_info", True) else "No"
        attach = "Yes" if email_cfg.get("attach_forensic_file", True) else "No"
        from core.legal_data import get_country as _gc
        _cn = _gc(email_cfg.get("country", "IE"))
        print(f"    Legal country: {_cn['flag']} {_cn['name']}  |  Complaint info: {legal}  |  Forensic attached: {attach}")
    mode_label = "Confirmation" if defense_mode == "confirmation" else "Immediate"
    print(f"  Defense        : {B}{'Active' if defense_enabled else 'Passive'}{N} ({mode_label} mode)")
    print(f"  Client agent   : {B}{'Enabled' if agent_enabled else 'Disabled (email only)'}{N}")
    if agent_enabled:
        print(f"    Forensic     : {'Yes' if client_agent_cfg['collect_after_incident'] else 'No'}")
    if defense_enabled:
        print(f"    Auto-block   : {'Yes' if auto_block else 'No'}")
        print(f"    Whitelist    : {', '.join(whitelist)}")
    print(f"  Dashboard      : {B}https://0.0.0.0:{web_port}{N} (user={web_user})")
    if netgate_enabled:
        print(f"  Netgate        : {B}{netgate_cfg['type']} @ {netgate_cfg['host']}{N} (alias={netgate_cfg['block_alias']})")
    else:
        print(f"  Netgate        : Disabled")
    print(f"  Retention      : alerts={alerts_days}d flows={flows_days}d")
    print()

    if _ask_yn(f"Save to {B}{config_path}{N} ?", True):
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True,
                      sort_keys=False)
        os.chmod(config_path, 0o640)
        print(f"\n  {G}✓ Configuration saved to {config_path}{N}\n")
    else:
        print(f"\n  {Y}Configuration not saved.{N}\n")

    return config
