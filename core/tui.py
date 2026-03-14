"""
CyberGuard Sentinel — TUI administration console (SSH).

Accessible via : sudo cyberguard console

Menu principal :
  1. System status (services, CPU, RAM, disque)
  2. Recent alerts
  3. Network inventory
  4. Incidents in progress
  5. Defense actions actives
  6. Modify configuration
  7. Manage user directory
  8. Test email sending
  9. View logs
  0. Quit
"""

import os
import sys
import subprocess

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm
from rich import box

from core.config import Config

console = Console()


def run_console(config_path: str = "/etc/cyberguard/config.yaml"):
    """Lance la console d'administration interactive."""
    cfg = Config(config_path)

    while True:
        console.clear()
        console.print(Panel(
            "[bold cyan]⛨  CyberGuard Sentinel — Administration console[/]\n"
            f"[dim]Config : {config_path}[/]",
            box=box.DOUBLE_EDGE, border_style="cyan",
        ))
        console.print()

        menu = [
            ("1", "System status", _show_status),
            ("2", "Recent alerts", _show_alerts),
            ("3", "Network inventory", _show_inventory),
            ("4", "Incidents", _show_incidents),
            ("5", "Defense actions actives", _show_defense),
            ("6", "Modify configuration", _edit_config),
            ("7", "User directory", _manage_users),
            ("8", "Test email sending", _test_email),
            ("9", "View logs", _view_logs),
            ("R", "Restart service", _restart_service),
            ("0", "Quit", None),
        ]

        for key, label, _ in menu:
            if key == "0":
                console.print(f"  [bold red]{key}[/bold red]  {label}")
            elif key == "R":
                console.print(f"  [bold]{key}[/bold]  {label}")
            else:
                console.print(f"  {key}  {label}")

        console.print()
        choice = Prompt.ask("Choice", default="0")

        if choice == "0":
            break

        for key, _, func in menu:
            if choice == key and func:
                try:
                    func(cfg, config_path)
                except KeyboardInterrupt:
                    pass
                except Exception as e:
                    console.print(f"[red]Error : {e}[/]")
                Prompt.ask("\n[dim]Press Enter to continue[/]")
                break


# ═══════════════════════════════════════════
# 1. System status
# ═══════════════════════════════════════════
def _show_status(cfg, config_path):
    console.print("\n[bold cyan]  System status[/]\n")
    from core.database import init_db
    from core.alerts import AlertEngine
    from core.health import HealthChecker
    init_db(cfg.get("general.data_dir"))
    r = HealthChecker(cfg, AlertEngine(cfg).fire).check_all()
    s = r["system"]

    t = Table(box=box.SIMPLE)
    t.add_column("Metric", style="bold")
    t.add_column("Value")
    t.add_row("CPU", f"{s['cpu_percent']}%")
    t.add_row("RAM", f"{s['memory_percent']}% ({s['mem_used_gb']}/{s['mem_total_gb']} Go)")
    t.add_row("Uptime", f"{s['uptime_h']}h")
    for mount, d in r["disk"].items():
        c = "green" if d["used_pct"] < 75 else "yellow" if d["used_pct"] < 90 else "red"
        t.add_row(f"Disque {mount}", f"[{c}]{d['used_pct']}%[/] ({d['free_gb']} Go free)")
    console.print(t)

    # Services
    services = ["cyberguard-sentinel"]
    # Ajouter Suricata seulement s'il est configured
    if cfg.get("suricata.eve_file") or cfg.get("suricata.syslog_port") or cfg.get("suricata.tcp_port"):
        services.append("suricata")
    for svc in services:
        try:
            r = subprocess.run(["systemctl", "is-active", svc],
                              capture_output=True, text=True, timeout=5)
            active = r.stdout.strip() == "active"
            icon = "[green]●[/]" if active else "[red]●[/]"
            console.print(f"  {icon} {svc} : {'active' if active else 'inactive'}")
        except Exception:
            console.print(f"  [dim]? {svc}[/]")


# ═══════════════════════════════════════════
# 2. Alerts
# ═══════════════════════════════════════════
def _show_alerts(cfg, config_path):
    from core.database import init_db, Alert
    init_db(cfg.get("general.data_dir"))
    sev_style = {1: "bold red", 2: "bold yellow", 3: "yellow", 4: "blue", 5: "dim"}
    sev_label = {1: "CRIT", 2: "HIGH", 3: "MED", 4: "LOW", 5: "INFO"}

    t = Table(title="30 latest alerts", box=box.SIMPLE)
    t.add_column("Time", style="dim")
    t.add_column("Sev.")
    t.add_column("Source")
    t.add_column("Title")
    t.add_column("IP")
    for a in Alert.select().order_by(Alert.ts.desc()).limit(30):
        t.add_row(
            a.ts.strftime("%d/%m %H:%M"),
            f"[{sev_style[a.severity]}]{sev_label[a.severity]}[/]",
            a.source, a.title[:50],
            f"{a.src_ip or ''} → {a.dst_ip or ''}",
        )
    console.print(t)


# ═══════════════════════════════════════════
# 3. Inventory
# ═══════════════════════════════════════════
def _show_inventory(cfg, config_path):
    from core.database import init_db
    from core.discovery import NetworkDiscovery
    init_db(cfg.get("general.data_dir"))
    hosts = NetworkDiscovery.get_inventory()

    t = Table(title=f"{len(hosts)} hosts", box=box.SIMPLE)
    t.add_column("IP", style="bold green")
    t.add_column("MAC", style="dim")
    t.add_column("Hostname")
    t.add_column("OS")
    t.add_column("Risk")
    t.add_column("Ident.", justify="center")
    t.add_column("Ports")
    t.add_column("Status")

    # Charger les empreintes si disponible
    identity_data = {}
    try:
        from core.host_identity import HostIdentityEngine
        from core.alerts import AlertEngine
        ie = HostIdentityEngine(cfg, AlertEngine(cfg).fire)
        for h in hosts:
            if h.get("mac"):
                v = ie.verify_identity(h["ip"], h["mac"])
                identity_data[h["ip"]] = v.get("score", 0)
    except Exception:
        pass

    for h in hosts:
        rc = "red" if h["risk_score"] >= 70 else "yellow" if h["risk_score"] >= 30 else "green"
        ports = ", ".join(str(p["port"]) for p in h["ports"][:8])
        st = "[green]●[/]" if h["status"] == "up" else "[red]●[/]"

        id_score = identity_data.get(h["ip"], -1)
        if id_score >= 0:
            ic = "green" if id_score >= 80 else "yellow" if id_score >= 50 else "red"
            id_str = f"[{ic}]{id_score}%[/]"
        else:
            id_str = "[dim]—[/]"

        t.add_row(h["ip"], h.get("mac") or "—", h.get("hostname") or "—",
                  h.get("os") or "—", f"[{rc}]{h['risk_score']}[/]",
                  id_str, ports, st)
    console.print(t)
    console.print(f"\n  [dim]Ident. = multi-factor identity score (≥80=reliable, <50=suspect)[/]")


# ═══════════════════════════════════════════
# 4. Incidents
# ═══════════════════════════════════════════
def _show_incidents(cfg, config_path):
    console.print("\n[bold cyan]  Incidents[/]")
    console.print("[dim]  (requires daemon to be running)[/]\n")
    try:
        import requests
        port = cfg.get("web.port", 8443)
        r = requests.get(f"https://localhost:{port}/api/incidents",
                        verify=False, timeout=5,
                        cookies={"session": "admin"})
        if r.status_code == 401:
            console.print("[yellow]  Authentication required — check the web dashboard.[/]")
            return
        incidents = r.json()
        if not incidents:
            console.print("  No incidents recorded.")
            return
        t = Table(box=box.SIMPLE)
        t.add_column("ID")
        t.add_column("Status")
        t.add_column("Cible")
        t.add_column("Attaquant")
        t.add_column("Type")
        for i in incidents[:20]:
            t.add_row(i["id"], i["status"], i["target_ip"], i["attacker_ip"], i["threat_type"])
        console.print(t)
    except Exception as e:
        console.print(f"[yellow]  Cannot contact the daemon : {e}[/]")
        console.print("[dim]  Is the service running? sudo systemctl start cyberguard-sentinel[/]")


# ═══════════════════════════════════════════
# 5. Defense
# ═══════════════════════════════════════════
def _show_defense(cfg, config_path):
    console.print("\n[bold cyan]  Active defense[/]\n")

    # Show current iptables rules
    try:
        r = subprocess.run(["iptables", "-L", "CYBERGUARD", "-n", "-v", "--line-numbers"],
                          capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            console.print("[bold]CYBERGUARD chain (iptables):[/]")
            console.print(r.stdout)
        else:
            console.print("  No active CyberGuard iptables rules.")
    except Exception:
        console.print("  [dim]iptables not accessible.[/]")

    # Rollback option
    console.print("\n  [bold]1[/]  Rollback to a previous state")
    console.print("  [bold]0[/]  Back")
    choice = Prompt.ask("Choice", default="0")

    if choice == "1":
        try:
            from core.snapshot import DefenseSnapshot
            snaps = DefenseSnapshot(cfg)
            available = snaps.list_snapshots()

            if not available:
                console.print("\n  [dim]No snapshots available.[/]")
                return

            console.print(f"\n  [bold]{len(available)} snapshot(s) available:[/]\n")
            t = Table(box=box.SIMPLE)
            t.add_column("#", style="dim")
            t.add_column("Incident")
            t.add_column("Date")
            t.add_column("Reason")
            t.add_column("Size")
            for i, s in enumerate(available):
                t.add_row(str(i + 1), s["incident_id"], s["created_at"],
                          s["reason"], f"{s['size_kb']} KB")
            console.print(t)

            idx = IntPrompt.ask("\n  Snapshot # to restore (0=cancel)", default=0)
            if 1 <= idx <= len(available):
                snap = available[idx - 1]
                console.print(f"\n  [yellow]⚠ This will restore the defense state from BEFORE[/]")
                console.print(f"  [yellow]  incident {snap['incident_id']} ({snap['created_at']})[/]")
                console.print(f"  [yellow]  All blocks/rules added since then will be removed.[/]")

                if Confirm.ask("\n  Proceed with rollback?", default=False):
                    result = snaps.restore(snap["filepath"])
                    if result["ok"]:
                        console.print(f"\n  [green]✓ Rollback completed:[/]")
                        for a in result["actions"]:
                            console.print(f"    ✓ {a}")
                    else:
                        console.print(f"\n  [red]✗ Rollback partial:[/]")
                        for a in result["actions"]:
                            console.print(f"    ✓ {a}")
                        for e in result["errors"]:
                            console.print(f"    ✗ {e}")
                else:
                    console.print("  Cancelled.")
        except Exception as e:
            console.print(f"  [red]Error: {e}[/]")


# ═══════════════════════════════════════════
# 6. Modify configuration
# ═══════════════════════════════════════════
def _edit_config(cfg, config_path):
    import yaml
    console.print("\n[bold cyan]  Modifying la configuration[/]\n")
    choices = [
        "Run full setup wizard (all options)",
        "Edit YAML file directly (nano/vim)",
        "Incident report options (attachment, legal section)",
        "Back",
    ]
    for i, c in enumerate(choices):
        console.print(f"  {i + 1}. {c}")

    choice = Prompt.ask("Choice", default="4")

    if choice == "1":
        from core.setup import run_setup
        run_setup(config_path, first_install=False)
        if Confirm.ask("Restart service pour appliquer ?", default=True):
            _restart_service(cfg, config_path)

    elif choice == "2":
        editor = os.environ.get("EDITOR", "nano")
        os.system(f"{editor} {config_path}")
        if Confirm.ask("Restart service pour appliquer ?", default=True):
            _restart_service(cfg, config_path)

    elif choice == "3":
        with open(config_path) as f:
            raw_cfg = yaml.safe_load(f) or {}
        email = raw_cfg.setdefault("email", {})

        # Show current state
        legal = email.get("include_legal_info", True)
        forensic = email.get("attach_forensic_file", True)
        current_country = email.get("country", "IE")
        from core.legal_data import get_country
        cdata = get_country(current_country)
        console.print(f"\n  Legal country : [bold]{cdata['flag']} {cdata['name']}[/]  (code: {current_country})")
        console.print(f"  Include complaint info : [{'green' if legal else 'red'}]{'Enabled' if legal else 'Disabled'}[/]")
        console.print(f"  Joindre le fichier forensique     : [{'green' if forensic else 'red'}]{'Enabled' if forensic else 'Disabled'}[/]")
        console.print()

        if Confirm.ask("  Modifier ces options ?", default=True):
            # Country selection
            from core.legal_data import get_supported_countries
            countries = get_supported_countries()
            console.print("\n  Country for legal information :")
            for i, (code, flag, name) in enumerate(countries):
                marker = "[green]>[/]" if code == current_country else " "
                console.print(f"    {marker} {i+1}. {flag} {name}")
            cidx = IntPrompt.ask("  Choice", default=next((i+1 for i,(c,_,_) in enumerate(countries) if c==current_country), 1))
            if 1 <= cidx <= len(countries):
                email["country"] = countries[cidx-1][0]

            email["include_legal_info"] = Confirm.ask(
                "  Include complaint filing contacts?",
                default=legal)
            email["attach_forensic_file"] = Confirm.ask(
                "  Attach forensic JSON file?",
                default=forensic)
            with open(config_path, "w") as f:
                yaml.dump(raw_cfg, f, default_flow_style=False, allow_unicode=True)
            console.print("  [green]✓ Options saved[/]")
            if Confirm.ask("  Restart service pour appliquer ?", default=True):
                _restart_service(cfg, config_path)


# ═══════════════════════════════════════════
# 7. User directory
# ═══════════════════════════════════════════
def _manage_users(cfg, config_path):
    import yaml
    console.print("\n[bold cyan]  User directory (IP/MAC → email)[/]\n")

    with open(config_path) as f:
        raw_cfg = yaml.safe_load(f) or {}
    users = raw_cfg.get("email", {}).get("user_directory", [])

    def _show_table():
        if users:
            t = Table(box=box.SIMPLE)
            t.add_column("#", style="dim")
            t.add_column("IP", style="bold green")
            t.add_column("MAC", style="dim")
            t.add_column("Nom", style="bold")
            t.add_column("Email")
            t.add_column("PC")
            t.add_column("Vendor", style="dim")
            for i, u in enumerate(users):
                t.add_row(str(i + 1), u.get("ip", ""), u.get("mac", "—"),
                          u.get("name", ""), u.get("email", ""),
                          u.get("hostname", ""), u.get("vendor", ""))
            console.print(t)
        else:
            console.print("  [dim]Directory empty.[/]")

    def _save_users():
        raw_cfg.setdefault("email", {})["user_directory"] = users
        with open(config_path, "w") as f:
            yaml.dump(raw_cfg, f, default_flow_style=False, allow_unicode=True)
        console.print("  [green]✓ Directory saved[/]")

    while True:
        console.print()
        _show_table()
        console.print()
        console.print("  [bold]1[/]  Scan network (discover hosts)")
        console.print("  [bold]2[/]  Add manually")
        console.print("  [bold]3[/]  Edit a user")
        console.print("  [bold]4[/]  Delete a user")
        console.print("  [bold]0[/]  Back")

        choice = Prompt.ask("Choice", default="0")

        if choice == "0":
            break

        elif choice == "1":
            # Scanner le network
            console.print("\n[cyan]  Scan ARP in progress…[/]")
            subnets = cfg.get("network.subnets", ["192.168.1.0/24"])
            iface = cfg.get("network.interface", "auto")
            excludes = cfg.get("network.exclude_ips", [])
            try:
                from core.netutils import get_iface_ip
                server_ip = get_iface_ip(iface if iface != "auto" else "eth0")
            except Exception:
                server_ip = ""

            try:
                from core.setup import _discover_hosts
                discovered = _discover_hosts(subnets, iface, excludes, server_ip)
            except Exception as e:
                console.print(f"  [red]Error scan : {e}[/]")
                continue

            if not discovered:
                console.print("  [yellow]No hosts detected.[/]")
                continue

            console.print(f"\n  [green]{len(discovered)} host(s) discovered[/]\n")

            # Index existant par IP et MAC
            existing_by_ip = {u["ip"]: u for u in users if u.get("ip")}
            existing_by_mac = {u["mac"].lower(): u for u in users if u.get("mac")}

            new_count = 0
            for host in discovered:
                h_ip = host["ip"]
                h_mac = host.get("mac", "")

                # Already in directory?
                existing = existing_by_ip.get(h_ip) or existing_by_mac.get(h_mac.lower() if h_mac else "")
                if existing and existing.get("name"):
                    console.print(f"  [dim]{h_ip} ({h_mac}) → already configured : {existing['name']}[/]")
                    continue

                # New host detected
                console.print(f"\n  [cyan]New host :[/]  IP=[bold]{h_ip}[/]  MAC={h_mac}  "
                             f"{host.get('vendor', '')}  {host.get('hostname', '')}  "
                             f"[dim]{host.get('os_hint', '')}[/]")

                name = Prompt.ask("  User name (vide=ignorer)", default="")
                if name:
                    email_addr = Prompt.ask("  Email", default="")
                    pc_name = Prompt.ask("  PC name", default=host.get("hostname", ""))
                    users.append({
                        "ip": h_ip, "mac": h_mac, "name": name,
                        "email": email_addr, "hostname": pc_name,
                        "vendor": host.get("vendor", ""),
                        "os": host.get("os_hint", ""),
                    })
                    new_count += 1
                    console.print(f"  [green]✓ {name} added[/]")

            if new_count > 0:
                _save_users()
                console.print(f"\n  [green]{new_count} nouveau(x) utilisateur(s) added(s)[/]")
            else:
                console.print("\n  [dim]No new hosts to configure.[/]")

        elif choice == "2":
            # Ajout manual
            ip = Prompt.ask("  Host IP")
            mac = Prompt.ask("  MAC (optional)", default="")
            name = Prompt.ask("  Full name")
            email_addr = Prompt.ask("  Email")
            hostname = Prompt.ask("  PC name", default="")
            entry = {"ip": ip, "name": name, "email": email_addr, "hostname": hostname}
            if mac:
                entry["mac"] = mac
            users.append(entry)
            _save_users()

        elif choice == "3" and users:
            # Modifier
            idx = IntPrompt.ask("  Number to edit", default=0)
            if 1 <= idx <= len(users):
                u = users[idx - 1]
                console.print(f"  [dim]Modifying {u.get('name', u.get('ip'))}[/]")
                console.print(f"  [dim](Enter = keep current value)[/]")
                u["ip"] = Prompt.ask("  IP", default=u.get("ip", ""))
                u["mac"] = Prompt.ask("  MAC", default=u.get("mac", ""))
                u["name"] = Prompt.ask("  Nom", default=u.get("name", ""))
                u["email"] = Prompt.ask("  Email", default=u.get("email", ""))
                u["hostname"] = Prompt.ask("  PC name", default=u.get("hostname", ""))
                _save_users()

        elif choice == "4" and users:
            # Supprimer
            idx = IntPrompt.ask("  Number to delete", default=0)
            if 1 <= idx <= len(users):
                removed = users.pop(idx - 1)
                _save_users()
                console.print(f"  [green]✓ {removed.get('name', '')} removed[/]")


# ═══════════════════════════════════════════
# 8. Test email
# ═══════════════════════════════════════════
def _test_email(cfg, config_path):
    console.print("\n[bold cyan]  Test d'sending email[/]\n")

    if not cfg.get("email.enabled"):
        console.print("[red]  Email disabled in config. Enable email.enabled first.[/]")
        return

    to = Prompt.ask("  Recipient address", default=cfg.get("email.admin_emails", [""])[0] if cfg.get("email.admin_emails") else "")
    if not to:
        return

    console.print("  Envoi in progress…")
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText("Ceci est un email de test de CyberGuard Sentinel.\n\nSi vous recevez ce message, la configuration SMTP est correcte.")
        msg["Subject"] = "✅ [CyberGuard] Test email — Configuration OK"
        msg["From"] = cfg.get("email.from_address", "sentinel@local")
        msg["To"] = to

        server_addr = cfg.get("email.smtp_server")
        port = cfg.get("email.smtp_port", 587)
        if port == 465:
            srv = smtplib.SMTP_SSL(server_addr, port, timeout=15)
        else:
            srv = smtplib.SMTP(server_addr, port, timeout=15)
            if cfg.get("email.smtp_tls", True):
                srv.starttls()
        user = cfg.get("email.smtp_user", "")
        if user:
            srv.login(user, cfg.get("email.smtp_password", ""))
        srv.send_message(msg)
        srv.quit()
        console.print(f"  [green]✓ Email sent to {to}[/]")
    except Exception as e:
        console.print(f"  [red]✗ Error : {e}[/]")


# ═══════════════════════════════════════════
# 9. Logs
# ═══════════════════════════════════════════
def _view_logs(cfg, config_path):
    console.print("\n[bold cyan]  Logs[/]\n")
    console.print("  1. CyberGuard logs (journalctl)")
    console.print("  2. cyberguard.log file")
    console.print("  3. Defense audit log")
    console.print("  4. Forensic files")

    choice = Prompt.ask("Choice", default="1")

    if choice == "1":
        os.system("journalctl -u cyberguard-sentinel --no-pager -n 50")
    elif choice == "2":
        log_file = os.path.join(cfg.get("general.log_dir", "/var/log/cyberguard"), "cyberguard.log")
        if os.path.exists(log_file):
            os.system(f"tail -50 {log_file}")
        else:
            console.print(f"  [dim]{log_file} not found.[/]")
    elif choice == "3":
        audit_file = os.path.join(cfg.get("general.log_dir"), "defense_audit.jsonl")
        if os.path.exists(audit_file):
            os.system(f"tail -30 {audit_file}")
        else:
            console.print("  [dim]No defense audit.[/]")
    elif choice == "4":
        forensic_dir = os.path.join(cfg.get("general.log_dir"), "forensics")
        if os.path.isdir(forensic_dir):
            files = sorted(os.listdir(forensic_dir), reverse=True)
            if files:
                for f in files[:10]:
                    size = os.path.getsize(os.path.join(forensic_dir, f)) / 1024
                    console.print(f"  📁 {f} ({size:.1f} Ko)")
            else:
                console.print("  [dim]No forensic files.[/]")
        else:
            console.print(f"  [dim]{forensic_dir} not found.[/]")


# ═══════════════════════════════════════════
# R. Restart
# ═══════════════════════════════════════════
def _restart_service(cfg, config_path):
    console.print("\n[yellow]  Restarting service…[/]")
    r = os.system("systemctl restart cyberguard-sentinel")
    if r == 0:
        console.print("  [green]✓ Service restarted.[/]")
    else:
        console.print("  [red]✗ Restart failed. Consultez : journalctl -u cyberguard-sentinel[/]")
