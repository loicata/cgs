#!/usr/bin/env python3
"""
CyberGuard SIEM — CLI.
Usage :
  sudo cyberguard start          Starts the full SIEM
  sudo cyberguard scan           ARP discovery
  sudo cyberguard portscan       Scan de ports
  cyberguard status              System status
  cyberguard alerts              Recent alertes
  cyberguard inventory           Network inventory
  cyberguard passwd              Changer le mot de passe
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import click, bcrypt
from rich.console import Console
from rich.table import Table
from core.config import Config

console = Console()
DCFG = "/opt/cyberguard/config.yaml"

@click.group()
@click.option("--config","-c", default=DCFG)
@click.pass_context
def cli(ctx, config):
    """⛨  CyberGuard — Micro-SIEM autonome 100 %% Python."""
    ctx.ensure_object(dict); ctx.obj["c"] = config

@cli.command()
@click.pass_context
def start(ctx):
    """Starts the daemon (requires root)."""
    if os.geteuid() != 0:
        console.print("[bold red]Error :[/] sudo required."); sys.exit(1)
    # Verify installation is complete
    state_file = "/opt/cyberguard/.install_state"
    if os.path.exists(state_file):
        state = open(state_file).read().strip()
        if "ROLLED_BACK" in state:
            console.print("[bold red]Incomplete installation detected (rollback).[/]")
            console.print("Re-run : [bold]sudo dpkg --configure cyberguard-sentinel[/]")
            console.print("       ou : [bold]sudo apt install --fix-broken[/]")
            sys.exit(1)
        if "STARTED" in state and "COMMITTED" not in state:
            console.print("[bold red]Incomplete installation (interrupted).[/]")
            console.print("Re-run : [bold]sudo dpkg --configure cyberguard-sentinel[/]")
            sys.exit(1)
    from daemon import Daemon
    Daemon(ctx.obj["c"]).start()

@cli.command()
@click.pass_context
def scan(ctx):
    """Manual ARP discovery."""
    cfg = Config(ctx.obj["c"])
    from core.database import init_db; from core.alerts import AlertEngine; from core.discovery import NetworkDiscovery
    init_db(cfg.get("general.data_dir"))
    disc = NetworkDiscovery(cfg, AlertEngine(cfg).fire)
    console.print("[cyan]ARP sweep…[/]")
    hosts = disc.arp_sweep()
    t = Table(title=f"{len(hosts)} hosts")
    t.add_column("IP", style="bold green"); t.add_column("MAC"); t.add_column("Vendor"); t.add_column("OS")
    for h in hosts: t.add_row(h["ip"], h.get("mac",""), h.get("vendor",""), h.get("os_hint",""))
    console.print(t)

@cli.command()
@click.pass_context
def portscan(ctx):
    """Scan de ports."""
    cfg = Config(ctx.obj["c"])
    from core.database import init_db; from core.alerts import AlertEngine; from core.discovery import NetworkDiscovery
    init_db(cfg.get("general.data_dir"))
    disc = NetworkDiscovery(cfg, AlertEngine(cfg).fire)
    console.print("[cyan]SYN scan…[/]")
    for ip, ports in disc.port_scan().items():
        if ports:
            t = Table(title=ip); t.add_column("Port",style="bold"); t.add_column("Service"); t.add_column("Banner")
            for p in ports: t.add_row(str(p["port"]), p.get("service",""), p.get("banner","")[:60])
            console.print(t)

@cli.command()
@click.pass_context
def status(ctx):
    """System status."""
    cfg = Config(ctx.obj["c"])
    from core.database import init_db; from core.alerts import AlertEngine; from core.health import HealthChecker
    init_db(cfg.get("general.data_dir"))
    r = HealthChecker(cfg, AlertEngine(cfg).fire).check_all()
    s = r["system"]
    console.print(f"\n[bold cyan]  ⛨ CyberGuard — System[/]")
    console.print(f"  CPU: {s['cpu_percent']}%  RAM: {s['memory_percent']}% ({s['mem_used_gb']}/{s['mem_total_gb']} Go)  Uptime: {s['uptime_h']}h")
    for m,d in r["disk"].items():
        bar = "█"*int(d["used_pct"]/5)+"░"*(20-int(d["used_pct"]/5))
        c = "green" if d["used_pct"]<75 else "yellow" if d["used_pct"]<90 else "red"
        console.print(f"  {m:12s} [{c}]{bar}[/] {d['used_pct']}% ({d['free_gb']} Go free)")
    console.print()

@cli.command()
@click.option("--limit","-n", default=20)
@click.pass_context
def alerts(ctx, limit):
    """Recent alerts."""
    cfg = Config(ctx.obj["c"])
    from core.database import init_db, Alert
    init_db(cfg.get("general.data_dir"))
    ss = {1:"bold red",2:"bold yellow",3:"yellow",4:"blue",5:"dim"}
    sl = {1:"CRIT",2:"HIGH",3:"MED ",4:"LOW ",5:"INFO"}
    t = Table(title=f"Last {limit} alerts")
    t.add_column("Time",style="dim"); t.add_column("Sev."); t.add_column("Source"); t.add_column("Title"); t.add_column("IP")
    for a in Alert.select().order_by(Alert.ts.desc()).limit(limit):
        t.add_row(a.ts.strftime("%d/%m %H:%M:%S"), f"[{ss[a.severity]}]{sl[a.severity]}[/]",
                  a.source, a.title[:60], f"{a.src_ip or''}{' → '+a.dst_ip if a.dst_ip else ''}")
    console.print(t)

@cli.command()
@click.pass_context
def inventory(ctx):
    """Network inventory."""
    cfg = Config(ctx.obj["c"])
    from core.database import init_db; from core.discovery import NetworkDiscovery
    init_db(cfg.get("general.data_dir"))
    hosts = NetworkDiscovery.get_inventory()
    t = Table(title=f"{len(hosts)} hosts")
    t.add_column("IP",style="bold green"); t.add_column("Hostname"); t.add_column("OS"); t.add_column("Vendor")
    t.add_column("Risk"); t.add_column("Ports"); t.add_column("Status")
    for h in hosts:
        rc = "red" if h["risk_score"]>=70 else "yellow" if h["risk_score"]>=30 else "green"
        ps = ", ".join(str(p["port"]) for p in h["ports"][:10])
        st = "[green]●[/] up" if h["status"]=="up" else "[red]●[/] down"
        t.add_row(h["ip"], h.get("hostname") or "—", h.get("os") or "—", h.get("vendor") or "—",
                  f"[{rc}]{h['risk_score']}[/]", ps, st)
    console.print(t)

@cli.command()
@click.pass_context
def passwd(ctx):
    """Changes the web password."""
    cfg = Config(ctx.obj["c"])
    pw = click.prompt("Mot de passe", hide_input=True, confirmation_prompt=True)
    cfg.set("web.password_hash", bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode())
    cfg.save()
    console.print("[green]Password updated.[/]")

@cli.command()
@click.option("--first-install", is_flag=True, hidden=True)
@click.pass_context
def setup(ctx, first_install):
    """Lance l'assistant de configuration interactive."""
    from core.setup import run_setup
    run_setup(ctx.obj["c"], first_install=first_install)

@cli.command(name="console")
@click.pass_context
def admin_console(ctx):
    """Opens the TUI administration console (menu interactive)."""
    if os.geteuid() != 0:
        console.print("[bold red]Error :[/] sudo required."); sys.exit(1)
    from core.tui import run_console
    run_console(ctx.obj["c"])

if __name__ == "__main__":
    cli()
