"""System monitoring: CPU, RAM, disk, interfaces."""
import logging, os
from datetime import datetime
import psutil
from core.netutils import get_all_interfaces

logger = logging.getLogger("cgs.health")

class HealthChecker:
    def __init__(self, config, alert_fn):
        self.cfg = config; self._alert = alert_fn

    def check_all(self) -> dict:
        r = {"ts": datetime.now().isoformat(),
             "system": self._sys(), "disk": self._disk(), "network": get_all_interfaces()}
        self._eval(r)
        return r

    def _sys(self):
        c = psutil.cpu_percent(interval=1); m = psutil.virtual_memory()
        l1,l5,_ = psutil.getloadavg()
        b = datetime.fromtimestamp(psutil.boot_time())
        return {"cpu_percent":c, "memory_percent":m.percent,
                "mem_used_gb":round(m.used/1e9,1), "mem_total_gb":round(m.total/1e9,1),
                "load_1":round(l1,2), "uptime_h":round((datetime.now()-b).total_seconds()/3600,1)}

    def _disk(self):
        d = {}
        skip = ("/snap/", "/boot/efi", "/run/")
        for p in psutil.disk_partitions():
            if any(p.mountpoint.startswith(s) for s in skip):
                continue
            if "squashfs" in (p.fstype or ""):
                continue
            try:
                u = psutil.disk_usage(p.mountpoint)
                d[p.mountpoint] = {"total_gb":round(u.total/1e9,1),"used_pct":u.percent,"free_gb":round(u.free/1e9,1)}
            except Exception as e: logger.debug("Failed to get disk usage for %s: %s", p.mountpoint, e)
        return d

    def _eval(self, r):
        s = r["system"]
        if s["cpu_percent"] > 90:
            self._alert(severity=2, source="system", category="cpu", title=f"CPU: {s['cpu_percent']}%")
        if s["memory_percent"] > 90:
            self._alert(severity=2, source="system", category="ram", title=f"RAM: {s['memory_percent']}%")
        for m,d in r["disk"].items():
            if d["used_pct"] > 90:
                self._alert(severity=2, source="system", category="disk", title=f"Disk {m}: {d['used_pct']}%")
