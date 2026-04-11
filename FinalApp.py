"""
FinalApp.py
Pi Intrusion Testing Appliance - Flask Web Application
Team 3 / ITP 258 Sprint 2

Routes:
  GET  /                  - dashboard: list all scans
  GET  /scan/<id>         - scan detail: hosts, ports, traffic events
  GET  /scan/<id>/report  - view the generated text report for a scan
  POST /scan/start        - kick off a new scan (accepts target and duration)
  GET  /status            - JSON health check endpoint
"""

import threading
import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, abort

from utils.db import (
    init_db,
    get_session,
    get_hosts,
    get_ports,
)


# ---------------------------------------------------------------------------
# Helpers not covered by Channing's public functions
# ---------------------------------------------------------------------------

def get_all_sessions():
    """Fetch all scan sessions for the dashboard listing."""
    import sqlite3
    from pathlib import Path
    db_path = Path(__file__).parent / "instance" / "results.db"
    if not db_path.exists():
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM scan_sessions ORDER BY started_at DESC"
    ).fetchall()
    conn.close()
    return rows


def get_traffic_findings(session_id: str):
    """Fetch traffic findings for a session."""
    import sqlite3
    from pathlib import Path
    db_path = Path(__file__).parent / "instance" / "results.db"
    if not db_path.exists():
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM traffic_findings WHERE session_id = ?", (session_id,)
    ).fetchall()
    conn.close()
    return rows


def get_report(session_id: str):
    """Fetch the most recent report for a session."""
    import sqlite3
    from pathlib import Path
    db_path = Path(__file__).parent / "instance" / "results.db"
    if not db_path.exists():
        return None
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM reports WHERE session_id = ? ORDER BY generated_at DESC LIMIT 1",
        (session_id,)
    ).fetchone()
    conn.close()
    return row


def get_all_reports():
    """Fetch all reports joined with their session info, newest first."""
    import sqlite3
    from pathlib import Path
    db_path = Path(__file__).parent / "instance" / "results.db"
    if not db_path.exists():
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT r.id, r.session_id, r.file_path, r.format, r.generated_at,
               s.target_cidr, s.status, s.started_at, s.completed_at
        FROM reports r
        JOIN scan_sessions s ON s.id = r.session_id
        ORDER BY r.generated_at DESC
    """).fetchall()
    conn.close()
    return rows


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app():
    app = Flask(__name__)
    app.secret_key = "dev-key-change-before-demo"

    # Initialize Channing's database on startup - safe to call every time
    with app.app_context():
        init_db()

    # Custom Jinja filter: convert Unix timestamp integer to EST string
    @app.template_filter("to_est")
    def to_est(unix_ts):
        if not unix_ts:
            return "—"
        utc = datetime.datetime.utcfromtimestamp(int(unix_ts))
        # EST = UTC-5 (fixed offset; covers Eastern Standard Time)
        est = utc - datetime.timedelta(hours=5)
        return est.strftime("%-I:%M %p EST %m/%d/%Y")

    register_routes(app)
    return app


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def register_routes(app):

    @app.route("/")
    def dashboard():
        scans = get_all_sessions()
        # Check if any scan is still running so the template can auto-refresh
        any_running = any(s["status"] == "running" for s in scans)
        return render_template("main.html", scans=scans, any_running=any_running)


    @app.route("/scan/<scan_id>")
    def scan_detail(scan_id):
        scan = get_session(scan_id)
        if not scan:
            abort(404)
        hosts = get_hosts(scan_id)
        hosts_with_ports = []
        for host in hosts:
            ports = get_ports(host["id"])
            hosts_with_ports.append({"host": host, "ports": ports})
        traffic = get_traffic_findings(scan_id)
        return render_template("scan_detail.html", scan=scan,
                               hosts_with_ports=hosts_with_ports,
                               traffic=traffic)


    @app.route("/scan/<scan_id>/report")
    def scan_report(scan_id):
        report = get_report(scan_id)
        if not report:
            abort(404)
        content = ""
        try:
            with open(report["file_path"], "r") as f:
                content = f.read()
        except Exception:
            content = "Report file could not be loaded."
        return render_template("report.html", report=report, content=content)


    @app.route("/scan/start", methods=["POST"])
    def start_scan():
        target    = request.form.get("target",    "192.168.1.0/24").strip()
        duration  = int(request.form.get("duration", 30))
        interface = request.form.get("interface", "wlan0").strip()

        from orchestrator import run_scan

        def _run():
            with app.app_context():
                run_scan(target=target, capture_seconds=duration, interface=interface)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return redirect(url_for("dashboard"))


    @app.route("/history")
    def history():
        scans = get_all_sessions()
        return render_template("history.html", scans=scans)


    @app.route("/reports")
    def reports_page():
        all_reports = get_all_reports()
        return render_template("reports.html", reports=all_reports)


    @app.route("/api/scans")
    def api_scans():
        """JSON endpoint for live polling - returns all sessions as dicts."""
        sessions = get_all_sessions()
        return jsonify({"scans": [dict(s) for s in sessions]})


    @app.route("/api/scan-detail/<scan_id>")
    def api_scan_detail(scan_id):
        """JSON endpoint returning hosts+ports and traffic findings for a session."""
        hosts = get_hosts(scan_id)
        hosts_out = []
        for host in hosts:
            ports = get_ports(host["id"])
            hosts_out.append({
                "id":         host["id"],
                "ip_address": host["ip_address"],
                "hostname":   host["hostname"],
                "os_guess":   host["os_guess"],
                "ports": [{
                    "port_number":     p["port_number"],
                    "protocol":        p["protocol"],
                    "state":           p["state"],
                    "service_name":    p["service_name"],
                    "service_version": p["service_version"],
                } for p in ports]
            })
        traffic = get_traffic_findings(scan_id)
        traffic_out = [dict(t) for t in traffic]
        return jsonify({"hosts": hosts_out, "traffic": traffic_out})


    @app.route("/api/system")
    def api_system():
        """
        Returns live system health and network info from the Pi.
        Uses only stdlib — no psutil required.
        """
        import subprocess, socket, re, time, os

        # ── CPU usage (via /proc/stat) ────────────────────────────────────
        def cpu_percent():
            try:
                with open("/proc/stat") as f:
                    line = f.readline()
                vals = list(map(int, line.split()[1:]))
                idle1, total1 = vals[3], sum(vals)
                time.sleep(0.1)
                with open("/proc/stat") as f:
                    line = f.readline()
                vals = list(map(int, line.split()[1:]))
                idle2, total2 = vals[3], sum(vals)
                diff_idle  = idle2  - idle1
                diff_total = total2 - total1
                return round(100.0 * (1 - diff_idle / diff_total), 1) if diff_total else 0.0
            except Exception:
                return None

        # ── Memory usage (via /proc/meminfo) ─────────────────────────────
        def mem_info():
            try:
                data = {}
                with open("/proc/meminfo") as f:
                    for line in f:
                        k, v = line.split(":")
                        data[k.strip()] = int(v.strip().split()[0])
                total    = data.get("MemTotal", 0)
                available = data.get("MemAvailable", 0)
                used     = total - available
                pct      = round(100.0 * used / total, 1) if total else 0.0
                return {
                    "total_mb": round(total / 1024),
                    "used_mb":  round(used  / 1024),
                    "pct":      pct,
                }
            except Exception:
                return None

        # ── Disk usage (via df) ───────────────────────────────────────────
        def disk_info():
            try:
                out = subprocess.check_output(
                    ["df", "-BM", "/"], text=True
                ).splitlines()[1]
                parts = out.split()
                total = int(parts[1].rstrip("M"))
                used  = int(parts[2].rstrip("M"))
                pct   = int(parts[4].rstrip("%"))
                return {"total_mb": total, "used_mb": used, "pct": pct}
            except Exception:
                return None

        # ── Tool availability ─────────────────────────────────────────────
        def tool_ok(name):
            try:
                subprocess.check_output(["which", name], stderr=subprocess.DEVNULL)
                return True
            except Exception:
                return False

        # ── Network interfaces ────────────────────────────────────────────
        def net_info():
            interfaces = []
            try:
                out = subprocess.check_output(["ip", "-o", "addr"], text=True)
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    iface = parts[1]
                    family = parts[2]
                    if family != "inet":
                        continue
                    cidr = parts[3]
                    ip   = cidr.split("/")[0]
                    mask = cidr.split("/")[1] if "/" in cidr else ""
                    if iface == "lo":
                        continue
                    interfaces.append({
                        "interface": iface,
                        "ip":        ip,
                        "cidr":      cidr,
                        "mask":      mask,
                    })
            except Exception:
                pass
            return interfaces

        # ── Hostname ──────────────────────────────────────────────────────
        hostname = socket.gethostname()

        # ── Uptime ────────────────────────────────────────────────────────
        uptime_str = ""
        try:
            with open("/proc/uptime") as f:
                secs = float(f.read().split()[0])
            h = int(secs // 3600)
            m = int((secs % 3600) // 60)
            uptime_str = f"{h}h {m}m"
        except Exception:
            uptime_str = "unknown"

        return jsonify({
            "hostname": hostname,
            "uptime":   uptime_str,
            "cpu":      cpu_percent(),
            "memory":   mem_info(),
            "disk":     disk_info(),
            "tools": {
                "nmap":   tool_ok("nmap"),
                "tshark": tool_ok("tshark"),
            },
            "interfaces": net_info(),
        })


    @app.route("/status")
    def status():
        sessions = get_all_sessions()
        total    = len(sessions)
        running  = sum(1 for s in sessions if s["status"] == "running")
        complete = sum(1 for s in sessions if s["status"] == "completed")
        return jsonify({"status": "ok", "scans_total": total,
                        "scans_running": running, "scans_complete": complete})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
