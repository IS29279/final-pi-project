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
