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
from flask import Flask, render_template, request, redirect, url_for, jsonify, abort
from models import db, Scan, Host, OpenPort, TrafficEvent, Report


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app():
    app = Flask(__name__)

    app.config["SQLALCHEMY_DATABASE_URI"]        = "sqlite:///final-pi-project.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.secret_key = "dev-key-change-before-demo"

    db.init_app(app)

    with app.app_context():
        db.create_all()

    # Register routes
    register_routes(app)

    return app


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def register_routes(app):

    @app.route("/")
    def dashboard():
        scans = Scan.query.order_by(Scan.started_at.desc()).all()
        return render_template("main.html", scans=scans)


    @app.route("/scan/<int:scan_id>")
    def scan_detail(scan_id):
        scan   = Scan.query.get_or_404(scan_id)
        hosts  = Host.query.filter_by(scan_id=scan_id).all()
        events = TrafficEvent.query.filter_by(scan_id=scan_id).order_by(TrafficEvent.severity.desc()).all()
        return render_template("scan_detail.html", scan=scan, hosts=hosts, events=events)


    @app.route("/scan/<int:scan_id>/report")
    def scan_report(scan_id):
        report = Report.query.filter_by(scan_id=scan_id).first_or_404()
        return render_template("report.html", report=report)


    @app.route("/scan/start", methods=["POST"])
    def start_scan():
        target   = request.form.get("target",   "192.168.1.0/24").strip()
        duration = int(request.form.get("duration", 30))
        interface = request.form.get("interface", "wlan0").strip()

        # Import here to avoid circular import
        from orchestrator import run_scan

        # Run the scan in a background thread so the browser does not hang
        def _run():
            with app.app_context():
                run_scan(target=target, capture_seconds=duration, interface=interface)

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        return redirect(url_for("dashboard"))


    @app.route("/status")
    def status():
        total     = Scan.query.count()
        running   = Scan.query.filter_by(status="running").count()
        complete  = Scan.query.filter_by(status="complete").count()
        return jsonify({"status": "ok", "scans_total": total,
                        "scans_running": running, "scans_complete": complete})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = create_app()
    # host="0.0.0.0" makes Flask reachable from other devices on the LAN
    app.run(host="0.0.0.0", port=5000, debug=True)
