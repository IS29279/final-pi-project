"""
FinalApp.py
Pi Intrusion Testing Appliance - Flask Web Application
Team 3 / ITP 258 Sprint 2

Routes:
  GET  /                         - dashboard: list all scans
  GET  /scan/<id>                - scan detail: hosts, ports, traffic events, flagged concerns
  GET  /scan/<id>/report         - view the generated report for a scan (rich HTML)
  POST /scan/start               - kick off a new scan (accepts target and duration)
  POST /admin/regenerate-reports - one-time: rebuild text reports for every scan in the DB
  GET  /status                   - JSON health check endpoint
"""

import threading
import datetime
from collections import Counter
from flask import Flask, render_template, request, redirect, url_for, jsonify, abort, send_file, Response

from utils.db import (
    init_db,
    get_session,
    get_hosts,
    get_ports,
    complete_session,
)

# Module-level scan state — tracks the active scan thread and stop flag
_active_scan = {
    "session_id": None,
    "stop_event": None,
    "thread":     None,
}


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


def _build_port_findings_for_flags(hosts_with_ports):
    """
    Flatten the nested hosts/ports structure into the flat list of dicts
    that flag_findings() expects. Each dict carries the host IP alongside
    the port fields so flags can be attributed back to the right host.
    """
    findings = []
    for item in hosts_with_ports:
        host_ip = item["host"]["ip_address"]
        for port in item["ports"]:
            findings.append({
                "host":            host_ip,
                "port_number":     port["port_number"],
                "protocol":        port["protocol"],
                "state":           port["state"],
                "service_name":    port["service_name"],
                "service_version": port["service_version"],
            })
    return findings


def _row_field(row, key):
    """
    Safely read a field from either a sqlite3.Row or a dict.
    sqlite3.Row supports [key] but not .get(), so flag_findings() callers
    that pass Row objects straight through work the same as plain dicts.
    """
    try:
        return row[key]
    except (KeyError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Narrative summary helper (Sprint 2 — used by /scan/<id>/report)
# ---------------------------------------------------------------------------

# Keyword substring → short label for the summary paragraph.
# Order matters: more specific patterns must come before less specific ones.
_SUMMARY_LABELS = [
    ("vsftpd",             "vsftpd backdoor"),
    ("outdated openssh",   "outdated SSH"),
    ("outdated open",      "outdated OpenSSL"),
    ("end-of-life apache", "end-of-life Apache"),
    ("end-of-life iis",    "end-of-life IIS"),
    ("iis 6",              "end-of-life IIS"),
    ("telnet",             "Telnet"),
    ("smb",                "SMB"),
    ("rdp",                "RDP"),
    ("vnc",                "VNC"),
    ("nfs",                "NFS"),
    ("ftp",                "FTP"),
    ("mssql",              "MSSQL"),
    ("mysql",              "MySQL"),
    ("postgres",           "PostgreSQL"),
    ("default port 22",    "SSH on default port"),
    ("ssh",                "SSH"),
    ("http alternate",     "HTTP alt port"),
    ("http",               "HTTP"),
]


def _label_for_reason(reason: str) -> str:
    """Turn a flag's reason string into a short noun phrase for the summary."""
    r = (reason or "").lower()
    for kw, label in _SUMMARY_LABELS:
        if kw in r:
            return label
    # Fallback: first word before the em-dash
    first = (reason or "").split("—")[0].strip().rstrip(".").split()
    return first[0] if first else "(unlabeled)"


def build_report_summary(scan, hosts_with_ports, flags):
    """
    Produce a human-readable summary of the scan's findings.

    Returns a dict with:
      - counts:    dict mapping severity → count (e.g. {"critical": 4, "high": 1})
      - headline:  single-line takeaway (e.g. "4 critical findings require action today")
      - paragraph: multi-sentence narrative describing what was found
    """
    target     = scan["target_cidr"] if scan and "target_cidr" in scan else "the target subnet"
    host_count = len(hosts_with_ports)
    counts     = Counter(f["severity"] for f in flags)

    # ── Headline: lead with the worst severity present ──────────────────
    if counts.get("critical", 0):
        n = counts["critical"]
        headline = f"{n} critical finding{'s' if n != 1 else ''} require{'' if n != 1 else 's'} action today"
    elif counts.get("high", 0):
        n = counts["high"]
        headline = f"{n} high-severity finding{'s' if n != 1 else ''} need{'' if n != 1 else 's'} attention"
    elif counts.get("medium", 0):
        n = counts["medium"]
        headline = f"{n} medium-severity finding{'s' if n != 1 else ''} worth reviewing"
    elif counts.get("info", 0):
        headline = "No security concerns detected"
    else:
        headline = "Scan complete"

    sentences = []

    # Sentence 1: what the scan looked at
    if host_count == 0:
        sentences.append(f"This scan of {target} discovered no live hosts.")
    elif host_count == 1:
        sentences.append(f"This scan of {target} examined 1 host.")
    else:
        sentences.append(f"This scan of {target} examined {host_count} hosts.")

    # Group port-scoped flags by host for the narrative
    host_to_critical = {}
    host_to_high     = {}
    host_to_medium   = {}
    for flag in flags:
        if flag["host"] == "network":
            continue
        bucket = {"critical": host_to_critical,
                  "high":     host_to_high,
                  "medium":   host_to_medium}.get(flag["severity"])
        if bucket is not None:
            bucket.setdefault(flag["host"], []).append(flag)

    def _describe(host_map, cap_hosts=2, cap_flags=3):
        """Turn {host: [flags]} into phrases like 'HOST has X and Y exposed'."""
        parts = []
        items = list(host_map.items())
        for host, host_flags in items[:cap_hosts]:
            labels = [_label_for_reason(f["reason"]) for f in host_flags[:cap_flags]]
            # De-dupe while preserving order
            seen = set()
            uniq = [x for x in labels if not (x in seen or seen.add(x))]
            if len(uniq) == 1:
                parts.append(f"{host} has {uniq[0]} exposed")
            elif len(uniq) == 2:
                parts.append(f"{host} has {uniq[0]} and {uniq[1]} exposed")
            else:
                parts.append(f"{host} has {', '.join(uniq[:-1])}, and {uniq[-1]} exposed")
        remaining = len(items) - cap_hosts
        if remaining > 0:
            parts.append(f"and {remaining} other host{'s' if remaining != 1 else ''} with similar findings")
        return parts

    # Sentence 2: headline finding (highest severity present on any host)
    if host_to_critical:
        sentences.append(f"Critical: {', '.join(_describe(host_to_critical))}.")
    elif host_to_high:
        sentences.append(f"High-severity: {', '.join(_describe(host_to_high))}.")
    elif host_to_medium:
        sentences.append(f"Medium-severity: {', '.join(_describe(host_to_medium))}.")

    # Sentence 3: traffic findings are network-wide, handled separately
    traffic_flags = [f for f in flags if f["host"] == "network"]
    if any(f["severity"] == "critical" for f in traffic_flags):
        sentences.append("A packet capture observed cleartext credentials on the wire — live evidence of unencrypted authentication traffic.")
    elif any(f["severity"] == "medium" for f in traffic_flags):
        sentences.append("A packet capture observed unencrypted protocols (HTTP/FTP/Telnet) in active use on the network.")

    # Sentence 4: positive findings (info tier, host-scoped only)
    info_flags = [f for f in flags if f["severity"] == "info" and f["host"] != "network"]
    if info_flags:
        info_hosts = len({f["host"] for f in info_flags})
        if info_hosts == 1:
            sentences.append("One host showed positive security signals such as HTTPS or modern SSH configuration.")
        else:
            sentences.append(f"{info_hosts} hosts showed positive security signals such as HTTPS or modern SSH configuration.")

    # Special cases
    if host_count == 0:
        sentences = sentences[:1]  # empty scan — just "discovered no live hosts"
    elif not flags:
        sentences.append("No concerns were flagged on any host.")

    return {
        "counts":    dict(counts),
        "headline":  headline,
        "paragraph": " ".join(sentences),
    }


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app():
    app = Flask(__name__)
    app.secret_key = "dev-key-change-before-demo"

    with app.app_context():
        init_db()

    @app.template_filter("to_est")
    def to_est(unix_ts):
        if not unix_ts:
            return "—"
        utc = datetime.datetime.utcfromtimestamp(int(unix_ts))
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

        port_findings = _build_port_findings_for_flags(hosts_with_ports)
        flags = flag_findings(port_findings, list(traffic))

        return render_template("scan_detail.html",
                               scan=scan,
                               hosts_with_ports=hosts_with_ports,
                               traffic=traffic,
                               flags=flags)


    @app.route("/scan/<scan_id>/report")
    def scan_report(scan_id):
        """
        Render a rich, styled report page with a three-column top section:
        severity legend on the left, narrative summary in the middle,
        flagged concerns on the right. Includes plain-English guidance
        and export buttons for PDF/Word versions.
        """
        from exports import build_plain_english_guidance

        report = get_report(scan_id)
        if not report:
            abort(404)

        scan = get_session(scan_id)
        if not scan:
            abort(404)

        hosts = get_hosts(scan_id)
        hosts_with_ports = []
        for host in hosts:
            ports = get_ports(host["id"])
            hosts_with_ports.append({"host": host, "ports": ports})
        traffic = get_traffic_findings(scan_id)

        port_findings = _build_port_findings_for_flags(hosts_with_ports)
        flags = flag_findings(port_findings, list(traffic))

        summary  = build_report_summary(scan, hosts_with_ports, flags)
        guidance = build_plain_english_guidance(flags)

        return render_template("report.html",
                               report=report,
                               scan=scan,
                               hosts_with_ports=hosts_with_ports,
                               traffic=traffic,
                               flags=flags,
                               summary=summary,
                               guidance=guidance)


    # ── Export routes ────────────────────────────────────────────────────
    # Four flavors: full/summary × pdf/docx. Each pulls the same structured
    # data the report page uses, hands it to a builder in exports.py, and
    # streams the resulting bytes back as an attachment.

    def _build_export_context(scan_id):
        """Shared data-gathering for all four export routes."""
        report = get_report(scan_id)
        scan   = get_session(scan_id)
        if not report or not scan:
            return None

        hosts = get_hosts(scan_id)
        hosts_with_ports = []
        for host in hosts:
            ports = get_ports(host["id"])
            hosts_with_ports.append({"host": host, "ports": ports})
        traffic = get_traffic_findings(scan_id)

        port_findings = _build_port_findings_for_flags(hosts_with_ports)
        flags   = flag_findings(port_findings, list(traffic))
        summary = build_report_summary(scan, hosts_with_ports, flags)

        return {
            "scan":             scan,
            "report":           report,
            "hosts_with_ports": hosts_with_ports,
            "traffic":          traffic,
            "flags":            flags,
            "summary":          summary,
        }

    def _send_export(data_bytes, filename, mimetype):
        """Stream an export blob as a download attachment."""
        import io
        buf = io.BytesIO(data_bytes)
        buf.seek(0)
        return send_file(buf,
                         mimetype=mimetype,
                         as_attachment=True,
                         download_name=filename)

    @app.route("/scan/<scan_id>/export/full.pdf")
    def export_full_pdf(scan_id):
        from exports import build_full_pdf
        ctx = _build_export_context(scan_id)
        if ctx is None:
            abort(404)
        data = build_full_pdf(ctx)
        return _send_export(data,
                            f"network-lock-report-{scan_id[:8]}-full.pdf",
                            "application/pdf")

    @app.route("/scan/<scan_id>/export/full.docx")
    def export_full_docx(scan_id):
        from exports import build_full_docx
        ctx = _build_export_context(scan_id)
        if ctx is None:
            abort(404)
        data = build_full_docx(ctx)
        return _send_export(data,
                            f"network-lock-report-{scan_id[:8]}-full.docx",
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document")

    @app.route("/scan/<scan_id>/export/summary.pdf")
    def export_summary_pdf(scan_id):
        from exports import build_summary_pdf
        ctx = _build_export_context(scan_id)
        if ctx is None:
            abort(404)
        data = build_summary_pdf(ctx)
        return _send_export(data,
                            f"network-lock-report-{scan_id[:8]}-summary.pdf",
                            "application/pdf")

    @app.route("/scan/<scan_id>/export/summary.docx")
    def export_summary_docx(scan_id):
        from exports import build_summary_docx
        ctx = _build_export_context(scan_id)
        if ctx is None:
            abort(404)
        data = build_summary_docx(ctx)
        return _send_export(data,
                            f"network-lock-report-{scan_id[:8]}-summary.docx",
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document")


    @app.route("/scan/start", methods=["POST"])
    def start_scan():
        target    = request.form.get("target",    "192.168.1.0/24").strip()
        duration  = int(request.form.get("duration", 30))
        interface = request.form.get("interface", "wlan0").strip()

        from orchestrator import run_scan

        stop_event = threading.Event()

        def _run():
            with app.app_context():
                session_id = run_scan(
                    target=target,
                    capture_seconds=duration,
                    interface=interface,
                    stop_event=stop_event,
                )
                _active_scan["session_id"] = None
                _active_scan["stop_event"] = None
                _active_scan["thread"]     = None

        t = threading.Thread(target=_run, daemon=True)
        _active_scan["stop_event"] = stop_event
        _active_scan["thread"]     = t
        t.start()
        return redirect(url_for("dashboard"))


    @app.route("/scan/stop", methods=["POST"])
    def stop_scan():
        stop_event = _active_scan.get("stop_event")
        if stop_event:
            stop_event.set()

        sessions = get_all_sessions()
        stopped_id = None
        for s in sessions:
            if s["status"] == "running":
                stopped_id = s["id"]
                complete_session(s["id"], "completed")
                break

        if stopped_id:
            try:
                from orchestrator import generate_report
                hosts    = get_hosts(stopped_id)
                host_ids = [h["id"] for h in hosts]
                findings  = get_traffic_findings(stopped_id)
                finding_id = findings[0]["id"] if findings else None
                session    = get_session(stopped_id)
                target     = session["target_cidr"] if session else "unknown"
                generate_report(stopped_id, target, host_ids, finding_id)
            except Exception as e:
                print(f"[stop] Partial report generation failed: {e}")

        _active_scan["session_id"] = None
        _active_scan["stop_event"] = None
        _active_scan["thread"]     = None

        return jsonify({"stopped": True, "session_id": stopped_id})


    @app.route("/history")
    def history():
        scans = get_all_sessions()
        return render_template("history.html", scans=scans)


    @app.route("/reports")
    def reports_page():
        all_reports = get_all_reports()
        return render_template("reports.html", reports=all_reports)


    @app.route("/admin/regenerate-reports", methods=["POST"])
    def regenerate_reports():
        """
        One-time admin action: rebuild the text report for every scan in the
        database using the current generate_report() implementation.
        """
        from orchestrator import generate_report

        sessions = get_all_sessions()
        regenerated = 0
        failed      = 0
        errors      = []

        for s in sessions:
            session_id = s["id"]
            target     = s["target_cidr"]
            try:
                hosts    = get_hosts(session_id)
                host_ids = [h["id"] for h in hosts]
                tf = get_traffic_findings(session_id)
                finding_id = tf[0]["id"] if tf else None
                generate_report(session_id, target, host_ids, finding_id)
                regenerated += 1
            except Exception as e:
                failed += 1
                errors.append(f"{session_id[:8]}: {e}")

        return jsonify({
            "regenerated": regenerated,
            "failed":      failed,
            "errors":      errors,
        })


    @app.route("/api/scans")
    def api_scans():
        sessions = get_all_sessions()
        return jsonify({"scans": [dict(s) for s in sessions]})


    @app.route("/api/scan-detail/<scan_id>")
    def api_scan_detail(scan_id):
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
        import subprocess, socket, re, time, os

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
                return {"total_mb": round(total / 1024),
                        "used_mb":  round(used  / 1024),
                        "pct":      pct}
            except Exception:
                return None

        def disk_info():
            try:
                out = subprocess.check_output(["df", "-BM", "/"], text=True).splitlines()[1]
                parts = out.split()
                total = int(parts[1].rstrip("M"))
                used  = int(parts[2].rstrip("M"))
                pct   = int(parts[4].rstrip("%"))
                return {"total_mb": total, "used_mb": used, "pct": pct}
            except Exception:
                return None

        def tool_ok(name):
            try:
                subprocess.check_output(["which", name], stderr=subprocess.DEVNULL)
                return True
            except Exception:
                return False

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
                    interfaces.append({"interface": iface, "ip": ip, "cidr": cidr, "mask": mask})
            except Exception:
                pass
            return interfaces

        hostname = socket.gethostname()

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
            "tools": {"nmap": tool_ok("nmap"), "tshark": tool_ok("tshark")},
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
# Added by Channing - Beginning of section added for testing.
# Extended in Sprint 2 to cover traffic findings, info-tier flags, and
# search terms (CVE + attack name + MITRE ATT&CK ID) on every flag.
# ---------------------------------------------------------------------------

FLAGGED_PORTS = {
    21:   ("high",     "FTP is unencrypted and should not be exposed",
           ["FTP credential sniffing", "T1040", "T1021"]),
    23:   ("critical", "Telnet is plaintext — credentials sent in the clear",
           ["Telnet credential sniffing", "T1040", "cleartext authentication"]),
    445:  ("critical", "SMB exposed — high-value target for ransomware and lateral movement",
           ["SMB ransomware", "EternalBlue CVE-2017-0144", "T1021.002"]),
    3389: ("critical", "RDP exposed — common brute-force and ransomware entry point",
           ["RDP brute force", "BlueKeep CVE-2019-0708", "T1021.001"]),
    22:   ("high",     "SSH exposed on default port 22",
           ["SSH brute force", "T1110.001", "T1021.004"]),
    80:   ("medium",   "HTTP (unencrypted web) is exposed",
           ["HTTP man-in-the-middle", "session hijacking", "T1557"]),
    8080: ("medium",   "HTTP alternate port exposed — often a misconfigured dev server",
           ["exposed dev server", "unauthenticated admin panel", "T1190"]),
    2049: ("high",     "NFS exposed — can allow unauthenticated file system access",
           ["NFS misconfiguration", "no_root_squash exploit", "T1078"]),
    5900: ("high",     "VNC exposed — remote desktop with historically weak auth",
           ["VNC brute force", "VNC authentication bypass", "T1021.005"]),
    1433: ("high",     "MSSQL database port exposed externally",
           ["MSSQL brute force", "xp_cmdshell exploit", "T1078"]),
    3306: ("high",     "MySQL database port exposed externally",
           ["MySQL brute force", "MySQL privilege escalation", "T1078"]),
    5432: ("high",     "PostgreSQL database port exposed externally",
           ["PostgreSQL brute force", "database enumeration", "T1078"]),
}

FLAGGED_VERSION_SUBSTRINGS = [
    ("OpenSSH 5.", "critical", "Outdated OpenSSH version with known critical vulnerabilities",
     ["OpenSSH 5 CVE", "CVE-2016-0777", "user enumeration"]),
    ("OpenSSH 6.", "high",     "Outdated OpenSSH version — upgrade to 8.x or later",
     ["OpenSSH 6 CVE", "CVE-2016-6210", "user enumeration"]),
    ("Apache/2.2", "high",     "End-of-life Apache 2.2 — no longer receives security patches",
     ["Apache 2.2 end of life", "CVE-2017-15710", "unpatched web server"]),
    ("IIS/6.0",    "critical", "IIS 6.0 is end-of-life and has known remote code execution CVEs",
     ["IIS 6.0 RCE", "CVE-2017-7269", "WebDAV exploit"]),
    ("vsftpd 2.3.4", "critical", "vsftpd 2.3.4 contains a backdoor (CVE-2011-2523)",
     ["vsftpd 2.3.4 backdoor", "CVE-2011-2523", "Metasploit vsftpd_234_backdoor"]),
    ("OpenSSL/1.0", "high",    "Outdated OpenSSL 1.0.x — vulnerable to multiple CVEs",
     ["OpenSSL 1.0 Heartbleed", "CVE-2014-0160", "CVE-2016-2107"]),
]

INFO_PORTS = {
    443: ("HTTPS present — encrypted web traffic",
          ["TLS hardening", "HSTS configuration", "Mozilla SSL Configuration Generator"]),
    993: ("IMAPS present — encrypted mail retrieval",
          ["IMAPS best practices", "mail server TLS configuration"]),
    995: ("POP3S present — encrypted mail retrieval",
          ["POP3S best practices", "mail server TLS configuration"]),
}

MODERN_SSH_SUBSTRINGS = ("OpenSSH 8.", "OpenSSH 9.", "OpenSSH 10.")
MODERN_SSH_INFO_TERMS = ["SSH hardening", "SSH non-standard port", "SSH key-only auth"]

CLEARTEXT_PROTOCOLS = {"telnet", "ftp", "http"}


def _flag_port_findings(findings: list) -> list:
    flags = []

    for finding in findings:
        host            = finding.get("host", "unknown")
        port_number     = finding.get("port_number")
        service_version = finding.get("service_version", "") or ""

        if port_number in FLAGGED_PORTS:
            severity, reason, search_terms = FLAGGED_PORTS[port_number]
            flags.append({
                "host":         host,
                "port":         port_number,
                "severity":     severity,
                "reason":       reason,
                "search_terms": list(search_terms),
            })

        for substring, severity, reason, search_terms in FLAGGED_VERSION_SUBSTRINGS:
            if substring.lower() in service_version.lower():
                flags.append({
                    "host":         host,
                    "port":         port_number,
                    "severity":     severity,
                    "reason":       reason,
                    "search_terms": list(search_terms),
                })
                break

        if port_number in INFO_PORTS:
            reason, search_terms = INFO_PORTS[port_number]
            flags.append({
                "host":         host,
                "port":         port_number,
                "severity":     "info",
                "reason":       reason,
                "search_terms": list(search_terms),
            })

        if port_number != 22 and any(
            m.lower() in service_version.lower() for m in MODERN_SSH_SUBSTRINGS
        ):
            flags.append({
                "host":         host,
                "port":         port_number,
                "severity":     "info",
                "reason":       "SSH on non-standard port with modern version — defensive configuration",
                "search_terms": list(MODERN_SSH_INFO_TERMS),
            })

    return flags


def _flag_traffic_findings(traffic: list) -> list:
    flags = []

    for row in traffic:
        if hasattr(row, "get"):
            cleartext = bool(row.get("cleartext_creds_found"))
            summary   = (row.get("protocol_summary") or "").lower()
        else:
            cleartext = bool(_row_field(row, "cleartext_creds_found"))
            summary   = (_row_field(row, "protocol_summary") or "").lower()

        if cleartext:
            flags.append({
                "host":         "network",
                "port":         None,
                "severity":     "critical",
                "reason":       "Cleartext credentials observed in capture — live evidence of unencrypted login traffic",
                "search_terms": ["packet sniffing credentials", "Wireshark credential analysis", "T1040"],
            })
            continue

        cleartext_in_summary = any(proto in summary for proto in CLEARTEXT_PROTOCOLS)

        if cleartext_in_summary:
            flags.append({
                "host":         "network",
                "port":         None,
                "severity":     "medium",
                "reason":       "Unencrypted traffic observed in capture (HTTP/FTP/Telnet) — confirms plaintext protocols are in active use",
                "search_terms": ["network traffic encryption", "deprecate plaintext protocols", "T1040"],
            })
        elif summary.strip():
            flags.append({
                "host":         "network",
                "port":         None,
                "severity":     "info",
                "reason":       "Only encrypted protocols observed during capture — baseline confirmation",
                "search_terms": ["network encryption baseline", "TLS adoption"],
            })

    return flags


def flag_findings(findings: list, traffic_findings: list = None) -> list:
    flags = _flag_port_findings(findings)
    if traffic_findings:
        flags.extend(_flag_traffic_findings(traffic_findings))
    return flags

# ---------------------------------------------------------------------------
# End of section added for testing.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
