"""
orchestrator.py
Pi Intrusion Testing Appliance - Core Orchestration Layer
Team 3 / ITP 258 Sprint 2

Responsibilities:
  - Run Nmap host discovery and port/service scan against a target subnet
  - Run tshark passive capture in parallel
  - Parse results and write structured records to the SQLite database
  - Produce a simple text summary report

Usage (direct):
  python orchestrator.py --target 192.168.1.0/24 --duration 30

Usage (from Flask):
  from orchestrator import run_scan
  scan_id = run_scan(target="192.168.1.0/24", capture_seconds=30)
"""

import subprocess
import datetime
import time
import json
import re
import os
import argparse

from models import db, Scan, Host, OpenPort, TrafficEvent, Report

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DEFAULT_TARGET   = "192.168.1.0/24"   # placeholder - update to match actual subnet
DEFAULT_DURATION = 30                  # tshark capture duration in seconds
REPORT_DIR       = "reports"           # directory where .txt reports are saved


# ---------------------------------------------------------------------------
# Nmap helpers
# ---------------------------------------------------------------------------

def run_nmap_discovery(target: str) -> list[str]:
    """
    Ping sweep to find live hosts on the target subnet.
    Returns a list of IP address strings.
    """
    print(f"[nmap] Starting host discovery on {target}")
    cmd = ["nmap", "-sn", "--open", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print("[nmap] Discovery timed out")
        return []
    except FileNotFoundError:
        print("[nmap] ERROR: nmap not found. Install with: sudo apt install nmap")
        return []

    hosts = re.findall(r"Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)", result.stdout)
    print(f"[nmap] Found {len(hosts)} live host(s): {hosts}")
    return hosts


def run_nmap_service_scan(hosts: list[str]) -> list[dict]:
    """
    Service/version scan against confirmed live hosts.
    Returns a list of host dicts, each containing a list of open port dicts.

    Each host dict:
      { "ip": str, "hostname": str, "ports": [ { "port": int, "protocol": str,
                                                  "state": str, "service": str,
                                                  "version": str }, ... ] }
    """
    if not hosts:
        return []

    print(f"[nmap] Starting service scan on {len(hosts)} host(s)")
    targets = " ".join(hosts)
    cmd = f"nmap -sV -T4 --open -oX - {targets}"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        print("[nmap] Service scan timed out")
        return []

    return _parse_nmap_xml(result.stdout)


def _parse_nmap_xml(xml_output: str) -> list[dict]:
    """
    Minimal XML parse of nmap -oX output without requiring lxml.
    Pulls host IPs, optional hostnames, and open port/service records.
    """
    import xml.etree.ElementTree as ET

    parsed_hosts = []

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        print(f"[nmap] XML parse error: {e}")
        return []

    for host_el in root.findall("host"):
        # Only include hosts with status "up"
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = ""
        hostname = ""

        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")

        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                service_name = ""
                service_version = ""
                if service_el is not None:
                    service_name    = service_el.get("name", "")
                    product         = service_el.get("product", "")
                    version         = service_el.get("version", "")
                    service_version = f"{product} {version}".strip()

                ports.append({
                    "port":     int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                    "state":    "open",
                    "service":  service_name,
                    "version":  service_version,
                })

        if ip:
            parsed_hosts.append({"ip": ip, "hostname": hostname, "ports": ports})

    return parsed_hosts


# ---------------------------------------------------------------------------
# tshark helpers
# ---------------------------------------------------------------------------

def run_tshark_capture(interface: str = "wlan0", duration: int = DEFAULT_DURATION) -> list[dict]:
    """
    Passive traffic capture for `duration` seconds.
    Returns a list of notable event dicts.

    Each event dict:
      { "timestamp": str, "src_ip": str, "dst_ip": str,
        "protocol": str, "info": str, "severity": str }

    Severity levels: "info", "warning", "critical"
    """
    print(f"[tshark] Capturing on {interface} for {duration}s")

    cmd = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-T", "fields",
        "-e", "frame.time",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
        "-E", "separator=|",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30)
    except subprocess.TimeoutExpired:
        print("[tshark] Capture timed out")
        return []
    except FileNotFoundError:
        print("[tshark] ERROR: tshark not found. Install with: sudo apt install tshark")
        return []

    return _parse_tshark_output(result.stdout)


def _parse_tshark_output(raw: str) -> list[dict]:
    """
    Parse pipe-delimited tshark field output into event dicts.
    Flags notable protocols and patterns with an appropriate severity.
    """
    events = []

    # Protocols that warrant at least a warning
    sensitive_protocols = {"telnet", "ftp", "http", "dns", "ldap", "snmp"}
    critical_protocols  = {"telnet", "ftp"}

    for line in raw.splitlines():
        parts = line.split("|")
        if len(parts) < 5:
            continue

        timestamp, src_ip, dst_ip, protocol, info = (p.strip() for p in parts[:5])

        proto_lower = protocol.lower()
        if proto_lower in critical_protocols:
            severity = "critical"
        elif proto_lower in sensitive_protocols:
            severity = "warning"
        else:
            severity = "info"

        # Only record events worth noting (skip pure noise)
        if severity == "info" and proto_lower not in {"arp", "icmp", "mdns"}:
            continue

        events.append({
            "timestamp": timestamp,
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "protocol":  protocol,
            "info":      info[:500],   # cap length for DB storage
            "severity":  severity,
        })

    print(f"[tshark] Captured {len(events)} notable event(s)")
    return events


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(scan: Scan, hosts: list[Host], events: list[TrafficEvent]) -> str:
    """
    Build a plain-text summary report from scan results.
    Returns the report text and also saves it to REPORT_DIR.
    """
    lines = []
    sep = "-" * 60

    lines.append("PI INTRUSION TESTING APPLIANCE")
    lines.append("Network Security Assessment Report")
    lines.append(sep)
    lines.append(f"Scan ID    : {scan.id}")
    lines.append(f"Target     : {scan.target}")
    lines.append(f"Started    : {scan.started_at}")
    lines.append(f"Completed  : {scan.completed_at}")
    lines.append(f"Status     : {scan.status}")
    lines.append(sep)

    lines.append(f"\nHOSTS DISCOVERED ({len(hosts)} total)\n")
    for host in hosts:
        lines.append(f"  {host.ip_address}  {host.hostname or '(no hostname)'}")
        for port in host.open_ports:
            lines.append(f"    {port.port}/{port.protocol}  {port.service}  {port.version or ''}")
        lines.append("")

    lines.append(sep)

    warning_events  = [e for e in events if e.severity in ("warning", "critical")]
    lines.append(f"\nNOTABLE TRAFFIC EVENTS ({len(warning_events)} flagged)\n")
    if warning_events:
        for ev in warning_events:
            lines.append(f"  [{ev.severity.upper()}] {ev.protocol}  {ev.src_ip} -> {ev.dst_ip}")
            lines.append(f"    {ev.info}")
            lines.append("")
    else:
        lines.append("  No high-severity traffic events detected.\n")

    lines.append(sep)
    lines.append("\nEND OF REPORT\n")

    report_text = "\n".join(lines)

    os.makedirs(REPORT_DIR, exist_ok=True)
    report_path = os.path.join(REPORT_DIR, f"scan_{scan.id}.txt")
    with open(report_path, "w") as f:
        f.write(report_text)

    print(f"[report] Saved to {report_path}")
    return report_text


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_scan(target: str = DEFAULT_TARGET,
             capture_seconds: int = DEFAULT_DURATION,
             interface: str = "wlan0") -> int:
    """
    Full scan workflow:
      1. Create a Scan record in the database
      2. Run Nmap discovery, then service scan
      3. Run tshark capture in parallel (simple sequential for Sprint 2)
      4. Persist all results to the database
      5. Generate and store a text report
      6. Return the scan ID

    This function is called directly by Flask.
    """
    # 1. Open scan record
    scan = Scan(
        target       = target,
        started_at   = datetime.datetime.utcnow(),
        status       = "running",
    )
    db.session.add(scan)
    db.session.commit()
    print(f"[scan] Started scan ID {scan.id} against {target}")

    try:
        # 2. Nmap
        live_ips    = run_nmap_discovery(target)
        host_data   = run_nmap_service_scan(live_ips)

        # Persist hosts and ports
        host_records = []
        for hd in host_data:
            host = Host(
                scan_id    = scan.id,
                ip_address = hd["ip"],
                hostname   = hd["hostname"] or None,
            )
            db.session.add(host)
            db.session.flush()   # get host.id before adding ports

            for pd in hd["ports"]:
                port = OpenPort(
                    host_id  = host.id,
                    port     = pd["port"],
                    protocol = pd["protocol"],
                    state    = pd["state"],
                    service  = pd["service"],
                    version  = pd["version"] or None,
                )
                db.session.add(port)

            host_records.append(host)

        db.session.commit()

        # 3. tshark
        raw_events   = run_tshark_capture(interface=interface, duration=capture_seconds)
        event_records = []
        for ev in raw_events:
            event = TrafficEvent(
                scan_id   = scan.id,
                timestamp = ev["timestamp"],
                src_ip    = ev["src_ip"],
                dst_ip    = ev["dst_ip"],
                protocol  = ev["protocol"],
                info      = ev["info"],
                severity  = ev["severity"],
            )
            db.session.add(event)
            event_records.append(event)

        db.session.commit()

        # 4. Report
        report_text = generate_report(scan, host_records, event_records)
        report = Report(
            scan_id     = scan.id,
            generated_at = datetime.datetime.utcnow(),
            content     = report_text,
        )
        db.session.add(report)

        # 5. Mark scan complete
        scan.completed_at = datetime.datetime.utcnow()
        scan.status       = "complete"
        db.session.commit()

        print(f"[scan] Scan {scan.id} complete.")

    except Exception as e:
        scan.status = "failed"
        db.session.commit()
        print(f"[scan] Scan {scan.id} FAILED: {e}")
        raise

    return scan.id


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pi Intrusion Testing Appliance - Orchestrator")
    parser.add_argument("--target",    default=DEFAULT_TARGET,   help="Target subnet (e.g. 192.168.1.0/24)")
    parser.add_argument("--duration",  default=DEFAULT_DURATION, type=int, help="tshark capture duration in seconds")
    parser.add_argument("--interface", default="wlan0",          help="Network interface for tshark")
    args = parser.parse_args()

    # When run directly, set up a minimal Flask app context so SQLAlchemy works
    from FinalApp import create_app
    app = create_app()
    with app.app_context():
        run_scan(target=args.target, capture_seconds=args.duration, interface=args.interface)
