"""
orchestrator.py
Pi Intrusion Testing Appliance - Core Orchestration Layer
Team 3 / ITP 258 Sprint 2

Responsibilities:
  - Run Nmap host discovery and port/service scan against a target subnet
  - Run tshark passive capture in parallel
  - Parse results and write structured records to the SQLite database
  - Produce a text summary report including flagged concerns with search terms

Usage (direct):
  python orchestrator.py --target 192.168.1.0/24 --duration 30

Usage (from Flask):
  from orchestrator import run_scan
  scan_id = run_scan(target="192.168.1.0/24", capture_seconds=30)
"""

import subprocess
import datetime
import time
import re
import os
import argparse

from utils.db import (
    init_db,
    create_session,
    complete_session,
    insert_host,
    insert_port,
    insert_traffic_finding,
    complete_traffic_finding,
    insert_audit_entry,
    complete_audit_entry,
    insert_report,
)

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DEFAULT_TARGET   = "192.168.1.0/24"
DEFAULT_DURATION = 30
REPORT_DIR       = "reports"


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


def run_nmap_service_scan(session_id: str, hosts: list[str]) -> list[str]:
    """
    Service/version scan against confirmed live hosts.
    Writes results directly to the database via Channing's functions.
    Returns a list of host_ids inserted.
    """
    if not hosts:
        return []

    print(f"[nmap] Starting service scan on {len(hosts)} host(s)")
    targets = " ".join(hosts)
    cmd = f"nmap -sV -T4 --open -oX - {targets}"

    entry_id = insert_audit_entry(session_id, "nmap", cmd)

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        print("[nmap] Service scan timed out")
        complete_audit_entry(entry_id)
        return []

    complete_audit_entry(entry_id)

    parsed = _parse_nmap_xml(result.stdout)
    host_ids = []

    for hd in parsed:
        host_id = insert_host(
            session_id=session_id,
            ip_address=hd["ip"],
            hostname=hd["hostname"] or None,
        )
        for pd in hd["ports"]:
            insert_port(
                host_id=host_id,
                port_number=pd["port"],
                protocol=pd["protocol"],
                state=pd["state"],
                service_name=pd["service"] or None,
                service_version=pd["version"] or None,
            )
        host_ids.append(host_id)

    return host_ids


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

def run_tshark_capture(session_id: str, interface: str = "wlan0",
                       duration: int = DEFAULT_DURATION,
                       stop_event=None) -> str:
    """
    Passive traffic capture for `duration` seconds.
    Saves a pcap file and writes a traffic_finding record.
    Returns the finding_id.
    """
    print(f"[tshark] Capturing on {interface} for {duration}s")

    os.makedirs(REPORT_DIR, exist_ok=True)
    pcap_path = os.path.join(REPORT_DIR, f"capture_{session_id}.pcap")

    cmd = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-w", pcap_path,
    ]

    entry_id   = insert_audit_entry(session_id, "tshark", " ".join(cmd))
    finding_id = insert_traffic_finding(session_id, pcap_path)

    cleartext_found = False
    protocol_summary = ""

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Poll every second so we can honour a stop request
        for _ in range(duration + 30):
            if stop_event is not None and stop_event.is_set():
                proc.terminate()
                print("[tshark] Capture terminated by stop request")
                break
            if proc.poll() is not None:
                break
            time.sleep(1)
        else:
            proc.terminate()

        # Quick post-capture analysis for cleartext protocols
        analysis_cmd = [
            "tshark", "-r", pcap_path,
            "-T", "fields", "-e", "_ws.col.Protocol",
        ]
        analysis = subprocess.run(analysis_cmd, capture_output=True, text=True, timeout=30)
        protocols = [p.strip().lower() for p in analysis.stdout.splitlines() if p.strip()]
        cleartext_found = any(p in {"telnet", "ftp", "http"} for p in protocols)

        from collections import Counter
        counts = Counter(protocols)
        protocol_summary = ", ".join(f"{p}:{c}" for p, c in counts.most_common(10))

    except subprocess.TimeoutExpired:
        print("[tshark] Capture timed out")
    except FileNotFoundError:
        print("[tshark] ERROR: tshark not found. Install with: sudo apt install tshark")

    complete_audit_entry(entry_id)
    complete_traffic_finding(finding_id, protocol_summary, cleartext_found)

    print(f"[tshark] Capture complete. Cleartext credentials found: {cleartext_found}")
    return finding_id


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(session_id: str, target: str,
                    host_ids: list[str], finding_id: str) -> str:
    """
    Build a plain-text summary report from scan results.
    Saves to REPORT_DIR and records in the reports table.
    Returns the report file path.

    Sprint 2: includes a "Flagged Concerns" section grouped by severity
    at the top of the report, with search terms under each flag, followed
    by the hosts and traffic breakdown.
    """
    from utils.db import get_hosts, get_ports, get_connection
    # flag_findings lives in FinalApp to keep it alongside its constants
    # (FLAGGED_PORTS, INFO_PORTS, etc.). Importing at call time avoids a
    # circular import on startup.
    from FinalApp import flag_findings

    lines = []
    sep = "-" * 60

    lines.append("NETWORK LOCK SECURITY")
    lines.append("Network Security Assessment Report")
    lines.append(sep)
    lines.append(f"Session ID : {session_id}")
    lines.append(f"Target     : {target}")
    lines.append(f"Generated  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(sep)

    # ── Gather data once, use it for both flags and the host/traffic sections ─
    hosts = get_hosts(session_id)

    # Flatten hosts+ports into the flat dict shape flag_findings() expects
    port_findings = []
    hosts_with_ports = []
    for host in hosts:
        host_ports = get_ports(host["id"])
        hosts_with_ports.append((host, host_ports))
        for port in host_ports:
            port_findings.append({
                "host":            host["ip_address"],
                "port_number":     port["port_number"],
                "protocol":        port["protocol"],
                "state":           port["state"],
                "service_name":    port["service_name"],
                "service_version": port["service_version"],
            })

    # Pull traffic finding (may be None if the capture never ran)
    with get_connection() as conn:
        finding = conn.execute(
            "SELECT * FROM traffic_findings WHERE id = ?", (finding_id,)
        ).fetchone() if finding_id else None

    traffic_findings = [finding] if finding else []

    # ── Flagged Concerns section ────────────────────────────────────────
    flags = flag_findings(port_findings, traffic_findings)

    lines.append("\nFLAGGED CONCERNS\n")
    if flags:
        severity_order = ["critical", "high", "medium", "info"]
        total_by_sev = {sev: sum(1 for f in flags if f["severity"] == sev)
                        for sev in severity_order}
        summary_bits = [f"{total_by_sev[s]} {s}" for s in severity_order if total_by_sev[s]]
        lines.append(f"  Summary: {', '.join(summary_bits)}")
        lines.append("")

        for sev in severity_order:
            group = [f for f in flags if f["severity"] == sev]
            if not group:
                continue
            lines.append(f"  [{sev.upper()}]  ({len(group)} finding{'s' if len(group) != 1 else ''})")
            for flag in group:
                target_str = flag["host"]
                if flag["port"] is not None:
                    target_str = f"{flag['host']}:{flag['port']}"
                lines.append(f"    - {target_str:<24}  {flag['reason']}")
                # Inline search terms so a reviewer reading the plain-text
                # report has somewhere to look up each finding.
                terms = flag.get("search_terms") or []
                if terms:
                    terms_str = " | ".join(terms)
                    lines.append(f"      search: {terms_str}")
            lines.append("")
    else:
        lines.append("  No concerns flagged for this scan.\n")

    lines.append(sep)

    # ── Hosts breakdown ─────────────────────────────────────────────────
    lines.append(f"\nHOSTS DISCOVERED ({len(hosts)} total)\n")
    for host, ports in hosts_with_ports:
        lines.append(f"  {host['ip_address']}  {host['hostname'] or '(no hostname)'}")
        for port in ports:
            lines.append(f"    {port['port_number']}/{port['protocol']}  "
                         f"{port['service_name'] or ''}  {port['service_version'] or ''}")
        lines.append("")

    lines.append(sep)

    # ── Traffic analysis ────────────────────────────────────────────────
    if finding:
        lines.append("\nTRAFFIC ANALYSIS\n")
        lines.append(f"  PCAP file        : {finding['pcap_path']}")
        lines.append(f"  Protocol summary : {finding['protocol_summary'] or 'N/A'}")
        lines.append(f"  Cleartext creds  : {'YES - REVIEW IMMEDIATELY' if finding['cleartext_creds_found'] else 'None detected'}")
        lines.append("")

    lines.append(sep)
    lines.append("\nEND OF REPORT\n")

    report_text = "\n".join(lines)

    os.makedirs(REPORT_DIR, exist_ok=True)
    report_path = os.path.join(REPORT_DIR, f"report_{session_id}.txt")
    with open(report_path, "w") as f:
        f.write(report_text)

    insert_report(session_id, report_path, "text")
    print(f"[report] Saved to {report_path}")
    return report_path


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_scan(target: str = DEFAULT_TARGET,
             capture_seconds: int = DEFAULT_DURATION,
             interface: str = "wlan0",
             stop_event=None) -> str:
    """
    Full scan workflow:
      1. Create a session record in the database
      2. Run Nmap discovery then service scan
      3. Run tshark passive capture
      4. Generate and store a text report
      5. Mark session complete
      6. Return the session ID

    stop_event: threading.Event — if set, the scan exits early and is marked failed.
    """
    init_db()

    session_id = create_session(target)
    print(f"[scan] Started session {session_id} against {target}")

    def stopped():
        return stop_event is not None and stop_event.is_set()

    host_ids   = []
    finding_id = None

    try:
        # Nmap discovery
        if not stopped():
            live_ips = run_nmap_discovery(target)
        else:
            live_ips = []

        # Nmap service scan
        if not stopped():
            host_ids = run_nmap_service_scan(session_id, live_ips)

        # tshark
        if not stopped():
            finding_id = run_tshark_capture(
                session_id=session_id,
                interface=interface,
                duration=capture_seconds,
                stop_event=stop_event,
            )

        # Generate report from whatever was collected (full or partial)
        generate_report(session_id, target, host_ids, finding_id)

        complete_session(session_id, "completed")
        if stopped():
            print(f"[scan] Session {session_id} stopped early — partial results saved.")
        else:
            print(f"[scan] Session {session_id} complete.")

    except Exception as e:
        complete_session(session_id, "failed")
        print(f"[scan] Session {session_id} FAILED: {e}")
        raise

    return session_id


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pi Intrusion Testing Appliance - Orchestrator")
    parser.add_argument("--target",    default=DEFAULT_TARGET,   help="Target subnet (e.g. 192.168.1.0/24)")
    parser.add_argument("--duration",  default=DEFAULT_DURATION, type=int, help="tshark capture duration in seconds")
    parser.add_argument("--interface", default="wlan0",          help="Network interface for tshark")
    args = parser.parse_args()

    run_scan(target=args.target, capture_seconds=args.duration, interface=args.interface)
