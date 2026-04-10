import sqlite3
import uuid
import time
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "instance" / "results.db"

SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS scan_sessions (
    id           TEXT PRIMARY KEY,
    target_cidr  TEXT NOT NULL,
    status       TEXT NOT NULL
                 CHECK(status IN ('running', 'completed', 'failed')),
    started_at   INTEGER NOT NULL,
    completed_at INTEGER
);

CREATE TABLE IF NOT EXISTS hosts (
    id           TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES scan_sessions(id),
    ip_address   TEXT NOT NULL,
    hostname     TEXT,
    os_guess     TEXT,
    first_seen   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hosts_session ON hosts(session_id);

CREATE TABLE IF NOT EXISTS ports (
    id              TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL REFERENCES hosts(id),
    port_number     INTEGER NOT NULL,
    protocol        TEXT NOT NULL
                    CHECK(protocol IN ('tcp', 'udp')),
    state           TEXT NOT NULL,
    service_name    TEXT,
    service_version TEXT
);

CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);

CREATE TABLE IF NOT EXISTS traffic_findings (
    id                    TEXT PRIMARY KEY,
    session_id            TEXT NOT NULL REFERENCES scan_sessions(id),
    pcap_path             TEXT NOT NULL,
    capture_start         INTEGER NOT NULL,
    capture_end           INTEGER,
    protocol_summary      TEXT,
    cleartext_creds_found INTEGER NOT NULL DEFAULT 0
                          CHECK(cleartext_creds_found IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_traffic_session ON traffic_findings(session_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id         TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES scan_sessions(id),
    tool_name  TEXT NOT NULL,
    arguments  TEXT NOT NULL,
    pid        INTEGER,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);

CREATE TABLE IF NOT EXISTS reports (
    id           TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES scan_sessions(id),
    file_path    TEXT NOT NULL,
    format       TEXT NOT NULL
                 CHECK(format IN ('html', 'json', 'text')),
    generated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_session ON reports(session_id);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    """
    Create all tables if they don't exist yet.
    Safe to call every time orchestrator.py starts —
    IF NOT EXISTS means it won't overwrite existing data.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.executescript(SCHEMA)


# ── scan_sessions ─────────────────────────────────────────────────────────────

def create_session(target_cidr: str) -> str:
    """Open a new scan session. Returns the new session ID."""
    session_id = str(uuid.uuid4())
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO scan_sessions (id, target_cidr, status, started_at) VALUES (?, ?, 'running', ?)",
            (session_id, target_cidr, int(time.time()))
        )
    return session_id


def complete_session(session_id: str, status: str = "completed") -> None:
    """Mark a session as completed or failed."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE scan_sessions SET status = ?, completed_at = ? WHERE id = ?",
            (status, int(time.time()), session_id)
        )


def get_session(session_id: str) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM scan_sessions WHERE id = ?", (session_id,)
        ).fetchone()


# ── hosts ─────────────────────────────────────────────────────────────────────

def insert_host(session_id: str, ip_address: str,
                hostname: str | None = None,
                os_guess: str | None = None) -> str:
    """Insert a discovered host. Returns the new host ID."""
    host_id = str(uuid.uuid4())
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO hosts (id, session_id, ip_address, hostname, os_guess, first_seen) VALUES (?, ?, ?, ?, ?, ?)",
            (host_id, session_id, ip_address, hostname, os_guess, int(time.time()))
        )
    return host_id


def get_hosts(session_id: str) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM hosts WHERE session_id = ? ORDER BY ip_address",
            (session_id,)
        ).fetchall()


# ── ports ─────────────────────────────────────────────────────────────────────

def insert_port(host_id: str, port_number: int, protocol: str, state: str,
                service_name: str | None = None,
                service_version: str | None = None) -> str:
    """Insert an open port for a host. Returns the new port ID."""
    port_id = str(uuid.uuid4())
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO ports (id, host_id, port_number, protocol, state, service_name, service_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (port_id, host_id, port_number, protocol, state, service_name, service_version)
        )
    return port_id


def get_ports(host_id: str) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM ports WHERE host_id = ? ORDER BY port_number",
            (host_id,)
        ).fetchall()


# ── traffic_findings ──────────────────────────────────────────────────────────

def insert_traffic_finding(session_id: str, pcap_path: str) -> str:
    """Open a traffic finding record when tshark starts. Returns the finding ID."""
    finding_id = str(uuid.uuid4())
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO traffic_findings (id, session_id, pcap_path, capture_start) VALUES (?, ?, ?, ?)",
            (finding_id, session_id, pcap_path, int(time.time()))
        )
    return finding_id


def complete_traffic_finding(finding_id: str, protocol_summary: str,
                              cleartext_creds_found: bool) -> None:
    """Update a traffic finding record when tshark finishes."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE traffic_findings SET capture_end = ?, protocol_summary = ?, cleartext_creds_found = ? WHERE id = ?",
            (int(time.time()), protocol_summary, int(cleartext_creds_found), finding_id)
        )


# ── audit_log ─────────────────────────────────────────────────────────────────

def insert_audit_entry(session_id: str, tool_name: str,
                        arguments: str, pid: int | None = None) -> str:
    """Log a tool invocation when it starts. Returns the log entry ID."""
    entry_id = str(uuid.uuid4())
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO audit_log (id, session_id, tool_name, arguments, pid, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (entry_id, session_id, tool_name, arguments, pid, int(time.time()))
        )
    return entry_id


def complete_audit_entry(entry_id: str) -> None:
    """Stamp the end time on an audit log entry when the tool exits."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE audit_log SET ended_at = ? WHERE id = ?",
            (int(time.time()), entry_id)
        )


def get_audit_log(session_id: str) -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM audit_log WHERE session_id = ? ORDER BY started_at",
            (session_id,)
        ).fetchall()


# ── reports ───────────────────────────────────────────────────────────────────

def insert_report(session_id: str, file_path: str, fmt: str) -> str:
    """Record a generated report file. Returns the report ID."""
    report_id = str(uuid.uuid4())
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO reports (id, session_id, file_path, format, generated_at) VALUES (?, ?, ?, ?, ?)",
            (report_id, session_id, file_path, fmt, int(time.time()))
        )
    return report_id
