import pytest
from FinalApp import flag_findings


# ═════════════════════════════════════════════════════════════════════════════
# DUMMY DATASETS
#
# Key names match utils/db.py schema exactly:
#   port_number     (integer)
#   service_version (string, matches _parse_nmap_xml output in orchestrator.py)
#   service_name    (string)
#   protocol        ("tcp" or "udp")
#   state           ("open")
#   host            (added by caller when joining hosts + ports tables)
# ═════════════════════════════════════════════════════════════════════════════

# ── Dataset A: Office network with legacy Windows server ─────────────────────
# Telnet and SMB on the same host, RDP exposed on another,
# and an end-of-life Apache web server left running somewhere.
DATASET_A_CONCERNING = [
    {
        "host":            "192.168.1.10",
        "port_number":     23,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "telnet",
        "service_version": "",
    },
    {
        "host":            "192.168.1.10",
        "port_number":     445,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "microsoft-ds",
        "service_version": "Windows Server 2008",
    },
    {
        "host":            "192.168.1.15",
        "port_number":     3389,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "ms-wbt-server",
        "service_version": "",
    },
    {
        "host":            "192.168.1.20",
        "port_number":     80,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "http",
        "service_version": "Apache/2.2.34",
    },
]

# ── Dataset B: Construction company NAS and old SSH ──────────────────────────
# NFS share exposed to the whole subnet, an outdated OpenSSH version
# with known CVEs, and MySQL left open after a server migration.
DATASET_B_CONCERNING = [
    {
        "host":            "10.0.0.5",
        "port_number":     2049,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "nfs",
        "service_version": "",
    },
    {
        "host":            "10.0.0.8",
        "port_number":     22,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "ssh",
        "service_version": "OpenSSH 5.3",
    },
    {
        "host":            "10.0.0.12",
        "port_number":     3306,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "mysql",
        "service_version": "MySQL 5.5.62",
    },
]

# ── Dataset C: Forgotten legacy server ───────────────────────────────────────
# vsftpd 2.3.4 — infamous for containing a deliberate backdoor (CVE-2011-2523),
# IIS 6.0 which is end-of-life with remote code execution CVEs,
# and VNC left open with no mention of authentication.
DATASET_C_CRITICAL = [
    {
        "host":            "172.16.0.5",
        "port_number":     21,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "ftp",
        "service_version": "vsftpd 2.3.4",
    },
    {
        "host":            "172.16.0.5",
        "port_number":     80,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "http",
        "service_version": "IIS/6.0",
    },
    {
        "host":            "172.16.0.9",
        "port_number":     5900,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "vnc",
        "service_version": "",
    },
]

# ── Dataset D: Clean network — nothing concerning ─────────────────────────────
# HTTPS only, modern SSH on a non-standard port (not in flag list),
# and a DNS server. Should produce zero flags.
DATASET_D_CLEAN = [
    {
        "host":            "192.168.50.1",
        "port_number":     443,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "https",
        "service_version": "nginx 1.24.0",
    },
    {
        "host":            "192.168.50.2",
        "port_number":     2222,
        "protocol":        "tcp",
        "state":           "open",
        "service_name":    "ssh",
        "service_version": "OpenSSH 9.2",
    },
    {
        "host":            "192.168.50.1",
        "port_number":     53,
        "protocol":        "udp",
        "state":           "open",
        "service_name":    "dns",
        "service_version": "",
    },
]


# ═════════════════════════════════════════════════════════════════════════════
# TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestFlagFindingsBasicBehaviour:
    """Sanity checks — correct return type, required keys, valid severity values."""

    def test_returns_a_list(self):
        """flag_findings() must always return a list, never None."""
        result = flag_findings([])
        assert isinstance(result, list)

    def test_empty_input_returns_empty_list(self):
        """No findings in → no flags out."""
        result = flag_findings([])
        assert result == []

    def test_each_flag_has_required_keys(self):
        """Every returned flag dict must have host, port, severity, and reason."""
        result = flag_findings(DATASET_A_CONCERNING)
        for flag in result:
            assert "host"     in flag, f"Flag missing 'host': {flag}"
            assert "port"     in flag, f"Flag missing 'port': {flag}"
            assert "severity" in flag, f"Flag missing 'severity': {flag}"
            assert "reason"   in flag, f"Flag missing 'reason': {flag}"

    def test_severity_values_are_valid(self):
        """Severity must be one of the four defined levels — nothing else."""
        valid_severities = {"critical", "high", "medium", "info"}
        all_findings = (
            DATASET_A_CONCERNING
            + DATASET_B_CONCERNING
            + DATASET_C_CRITICAL
        )
        result = flag_findings(all_findings)
        for flag in result:
            assert flag["severity"] in valid_severities, (
                f"Unexpected severity '{flag['severity']}' in flag: {flag}"
            )


class TestDatasetA:
    """Office network — Telnet, SMB, RDP, and a legacy Apache server."""

    def test_telnet_flagged_as_critical(self):
        """Port 23 (Telnet) must always be flagged critical — plaintext credentials."""
        result = flag_findings(DATASET_A_CONCERNING)
        telnet_flags = [f for f in result if f["port"] == 23]
        assert len(telnet_flags) >= 1, "Telnet on port 23 was not flagged"
        assert telnet_flags[0]["severity"] == "critical"

    def test_smb_flagged_as_critical(self):
        """Port 445 (SMB) must be flagged critical — top ransomware entry point."""
        result = flag_findings(DATASET_A_CONCERNING)
        smb_flags = [f for f in result if f["port"] == 445]
        assert len(smb_flags) >= 1, "SMB on port 445 was not flagged"
        assert smb_flags[0]["severity"] == "critical"

    def test_rdp_flagged_as_critical(self):
        """Port 3389 (RDP) must be flagged critical."""
        result = flag_findings(DATASET_A_CONCERNING)
        rdp_flags = [f for f in result if f["port"] == 3389]
        assert len(rdp_flags) >= 1, "RDP on port 3389 was not flagged"
        assert rdp_flags[0]["severity"] == "critical"

    def test_old_apache_version_flagged(self):
        """
        Apache/2.2 in the service_version field should trigger a version flag.
        This tests that flag_findings() reads service_version (not 'version').
        """
        result = flag_findings(DATASET_A_CONCERNING)
        apache_flags = [f for f in result if "Apache" in f.get("reason", "")]
        assert len(apache_flags) >= 1, (
            "Apache/2.2 in service_version was not flagged — "
            "check that flag_findings() reads 'service_version', not 'version'"
        )

    def test_multiple_flags_on_same_host(self):
        """A single host with both Telnet and SMB open should produce at least 2 flags."""
        result = flag_findings(DATASET_A_CONCERNING)
        host_10_flags = [f for f in result if f["host"] == "192.168.1.10"]
        assert len(host_10_flags) >= 2, (
            "192.168.1.10 has Telnet and SMB open — expected at least 2 flags, "
            f"got {len(host_10_flags)}"
        )


class TestDatasetB:
    """Construction company NAS — NFS, outdated SSH, exposed MySQL."""

    def test_nfs_flagged(self):
        """Port 2049 (NFS) must be flagged — can allow unauthenticated file access."""
        result = flag_findings(DATASET_B_CONCERNING)
        nfs_flags = [f for f in result if f["port"] == 2049]
        assert len(nfs_flags) >= 1, "NFS on port 2049 was not flagged"

    def test_outdated_openssh_flagged_critical(self):
        """
        OpenSSH 5.3 in the service_version field should trigger a critical flag.
        This tests that flag_findings() reads service_version (not 'version').
        """
        result = flag_findings(DATASET_B_CONCERNING)
        ssh_version_flags = [
            f for f in result
            if f["port"] == 22 and "OpenSSH" in f.get("reason", "")
        ]
        assert len(ssh_version_flags) >= 1, (
            "OpenSSH 5.3 in service_version was not flagged — "
            "check that flag_findings() reads 'service_version', not 'version'"
        )
        assert ssh_version_flags[0]["severity"] == "critical", (
            f"OpenSSH 5.3 should be critical, got: {ssh_version_flags[0]['severity']}"
        )

    def test_mysql_exposed_flagged(self):
        """Port 3306 (MySQL) visible on the network must be flagged."""
        result = flag_findings(DATASET_B_CONCERNING)
        mysql_flags = [f for f in result if f["port"] == 3306]
        assert len(mysql_flags) >= 1, "MySQL on port 3306 was not flagged"

    def test_all_three_hosts_produce_flags(self):
        """Every host in dataset B has at least one issue — all should appear in results."""
        result = flag_findings(DATASET_B_CONCERNING)
        flagged_hosts = {f["host"] for f in result}
        expected_hosts = {"10.0.0.5", "10.0.0.8", "10.0.0.12"}
        assert expected_hosts == flagged_hosts, (
            f"Expected flags on all three hosts, only got: {flagged_hosts}"
        )


class TestDatasetC:
    """Legacy server — backdoored FTP, IIS 6.0, and open VNC."""

    def test_vsftpd_backdoor_flagged_critical(self):
        """
        vsftpd 2.3.4 contains a deliberate backdoor (CVE-2011-2523).
        Must be flagged critical and the reason string must call it out.
        """
        result = flag_findings(DATASET_C_CRITICAL)
        vsftpd_flags = [
            f for f in result
            if f["port"] == 21 and (
                "backdoor" in f.get("reason", "").lower()
                or "vsftpd" in f.get("reason", "").lower()
            )
        ]
        assert len(vsftpd_flags) >= 1, (
            "vsftpd 2.3.4 backdoor in service_version was not specifically flagged"
        )
        assert vsftpd_flags[0]["severity"] == "critical"

    def test_iis6_flagged_critical(self):
        """
        IIS/6.0 in service_version is end-of-life with remote code execution CVEs.
        Must be flagged critical.
        """
        result = flag_findings(DATASET_C_CRITICAL)
        iis_flags = [f for f in result if "IIS" in f.get("reason", "")]
        assert len(iis_flags) >= 1, (
            "IIS/6.0 in service_version was not flagged — "
            "check that flag_findings() reads 'service_version', not 'version'"
        )
        assert iis_flags[0]["severity"] == "critical"

    def test_vnc_flagged(self):
        """Port 5900 (VNC) must be flagged — historically weak authentication."""
        result = flag_findings(DATASET_C_CRITICAL)
        vnc_flags = [f for f in result if f["port"] == 5900]
        assert len(vnc_flags) >= 1, "VNC on port 5900 was not flagged"

    def test_single_host_multiple_critical_flags(self):
        """
        172.16.0.5 has both vsftpd 2.3.4 and IIS/6.0.
        Both should appear as separate critical flags on the same host.
        """
        result = flag_findings(DATASET_C_CRITICAL)
        critical_on_host = [
            f for f in result
            if f["host"] == "172.16.0.5" and f["severity"] == "critical"
        ]
        assert len(critical_on_host) >= 2, (
            f"Expected at least 2 critical flags on 172.16.0.5, "
            f"got {len(critical_on_host)}: {critical_on_host}"
        )


class TestDatasetD:
    """Clean network — HTTPS, modern SSH on non-standard port, DNS."""

    def test_clean_network_produces_no_flags(self):
        """
        A properly configured network should return zero flags.
        If this test fails, flag_findings() is producing false positives.
        """
        result = flag_findings(DATASET_D_CLEAN)
        assert result == [], (
            f"Expected no flags on a clean network, got {len(result)} flag(s):\n"
            + "\n".join(f"  - {f}" for f in result)
        )

    def test_modern_openssh_not_flagged(self):
        """
        OpenSSH 9.2 on a non-standard port should not trigger any version flag.
        Confirms the version check is a substring match, not a blanket SSH flag.
        """
        result = flag_findings(DATASET_D_CLEAN)
        ssh_flags = [f for f in result if "OpenSSH" in f.get("reason", "")]
        assert ssh_flags == [], (
            f"Modern OpenSSH 9.2 should not be flagged, but got: {ssh_flags}"
        )


class TestEdgeCases:
    """Unusual or missing input values that should not crash the function."""

    def test_missing_service_version_does_not_crash(self):
        """
        A finding with no 'service_version' key should still be processed.
        Port-based flagging should still work.
        """
        findings = [{
            "host":         "192.168.1.1",
            "port_number":  23,
            "protocol":     "tcp",
            "state":        "open",
            "service_name": "telnet",
            # service_version intentionally omitted
        }]
        result = flag_findings(findings)
        assert any(f["port"] == 23 for f in result), (
            "Port 23 should still be flagged even when service_version is absent"
        )

    def test_none_service_version_does_not_crash(self):
        """
        db.py stores NULL as None — flag_findings() must handle None gracefully
        without throwing an AttributeError on .lower().
        """
        findings = [{
            "host":            "192.168.1.1",
            "port_number":     445,
            "protocol":        "tcp",
            "state":           "open",
            "service_name":    "microsoft-ds",
            "service_version": None,   # ← NULL from SQLite
        }]
        result = flag_findings(findings)
        assert any(f["port"] == 445 for f in result), (
            "Port 445 should still be flagged even when service_version is None"
        )

    def test_unknown_port_produces_no_flag(self):
        """A port not in FLAGGED_PORTS with a clean version string should not be flagged."""
        findings = [{
            "host":            "192.168.1.1",
            "port_number":     9999,
            "protocol":        "tcp",
            "state":           "open",
            "service_name":    "unknown",
            "service_version": "",
        }]
        result = flag_findings(findings)
        assert result == [], f"Port 9999 should not be flagged, got: {result}"

    def test_mixed_dataset_clean_hosts_stay_clean(self):
        """
        Running all four datasets together should not cause the clean hosts
        from Dataset D to pick up any flags.
        """
        all_findings = (
            DATASET_A_CONCERNING
            + DATASET_B_CONCERNING
            + DATASET_C_CRITICAL
            + DATASET_D_CLEAN
        )
        result = flag_findings(all_findings)
        clean_flags = [f for f in result if f["host"].startswith("192.168.50")]
        assert clean_flags == [], (
            f"Clean hosts should produce no flags in a mixed dataset, "
            f"got: {clean_flags}"
        )
