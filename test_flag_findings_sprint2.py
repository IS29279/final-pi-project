"""
test_flag_findings_sprint2.py
Sprint 2 additions to Channing's flag_findings() test suite.

Covers two categories the original suite did not:
  - Traffic-based flags derived from tshark capture rows
  - Info-tier flags for positive findings (HTTPS, modern SSH on non-default port)

The shape of traffic rows matches what get_traffic_findings() returns from
the traffic_findings table in utils/db.py:
    {
        "id":                    "uuid",
        "session_id":            "uuid",
        "pcap_path":             "reports/capture_<id>.pcap",
        "protocol_summary":      "tcp:142, http:38, dns:12, telnet:4",
        "cleartext_creds_found": 1,
        "capture_start":         <unix ts>,
        "capture_end":           <unix ts>,
    }
"""

import pytest
from FinalApp import flag_findings


# ═════════════════════════════════════════════════════════════════════════════
# TRAFFIC DATASETS
# ═════════════════════════════════════════════════════════════════════════════

# ── Capture with live cleartext credentials on the wire ──────────────────────
# tshark saw telnet traffic during the capture window and set the
# cleartext_creds_found flag. This is the strongest traffic signal —
# evidence of credentials actually moving through the network.
TRAFFIC_CLEARTEXT_CREDS = [{
    "id":                    "t-001",
    "session_id":             "s-001",
    "pcap_path":              "reports/capture_s-001.pcap",
    "protocol_summary":       "tcp:420, telnet:12, dns:8",
    "cleartext_creds_found":  1,
    "capture_start":          1729000000,
    "capture_end":            1729000030,
}]

# ── Capture with HTTP traffic but no confirmed cleartext creds ───────────────
# HTTP and FTP showed up in the summary, but tshark's credential check
# didn't trigger. Should be medium — "we saw plaintext protocols in use"
# but we can't say for sure credentials crossed the wire.
TRAFFIC_HTTP_NO_CREDS = [{
    "id":                    "t-002",
    "session_id":             "s-002",
    "pcap_path":              "reports/capture_s-002.pcap",
    "protocol_summary":       "tcp:800, http:142, tls:95, dns:40",
    "cleartext_creds_found":  0,
    "capture_start":          1729000100,
    "capture_end":            1729000130,
}]

# ── Clean capture — only encrypted protocols observed ────────────────────────
# All traffic during the capture was TLS/HTTPS/SSH. Should emit an info
# flag so the report can show a positive finding.
TRAFFIC_ENCRYPTED_ONLY = [{
    "id":                    "t-003",
    "session_id":             "s-003",
    "pcap_path":              "reports/capture_s-003.pcap",
    "protocol_summary":       "tcp:1200, tls:850, ssh:30, dns:20",
    "cleartext_creds_found":  0,
    "capture_start":          1729000200,
    "capture_end":            1729000230,
}]

# ── Empty capture — nothing useful observed ──────────────────────────────────
# The capture ran but the subnet was quiet. protocol_summary is empty.
# Should emit no traffic flags at all — we can't say anything positive
# or negative about traffic we never saw.
TRAFFIC_EMPTY = [{
    "id":                    "t-004",
    "session_id":             "s-004",
    "pcap_path":              "reports/capture_s-004.pcap",
    "protocol_summary":       "",
    "cleartext_creds_found":  0,
    "capture_start":          1729000300,
    "capture_end":            1729000330,
}]

# ── Capture where creds flag is truthy but summary happens to be empty ───────
# Edge case: cleartext_creds_found is set but somehow protocol_summary
# didn't populate. The creds flag is the authoritative signal — it should
# still produce a critical flag.
TRAFFIC_CREDS_NO_SUMMARY = [{
    "id":                    "t-005",
    "session_id":             "s-005",
    "pcap_path":              "reports/capture_s-005.pcap",
    "protocol_summary":       "",
    "cleartext_creds_found":  1,
    "capture_start":          1729000400,
    "capture_end":            1729000430,
}]


# ═════════════════════════════════════════════════════════════════════════════
# PORT DATASETS FOR INFO-TIER TESTS
# ═════════════════════════════════════════════════════════════════════════════

# ── Well-configured host ────────────────────────────────────────────────────
# HTTPS exposed with modern nginx, and SSH on a non-standard port running
# a current OpenSSH version. Both should produce info flags.
INFO_DATASET_HTTPS_AND_MODERN_SSH = [
    {"host": "192.168.100.1", "port_number": 443, "protocol": "tcp", "state": "open",
     "service_name": "https", "service_version": "nginx 1.24.0"},
    {"host": "192.168.100.2", "port_number": 2222, "protocol": "tcp", "state": "open",
     "service_name": "ssh", "service_version": "OpenSSH 9.2"},
]

# ── SSH on port 22 with modern version ──────────────────────────────────────
# Even if the version is modern, port 22 exposure is still a high-severity
# concern. The info flag for "modern SSH on non-standard port" should NOT
# fire here — only the port-22 high flag should.
INFO_DATASET_MODERN_SSH_ON_22 = [
    {"host": "10.1.1.1", "port_number": 22, "protocol": "tcp", "state": "open",
     "service_name": "ssh", "service_version": "OpenSSH 9.6"},
]

# ── Combined dataset — alarms AND positive findings on same scan ────────────
# Realistic scan output: one host is a mess (Telnet), one host is well-configured
# (HTTPS). The flag list should contain both the critical alarm AND the info flag,
# with hosts correctly preserved on each.
INFO_DATASET_MIXED = [
    {"host": "10.1.1.5", "port_number": 23, "protocol": "tcp", "state": "open",
     "service_name": "telnet", "service_version": ""},
    {"host": "10.1.1.10", "port_number": 443, "protocol": "tcp", "state": "open",
     "service_name": "https", "service_version": "nginx 1.24.0"},
]


# ═════════════════════════════════════════════════════════════════════════════
# TRAFFIC FLAG TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestTrafficCleartextCreds:
    """
    When tshark detected cleartext credentials, the scanner should emit a
    critical traffic flag — this is the strongest signal the capture produced.
    """

    def test_cleartext_creds_produces_critical_flag(self):
        result = flag_findings([], TRAFFIC_CLEARTEXT_CREDS)
        critical = [f for f in result if f["severity"] == "critical"]
        assert len(critical) >= 1, (
            "Expected a critical flag when cleartext_creds_found is truthy, "
            f"got: {result}"
        )

    def test_cleartext_creds_flag_is_network_scoped(self):
        """Traffic flags are not host-specific — they apply to the capture as a whole."""
        result = flag_findings([], TRAFFIC_CLEARTEXT_CREDS)
        critical = [f for f in result if f["severity"] == "critical"]
        assert critical[0]["host"] == "network", (
            f"Traffic flag should have host='network', got: {critical[0]['host']}"
        )

    def test_cleartext_creds_flag_has_no_port(self):
        """Traffic flags aren't tied to a single port — port should be None."""
        result = flag_findings([], TRAFFIC_CLEARTEXT_CREDS)
        critical = [f for f in result if f["severity"] == "critical"]
        assert critical[0]["port"] is None

    def test_creds_flag_fires_even_with_empty_summary(self):
        """
        The creds boolean is authoritative — even if protocol_summary is empty,
        the critical flag should still fire.
        """
        result = flag_findings([], TRAFFIC_CREDS_NO_SUMMARY)
        critical = [f for f in result if f["severity"] == "critical"]
        assert len(critical) >= 1

    def test_creds_flag_does_not_double_flag_on_medium(self):
        """
        When cleartext_creds_found is truthy, the critical flag should fire
        and suppress the medium 'unencrypted traffic' flag — they describe
        the same underlying evidence and would be noisy if both appeared.
        """
        result = flag_findings([], TRAFFIC_CLEARTEXT_CREDS)
        mediums = [f for f in result if f["severity"] == "medium"]
        assert mediums == [], (
            f"Expected no medium flags when critical creds flag fired, got: {mediums}"
        )


class TestTrafficUnencryptedInSummary:
    """
    When cleartext protocols (HTTP/FTP/Telnet) appear in the capture summary
    but the creds flag didn't fire, emit a medium flag — we saw plaintext
    protocols in active use but can't confirm credential exposure.
    """

    def test_http_in_summary_produces_medium_flag(self):
        result = flag_findings([], TRAFFIC_HTTP_NO_CREDS)
        mediums = [f for f in result if f["severity"] == "medium"]
        assert len(mediums) >= 1, (
            f"Expected a medium flag for HTTP in summary, got: {result}"
        )

    def test_http_flag_does_not_escalate_to_critical(self):
        """
        Without cleartext_creds_found, HTTP in the summary alone isn't
        critical — the scanner hasn't confirmed credentials on the wire.
        """
        result = flag_findings([], TRAFFIC_HTTP_NO_CREDS)
        critical = [f for f in result if f["severity"] == "critical"]
        assert critical == [], (
            f"Expected no critical flag without creds evidence, got: {critical}"
        )


class TestTrafficEncryptedOnly:
    """
    A capture containing only encrypted protocols (TLS/SSH/HTTPS) should
    produce an info flag — a positive baseline finding for the report.
    """

    def test_encrypted_only_capture_produces_info_flag(self):
        result = flag_findings([], TRAFFIC_ENCRYPTED_ONLY)
        info = [f for f in result if f["severity"] == "info" and f["host"] == "network"]
        assert len(info) >= 1, (
            f"Expected an info flag for encrypted-only capture, got: {result}"
        )

    def test_encrypted_only_does_not_produce_alarm(self):
        """A clean capture must not produce any critical/high/medium flags."""
        result = flag_findings([], TRAFFIC_ENCRYPTED_ONLY)
        alarms = [f for f in result if f["severity"] in {"critical", "high", "medium"}]
        assert alarms == [], (
            f"Encrypted-only capture should not raise alarms, got: {alarms}"
        )


class TestTrafficEmptyCapture:
    """
    A capture with no traffic observed at all isn't evidence of anything —
    we shouldn't emit a positive OR negative flag for it.
    """

    def test_empty_summary_produces_no_flags(self):
        result = flag_findings([], TRAFFIC_EMPTY)
        assert result == [], (
            f"Empty capture should produce no flags, got: {result}"
        )


# ═════════════════════════════════════════════════════════════════════════════
# INFO-TIER PORT FLAG TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestInfoTierPortFlags:
    """
    Positive findings for well-configured services — HTTPS, modern SSH on
    non-default ports — so a clean scan still has something to report.
    """

    def test_https_produces_info_flag(self):
        result = flag_findings(INFO_DATASET_HTTPS_AND_MODERN_SSH)
        https = [f for f in result if f["port"] == 443]
        assert len(https) >= 1
        assert https[0]["severity"] == "info"

    def test_modern_ssh_on_non_default_port_produces_info_flag(self):
        result = flag_findings(INFO_DATASET_HTTPS_AND_MODERN_SSH)
        ssh_info = [
            f for f in result
            if f["port"] == 2222 and f["severity"] == "info"
        ]
        assert len(ssh_info) >= 1, (
            "OpenSSH 9.2 on port 2222 should produce an info flag — "
            "defensive configuration worth reporting positively"
        )

    def test_modern_ssh_on_port_22_does_not_produce_info_flag(self):
        """
        Even with a modern version, port 22 exposure is still a concern.
        The info flag would be misleading — the port-22 high flag is what
        the reviewer needs to see.
        """
        result = flag_findings(INFO_DATASET_MODERN_SSH_ON_22)
        info = [f for f in result if f["severity"] == "info"]
        assert info == [], (
            f"Info flag should not fire for SSH on port 22, got: {info}"
        )

    def test_port_22_high_flag_still_fires_with_modern_version(self):
        """Confirms the existing high-severity port-22 flag behavior is preserved."""
        result = flag_findings(INFO_DATASET_MODERN_SSH_ON_22)
        high = [f for f in result if f["port"] == 22 and f["severity"] == "high"]
        assert len(high) >= 1

    def test_info_flag_preserves_host(self):
        """Info flags on specific hosts should keep the host field populated."""
        result = flag_findings(INFO_DATASET_HTTPS_AND_MODERN_SSH)
        https = [f for f in result if f["port"] == 443]
        assert https[0]["host"] == "192.168.100.1"


class TestMixedAlarmsAndInfo:
    """
    Realistic scan: some hosts are compromised-looking, others are well-configured.
    Both sets of findings should appear in the result, on their correct hosts.
    """

    def test_mixed_dataset_produces_both_alarms_and_info(self):
        result = flag_findings(INFO_DATASET_MIXED)
        alarms = [f for f in result if f["severity"] in {"critical", "high", "medium"}]
        info   = [f for f in result if f["severity"] == "info"]
        assert len(alarms) >= 1, f"Expected alarm-level flags, got: {result}"
        assert len(info)   >= 1, f"Expected info-level flags, got: {result}"

    def test_mixed_dataset_preserves_host_assignment(self):
        result = flag_findings(INFO_DATASET_MIXED)
        telnet_flag = next(f for f in result if f["port"] == 23)
        https_flag  = next(f for f in result if f["port"] == 443)
        assert telnet_flag["host"] == "10.1.1.5"
        assert https_flag["host"]  == "10.1.1.10"


# ═════════════════════════════════════════════════════════════════════════════
# SIGNATURE / BACKWARD-COMPATIBILITY TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestSignatureCompatibility:
    """
    flag_findings() gained an optional traffic_findings argument in Sprint 2.
    Existing single-argument callers should continue to work unchanged.
    """

    def test_single_argument_call_still_works(self):
        """Calling with only port findings should behave exactly as before."""
        findings = [{"host": "1.1.1.1", "port_number": 23, "protocol": "tcp",
                     "state": "open", "service_name": "telnet", "service_version": ""}]
        result = flag_findings(findings)
        assert any(f["port"] == 23 for f in result)

    def test_traffic_none_is_same_as_omitted(self):
        """Explicitly passing traffic_findings=None must behave like omitting it."""
        findings = [{"host": "1.1.1.1", "port_number": 23, "protocol": "tcp",
                     "state": "open", "service_name": "telnet", "service_version": ""}]
        a = flag_findings(findings)
        b = flag_findings(findings, None)
        assert a == b

    def test_empty_traffic_list_does_not_add_flags(self):
        """An empty traffic list should not change the result from port findings alone."""
        findings = [{"host": "1.1.1.1", "port_number": 23, "protocol": "tcp",
                     "state": "open", "service_name": "telnet", "service_version": ""}]
        a = flag_findings(findings)
        b = flag_findings(findings, [])
        assert a == b

    def test_port_and_traffic_findings_combine(self):
        """Port flags and traffic flags should both appear in the output."""
        port_findings = [{"host": "1.1.1.1", "port_number": 23, "protocol": "tcp",
                          "state": "open", "service_name": "telnet", "service_version": ""}]
        result = flag_findings(port_findings, TRAFFIC_CLEARTEXT_CREDS)
        # Port flag for Telnet on host
        assert any(f["port"] == 23 and f["host"] == "1.1.1.1" for f in result)
        # Traffic flag scoped to "network"
        assert any(f["host"] == "network" and f["severity"] == "critical" for f in result)
