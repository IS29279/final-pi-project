"""
test_flag_findings_search_terms.py
Sprint 2 addition: every flag produced by flag_findings() should carry a
'search_terms' field — a list of 1-3 short strings a reviewer can copy
into Google or the MITRE ATT&CK site to learn about the finding.
"""

import pytest
from FinalApp import flag_findings


# ═════════════════════════════════════════════════════════════════════════════
# SAMPLE DATASETS — one finding of each major category
# ═════════════════════════════════════════════════════════════════════════════

PORT_FINDING_TELNET = [{
    "host": "10.0.0.1", "port_number": 23, "protocol": "tcp", "state": "open",
    "service_name": "telnet", "service_version": "",
}]

PORT_FINDING_RDP = [{
    "host": "10.0.0.2", "port_number": 3389, "protocol": "tcp", "state": "open",
    "service_name": "ms-wbt-server", "service_version": "",
}]

PORT_FINDING_VSFTPD = [{
    "host": "10.0.0.3", "port_number": 21, "protocol": "tcp", "state": "open",
    "service_name": "ftp", "service_version": "vsftpd 2.3.4",
}]

PORT_FINDING_HTTPS = [{
    "host": "10.0.0.4", "port_number": 443, "protocol": "tcp", "state": "open",
    "service_name": "https", "service_version": "nginx 1.24.0",
}]

PORT_FINDING_MODERN_SSH = [{
    "host": "10.0.0.5", "port_number": 2222, "protocol": "tcp", "state": "open",
    "service_name": "ssh", "service_version": "OpenSSH 9.2",
}]

TRAFFIC_CLEARTEXT = [{
    "id": "t1", "session_id": "s1",
    "pcap_path": "reports/capture_s1.pcap",
    "protocol_summary": "tcp:100, telnet:12",
    "cleartext_creds_found": 1,
    "capture_start": 1729000000, "capture_end": 1729000030,
}]

TRAFFIC_HTTP = [{
    "id": "t2", "session_id": "s2",
    "pcap_path": "reports/capture_s2.pcap",
    "protocol_summary": "tcp:100, http:40, dns:12",
    "cleartext_creds_found": 0,
    "capture_start": 1729000100, "capture_end": 1729000130,
}]

TRAFFIC_ENCRYPTED = [{
    "id": "t3", "session_id": "s3",
    "pcap_path": "reports/capture_s3.pcap",
    "protocol_summary": "tcp:100, tls:80, ssh:20",
    "cleartext_creds_found": 0,
    "capture_start": 1729000200, "capture_end": 1729000230,
}]


# ═════════════════════════════════════════════════════════════════════════════
# GENERAL CONTRACT TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestSearchTermsContract:
    """
    Every flag produced by flag_findings() must include a search_terms field
    with at least one non-empty string.
    """

    def _all_flag_scenarios(self):
        """Produce flags covering every major category in one flat list."""
        port_findings = (
            PORT_FINDING_TELNET + PORT_FINDING_RDP + PORT_FINDING_VSFTPD +
            PORT_FINDING_HTTPS + PORT_FINDING_MODERN_SSH
        )
        traffic = TRAFFIC_CLEARTEXT + TRAFFIC_HTTP + TRAFFIC_ENCRYPTED
        return flag_findings(port_findings, traffic)

    def test_every_flag_has_search_terms_field(self):
        """No flag should be missing the search_terms key."""
        for flag in self._all_flag_scenarios():
            assert "search_terms" in flag, f"Flag missing search_terms: {flag}"

    def test_search_terms_is_always_a_list(self):
        """search_terms must be a list — never a string, never None."""
        for flag in self._all_flag_scenarios():
            assert isinstance(flag["search_terms"], list), (
                f"search_terms should be a list, got {type(flag['search_terms']).__name__}: {flag}"
            )

    def test_search_terms_is_never_empty(self):
        """Every flag should have at least one search term — empty lists defeat the purpose."""
        for flag in self._all_flag_scenarios():
            assert len(flag["search_terms"]) >= 1, (
                f"Flag has empty search_terms list: {flag}"
            )

    def test_search_terms_are_non_empty_strings(self):
        """Each term must be a non-empty string (no None, no ints, no blanks)."""
        for flag in self._all_flag_scenarios():
            for term in flag["search_terms"]:
                assert isinstance(term, str), (
                    f"search term should be a string, got {type(term).__name__}: {term}"
                )
                assert term.strip() != "", (
                    f"search term is blank in flag: {flag}"
                )

    def test_search_terms_count_is_reasonable(self):
        """
        Keep search_terms lists short — 1 to 5 terms is plenty.
        More than that starts to feel like noise.
        """
        for flag in self._all_flag_scenarios():
            assert 1 <= len(flag["search_terms"]) <= 5, (
                f"Flag has {len(flag['search_terms'])} search terms — "
                f"should be 1-5 for readability: {flag}"
            )


# ═════════════════════════════════════════════════════════════════════════════
# SPECIFIC CATEGORY TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestSearchTermsPortFlags:
    """Port-based flags should carry terms relevant to the specific service."""

    def test_telnet_terms_mention_credentials_or_sniffing(self):
        flag = flag_findings(PORT_FINDING_TELNET)[0]
        combined = " ".join(flag["search_terms"]).lower()
        assert any(kw in combined for kw in ["credential", "sniffing", "cleartext", "telnet"]), (
            f"Telnet flag terms should reference credentials/sniffing: {flag['search_terms']}"
        )

    def test_rdp_terms_include_cve_or_mitre_reference(self):
        """RDP has well-known CVEs (BlueKeep) and a MITRE technique — at least one should appear."""
        flag = flag_findings(PORT_FINDING_RDP)[0]
        combined = " ".join(flag["search_terms"])
        has_cve   = "CVE-" in combined
        has_mitre = "T1021" in combined or "T1110" in combined
        assert has_cve or has_mitre, (
            f"RDP flag should include a CVE or MITRE reference, got: {flag['search_terms']}"
        )


class TestSearchTermsVersionFlags:
    """Version-based flags should reference the specific CVE or product."""

    def test_vsftpd_backdoor_terms_mention_cve(self):
        """The vsftpd 2.3.4 backdoor is CVE-2011-2523 — that CVE should be searchable."""
        flags = flag_findings(PORT_FINDING_VSFTPD)
        vsftpd_flag = next(f for f in flags if "vsftpd" in f["reason"].lower())
        combined = " ".join(vsftpd_flag["search_terms"])
        assert "CVE-2011-2523" in combined, (
            f"vsftpd flag should reference CVE-2011-2523, got: {vsftpd_flag['search_terms']}"
        )


class TestSearchTermsInfoFlags:
    """Info-tier flags should have terms too — they point at hardening guides."""

    def test_https_info_flag_has_search_terms(self):
        flags = flag_findings(PORT_FINDING_HTTPS)
        https_flag = next(f for f in flags if f["port"] == 443)
        assert https_flag["severity"] == "info"
        assert len(https_flag["search_terms"]) >= 1, (
            "HTTPS info flag should still have at least one search term for hardening guidance"
        )

    def test_modern_ssh_info_flag_has_search_terms(self):
        flags = flag_findings(PORT_FINDING_MODERN_SSH)
        # Find the info flag specifically (there may or may not be others)
        ssh_info = next(f for f in flags if f["severity"] == "info" and f["port"] == 2222)
        assert len(ssh_info["search_terms"]) >= 1


class TestSearchTermsTrafficFlags:
    """Traffic flags should point at packet-analysis resources."""

    def test_cleartext_creds_flag_has_search_terms(self):
        flag = flag_findings([], TRAFFIC_CLEARTEXT)[0]
        assert len(flag["search_terms"]) >= 1
        combined = " ".join(flag["search_terms"]).lower()
        assert any(kw in combined for kw in ["sniff", "wireshark", "credential", "t1040"]), (
            f"Cleartext creds traffic flag should reference packet analysis: {flag['search_terms']}"
        )

    def test_http_traffic_flag_has_search_terms(self):
        flag = flag_findings([], TRAFFIC_HTTP)[0]
        assert len(flag["search_terms"]) >= 1

    def test_encrypted_only_flag_has_search_terms(self):
        flag = flag_findings([], TRAFFIC_ENCRYPTED)[0]
        assert len(flag["search_terms"]) >= 1
