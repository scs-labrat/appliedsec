"""Contract tests — Story 16-7.

Verifies that 3+ realistic Splunk ES notable event payloads map to valid
CanonicalAlert objects and that the entities_raw field is parseable by the
entity parser.
"""

from __future__ import annotations

import json

from entity_parser.parser import parse_alert_entities
from splunk_adapter.adapter import SplunkAdapter
from shared.schemas.alert import CanonicalAlert


# ---- sample payloads -------------------------------------------------------

PAYLOAD_BRUTE_FORCE = {
    "event_id": "splunk-notable-bf-001",
    "_time": "2026-02-14T14:32:45.000Z",
    "search_name": "Access - Brute Force Access Behavior Detected",
    "rule_title": "Brute Force Access Behavior Detected",
    "description": "50 failed login attempts from 10.0.0.99 targeting admin account in 5 minutes",
    "urgency": "critical",
    "annotations": {
        "mitre_attack": {
            "mitre_tactic": ["Credential Access"],
            "mitre_technique_id": ["T1110.001"],
        },
    },
    "src": "10.0.0.99",
    "dest": "192.168.1.10",
    "user": "admin",
    "src_ip": "10.0.0.99",
    "dest_ip": "192.168.1.10",
    "source": "Splunk_SA_CIM - Brute Force Access Behavior Detected",
    "tenant_id": "corp-tenant",
}

PAYLOAD_SUSPICIOUS_POWERSHELL = {
    "event_id": "splunk-notable-ps-001",
    "_time": "2026-02-14T08:15:00.000Z",
    "search_name": "Endpoint - Suspicious Powershell Execution",
    "rule_title": "Suspicious Powershell Execution",
    "description": "Encoded PowerShell command execution on WORKSTATION-42 by jsmith",
    "urgency": "high",
    "annotations": {
        "mitre_attack": {
            "mitre_tactic": ["Execution", "Defense Evasion"],
            "mitre_technique_id": ["T1059.001", "T1027"],
        },
    },
    "src": "10.0.1.50",
    "dest": "10.0.1.50",
    "user": "jsmith",
    "dest_host": "WORKSTATION-42",
    "process_name": "powershell.exe",
    "process_id": "3428",
    "process_exec": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AA...",
    "source": "Splunk_SA_CIM - Suspicious Powershell",
    "tenant_id": "contoso-tenant",
}

PAYLOAD_EXCESSIVE_DNS = {
    "event_id": "splunk-notable-dns-001",
    "_time": "2026-02-14T22:05:30.000Z",
    "search_name": "Network - Excessive DNS Queries to Rare Domain",
    "rule_title": "Excessive DNS Queries",
    "description": "Host srv-web-03 made 500+ DNS queries to suspicious.xyz in 10 minutes",
    "urgency": "medium",
    "annotations": {
        "mitre_attack": {
            "mitre_tactic": ["Command and Control"],
            "mitre_technique_id": ["T1071.004"],
        },
    },
    "src": "192.168.10.20",
    "dest": "8.8.8.8",
    "src_host": "srv-web-03",
    "source": "Custom - Excessive DNS Correlation",
    "tenant_id": "megacorp-tenant",
}

PAYLOADS = [PAYLOAD_BRUTE_FORCE, PAYLOAD_SUSPICIOUS_POWERSHELL, PAYLOAD_EXCESSIVE_DNS]


# ---- contract tests --------------------------------------------------------

class TestContractBasicFields:
    """Every payload must produce a valid CanonicalAlert with all required fields."""

    def test_all_payloads_produce_canonical(self):
        adapter = SplunkAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None, f"Payload {payload['event_id']} returned None"
            assert isinstance(alert, CanonicalAlert)

    def test_alert_id_populated(self):
        adapter = SplunkAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.alert_id == payload["event_id"]

    def test_source_is_splunk(self):
        adapter = SplunkAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.source == "splunk"

    def test_timestamp_is_valid_iso(self):
        adapter = SplunkAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert "T" in alert.timestamp

    def test_severity_is_lowercase(self):
        adapter = SplunkAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.severity == alert.severity.lower()

    def test_tactics_is_list(self):
        adapter = SplunkAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert isinstance(alert.tactics, list)
            assert len(alert.tactics) > 0

    def test_techniques_is_list(self):
        adapter = SplunkAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert isinstance(alert.techniques, list)
            assert len(alert.techniques) > 0

    def test_raw_payload_preserved(self):
        adapter = SplunkAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.raw_payload == payload


class TestContractEntitiesRoundTrip:
    """Entities_raw must be valid JSON that the entity parser can process."""

    def test_entities_raw_is_valid_json(self):
        adapter = SplunkAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            entities = json.loads(alert.entities_raw)
            assert isinstance(entities, list)

    def test_entity_parser_round_trip(self):
        """End-to-end: Splunk → CanonicalAlert → EntityParser → AlertEntities."""
        adapter = SplunkAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            result = parse_alert_entities(alert.entities_raw)
            total = (
                len(result.accounts) + len(result.hosts) + len(result.ips)
                + len(result.processes) + len(result.files) + len(result.urls)
                + len(result.dns_records) + len(result.file_hashes)
                + len(result.mailboxes) + len(result.other)
            )
            assert total > 0, f"No entities parsed from {payload['event_id']}"


class TestContractBruteForce:
    """Specific assertions for the Brute Force CIM-compliant payload."""

    def test_severity_is_critical(self):
        adapter = SplunkAdapter()
        alert = adapter.to_canonical(PAYLOAD_BRUTE_FORCE)
        assert alert is not None
        assert alert.severity == "critical"

    def test_technique_is_brute_force(self):
        adapter = SplunkAdapter()
        alert = adapter.to_canonical(PAYLOAD_BRUTE_FORCE)
        assert alert is not None
        assert "T1110.001" in alert.techniques

    def test_src_and_dest_ips_extracted(self):
        adapter = SplunkAdapter()
        alert = adapter.to_canonical(PAYLOAD_BRUTE_FORCE)
        assert alert is not None
        result = parse_alert_entities(alert.entities_raw)
        ip_values = {e.primary_value for e in result.ips}
        assert "10.0.0.99" in ip_values
        assert "192.168.1.10" in ip_values

    def test_user_extracted(self):
        adapter = SplunkAdapter()
        alert = adapter.to_canonical(PAYLOAD_BRUTE_FORCE)
        assert alert is not None
        result = parse_alert_entities(alert.entities_raw)
        assert len(result.accounts) >= 1
        names = {e.primary_value for e in result.accounts}
        assert "admin" in names


class TestContractSuspiciousPowershell:
    """Specific assertions for the Endpoint Powershell payload."""

    def test_multi_tactics(self):
        adapter = SplunkAdapter()
        alert = adapter.to_canonical(PAYLOAD_SUSPICIOUS_POWERSHELL)
        assert alert is not None
        assert "Execution" in alert.tactics
        assert "Defense Evasion" in alert.tactics

    def test_multi_techniques(self):
        adapter = SplunkAdapter()
        alert = adapter.to_canonical(PAYLOAD_SUSPICIOUS_POWERSHELL)
        assert alert is not None
        assert "T1059.001" in alert.techniques
        assert "T1027" in alert.techniques

    def test_host_extracted(self):
        adapter = SplunkAdapter()
        alert = adapter.to_canonical(PAYLOAD_SUSPICIOUS_POWERSHELL)
        assert alert is not None
        result = parse_alert_entities(alert.entities_raw)
        assert len(result.hosts) >= 1
        host_names = {e.primary_value for e in result.hosts}
        assert "WORKSTATION-42" in host_names


class TestContractExcessiveDNS:
    """Specific assertions for the Network DNS correlation payload."""

    def test_severity_is_medium(self):
        adapter = SplunkAdapter()
        alert = adapter.to_canonical(PAYLOAD_EXCESSIVE_DNS)
        assert alert is not None
        assert alert.severity == "medium"

    def test_c2_tactic(self):
        adapter = SplunkAdapter()
        alert = adapter.to_canonical(PAYLOAD_EXCESSIVE_DNS)
        assert alert is not None
        assert "Command and Control" in alert.tactics

    def test_src_host_in_entities(self):
        adapter = SplunkAdapter()
        alert = adapter.to_canonical(PAYLOAD_EXCESSIVE_DNS)
        assert alert is not None
        result = parse_alert_entities(alert.entities_raw)
        assert len(result.hosts) >= 1
        host_names = {e.primary_value for e in result.hosts}
        assert "srv-web-03" in host_names
