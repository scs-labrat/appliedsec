"""Contract tests — Story 4.4.

Verifies that 3+ realistic Sentinel SecurityAlert payloads map to valid
CanonicalAlert objects and that the entities_raw field is parseable by the
entity parser.
"""

from __future__ import annotations

import json

from entity_parser.parser import parse_alert_entities
from sentinel_adapter.adapter import SentinelAdapter
from shared.schemas.alert import CanonicalAlert


# ---- sample payloads -------------------------------------------------------

PAYLOAD_MDE_POWERSHELL = {
    "SystemAlertId": "d8f5e8c2-4b9a-4d7c-8e9f-3c2b1a0f9e8d",
    "TimeGenerated": "2026-02-14T14:32:45.123Z",
    "AlertName": "Suspicious PowerShell Activity Detected",
    "Description": "Encoded PowerShell command execution detected on WORKSTATION-42",
    "Severity": "High",
    "Tactics": "Execution, Command and Control",
    "Techniques": "T1059.001, T1071.001",
    "Entities": json.dumps([
        {
            "$id": "1", "Type": "account",
            "Name": "jsmith", "UPNSuffix": "contoso.com",
            "AadUserId": "a1b2c3d4", "IsDomainJoined": True,
        },
        {
            "$id": "2", "Type": "host",
            "HostName": "WORKSTATION-42", "DnsDomain": "contoso.com",
            "OSFamily": "Windows",
        },
        {
            "$id": "3", "Type": "process",
            "ProcessId": "3428",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AA...",
        },
    ]),
    "ProductName": "Microsoft Defender for Endpoint",
    "TenantId": "contoso-tenant-id",
    "AlertLink": "https://security.microsoft.com/alerts/...",
}

PAYLOAD_AADIP_IMPOSSIBLE_TRAVEL = {
    "SystemAlertId": "aadip-travel-001",
    "TimeGenerated": "2026-02-14T08:15:00Z",
    "AlertName": "Impossible travel activity",
    "Description": "Sign-in from US and then from CN within 30 minutes",
    "Severity": "Medium",
    "Tactics": "InitialAccess",
    "Techniques": "T1078",
    "Entities": json.dumps([
        {
            "$id": "1", "Type": "account",
            "Name": "cfo", "UPNSuffix": "megacorp.com",
        },
        {
            "$id": "2", "Type": "ip", "Address": "198.51.100.22",
            "Location": {"CountryCode": "US"},
        },
        {
            "$id": "3", "Type": "ip", "Address": "203.0.113.45",
            "Location": {"CountryCode": "CN"},
        },
    ]),
    "ProductName": "Azure AD Identity Protection",
    "TenantId": "megacorp-tenant",
}

PAYLOAD_ANALYTICS_RULE = {
    "SystemAlertId": "rule-brute-001",
    "TimeGenerated": "2026-02-14T22:05:30Z",
    "AlertName": "Brute-force attack detected",
    "Description": "50 failed sign-in attempts from 10.0.0.99 in 5 minutes",
    "Severity": "Critical",
    "Tactics": "Credential Access",
    "Techniques": "T1110.001",
    "Entities": json.dumps([
        {
            "$id": "1", "Type": "ip", "Address": "10.0.0.99",
        },
        {
            "$id": "2", "Type": "account",
            "Name": "admin", "UPNSuffix": "corp.local",
        },
    ]),
    "ProductName": "Azure Sentinel Analytics Rules",
    "TenantId": "corp-tenant",
}

PAYLOADS = [PAYLOAD_MDE_POWERSHELL, PAYLOAD_AADIP_IMPOSSIBLE_TRAVEL, PAYLOAD_ANALYTICS_RULE]


# ---- contract tests --------------------------------------------------------

class TestContractBasicFields:
    """Every payload must produce a valid CanonicalAlert with all required fields."""

    def test_all_payloads_produce_canonical(self):
        adapter = SentinelAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None, f"Payload {payload['SystemAlertId']} returned None"
            assert isinstance(alert, CanonicalAlert)

    def test_alert_id_populated(self):
        adapter = SentinelAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.alert_id == payload["SystemAlertId"]

    def test_source_is_sentinel(self):
        adapter = SentinelAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.source == "sentinel"

    def test_timestamp_is_valid_iso(self):
        adapter = SentinelAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert "T" in alert.timestamp
            assert alert.timestamp == payload["TimeGenerated"]

    def test_severity_is_lowercase(self):
        adapter = SentinelAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.severity == alert.severity.lower()

    def test_tactics_is_list(self):
        adapter = SentinelAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert isinstance(alert.tactics, list)
            assert len(alert.tactics) > 0

    def test_techniques_is_list(self):
        adapter = SentinelAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert isinstance(alert.techniques, list)
            assert len(alert.techniques) > 0

    def test_raw_payload_preserved(self):
        adapter = SentinelAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.raw_payload == payload


class TestContractEntitiesRoundTrip:
    """Entities_raw must be valid JSON that the entity parser can process."""

    def test_entities_raw_is_valid_json(self):
        adapter = SentinelAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            entities = json.loads(alert.entities_raw)
            assert isinstance(entities, list)

    def test_entity_parser_round_trip(self):
        """End-to-end: Sentinel → CanonicalAlert → EntityParser → AlertEntities."""
        adapter = SentinelAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            result = parse_alert_entities(alert.entities_raw)
            # Each payload has at least one entity
            total = (
                len(result.accounts) + len(result.hosts) + len(result.ips)
                + len(result.processes) + len(result.files) + len(result.urls)
                + len(result.dns_records) + len(result.file_hashes)
                + len(result.mailboxes) + len(result.other)
            )
            assert total > 0, f"No entities parsed from {payload['SystemAlertId']}"


class TestContractMdePowershell:
    """Specific assertions for the MDE PowerShell payload."""

    def test_multi_tactics(self):
        adapter = SentinelAdapter()
        alert = adapter.to_canonical(PAYLOAD_MDE_POWERSHELL)
        assert alert is not None
        assert "Execution" in alert.tactics
        assert "Command and Control" in alert.tactics

    def test_multi_techniques(self):
        adapter = SentinelAdapter()
        alert = adapter.to_canonical(PAYLOAD_MDE_POWERSHELL)
        assert alert is not None
        assert "T1059.001" in alert.techniques
        assert "T1071.001" in alert.techniques

    def test_entities_have_account_host_process(self):
        adapter = SentinelAdapter()
        alert = adapter.to_canonical(PAYLOAD_MDE_POWERSHELL)
        assert alert is not None
        result = parse_alert_entities(alert.entities_raw)
        assert len(result.accounts) >= 1
        assert len(result.hosts) >= 1
        assert len(result.processes) >= 1


class TestContractImpossibleTravel:
    """Specific assertions for the AAD IP impossible-travel payload."""

    def test_two_ips_extracted(self):
        adapter = SentinelAdapter()
        alert = adapter.to_canonical(PAYLOAD_AADIP_IMPOSSIBLE_TRAVEL)
        assert alert is not None
        result = parse_alert_entities(alert.entities_raw)
        assert len(result.ips) == 2
        ip_values = {e.primary_value for e in result.ips}
        assert "198.51.100.22" in ip_values
        assert "203.0.113.45" in ip_values

    def test_severity_is_medium(self):
        adapter = SentinelAdapter()
        alert = adapter.to_canonical(PAYLOAD_AADIP_IMPOSSIBLE_TRAVEL)
        assert alert is not None
        assert alert.severity == "medium"


class TestContractBruteForce:
    """Specific assertions for the Analytics Rule brute-force payload."""

    def test_severity_is_critical(self):
        adapter = SentinelAdapter()
        alert = adapter.to_canonical(PAYLOAD_ANALYTICS_RULE)
        assert alert is not None
        assert alert.severity == "critical"

    def test_technique_is_brute_force(self):
        adapter = SentinelAdapter()
        alert = adapter.to_canonical(PAYLOAD_ANALYTICS_RULE)
        assert alert is not None
        assert "T1110.001" in alert.techniques
