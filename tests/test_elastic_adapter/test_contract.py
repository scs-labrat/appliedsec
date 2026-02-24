"""Contract tests — Story 16-3.

Verifies that 3+ realistic Elastic SIEM signal payloads map to valid
CanonicalAlert objects and that the entities_raw field is parseable by the
entity parser.
"""

from __future__ import annotations

import json

from entity_parser.parser import parse_alert_entities
from elastic_adapter.adapter import ElasticAdapter
from shared.schemas.alert import CanonicalAlert


# ---- sample payloads -------------------------------------------------------

PAYLOAD_PROCESS_EXECUTION = {
    "@timestamp": "2026-02-14T14:32:45.123Z",
    "signal": {
        "rule": {
            "id": "elastic-endpoint-proc-001",
            "name": "Suspicious PowerShell Execution",
            "description": "Encoded PowerShell command execution detected via Elastic Endpoint",
            "severity": "high",
        },
    },
    "kibana": {
        "alert": {
            "rule": {
                "parameters": {
                    "threat": [
                        {
                            "tactic": {"id": "TA0002", "name": "Execution"},
                            "technique": [
                                {
                                    "id": "T1059",
                                    "name": "Command and Scripting Interpreter",
                                    "subtechnique": [
                                        {"id": "T1059.001", "name": "PowerShell"},
                                    ],
                                },
                            ],
                        },
                        {
                            "tactic": {"id": "TA0011", "name": "Command and Control"},
                            "technique": [
                                {"id": "T1071", "name": "Application Layer Protocol"},
                            ],
                        },
                    ]
                }
            }
        }
    },
    "host": {
        "name": "WORKSTATION-42",
        "os": {"family": "windows", "version": "10.0"},
    },
    "user": {"name": "jsmith", "domain": "contoso.com"},
    "process": {
        "name": "powershell.exe",
        "pid": 3428,
        "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AA...",
    },
    "source": {"ip": "10.0.1.50"},
    "agent": {"type": "endpoint"},
}

PAYLOAD_NETWORK_ANOMALY = {
    "@timestamp": "2026-02-14T08:15:00.000Z",
    "signal": {
        "rule": {
            "id": "elastic-net-anomaly-001",
            "name": "Unusual External Connection Detected",
            "description": "Host connected to IP in uncommon geo within 30min of login from different geo",
            "severity": "medium",
        },
    },
    "kibana": {
        "alert": {
            "rule": {
                "parameters": {
                    "threat": [
                        {
                            "tactic": {"id": "TA0001", "name": "Initial Access"},
                            "technique": [
                                {"id": "T1078", "name": "Valid Accounts"},
                            ],
                        },
                    ]
                }
            }
        }
    },
    "host": {"name": "laptop-cfo", "os": {"family": "macos"}},
    "user": {"name": "cfo", "domain": "megacorp.com"},
    "source": {"ip": "198.51.100.22"},
    "destination": {"ip": "203.0.113.45"},
    "agent": {"type": "endpoint"},
}

PAYLOAD_INDICATOR_MATCH = {
    "@timestamp": "2026-02-14T22:05:30.000Z",
    "signal": {
        "rule": {
            "id": "elastic-indicator-match-001",
            "name": "Threat Intel Indicator Match - Known C2 IP",
            "description": "Connection to known C2 infrastructure IP 45.33.32.156",
            "severity": "critical",
        },
    },
    "kibana": {
        "alert": {
            "rule": {
                "parameters": {
                    "threat": [
                        {
                            "tactic": {"id": "TA0011", "name": "Command and Control"},
                            "technique": [
                                {
                                    "id": "T1071",
                                    "name": "Application Layer Protocol",
                                    "subtechnique": [
                                        {"id": "T1071.001", "name": "Web Protocols"},
                                    ],
                                },
                            ],
                        },
                    ]
                }
            }
        }
    },
    "host": {"name": "srv-web-03", "os": {"family": "linux"}},
    "source": {"ip": "192.168.10.20"},
    "destination": {"ip": "45.33.32.156"},
    "agent": {"type": "endpoint"},
}

PAYLOADS = [PAYLOAD_PROCESS_EXECUTION, PAYLOAD_NETWORK_ANOMALY, PAYLOAD_INDICATOR_MATCH]


# ---- contract tests --------------------------------------------------------

class TestContractBasicFields:
    """Every payload must produce a valid CanonicalAlert with all required fields."""

    def test_all_payloads_produce_canonical(self):
        adapter = ElasticAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None, f"Payload {payload['signal']['rule']['id']} returned None"
            assert isinstance(alert, CanonicalAlert)

    def test_alert_id_populated(self):
        adapter = ElasticAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.alert_id == payload["signal"]["rule"]["id"]

    def test_source_is_elastic(self):
        adapter = ElasticAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.source == "elastic"

    def test_timestamp_is_valid_iso(self):
        adapter = ElasticAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert "T" in alert.timestamp
            assert alert.timestamp == payload["@timestamp"]

    def test_severity_is_lowercase(self):
        adapter = ElasticAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.severity == alert.severity.lower()

    def test_tactics_is_list(self):
        adapter = ElasticAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert isinstance(alert.tactics, list)
            assert len(alert.tactics) > 0

    def test_techniques_is_list(self):
        adapter = ElasticAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert isinstance(alert.techniques, list)
            assert len(alert.techniques) > 0

    def test_raw_payload_preserved(self):
        adapter = ElasticAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.raw_payload == payload


class TestContractEntitiesRoundTrip:
    """Entities_raw must be valid JSON that the entity parser can process."""

    def test_entities_raw_is_valid_json(self):
        adapter = ElasticAdapter()
        for payload in PAYLOADS:
            alert = adapter.to_canonical(payload)
            assert alert is not None
            entities = json.loads(alert.entities_raw)
            assert isinstance(entities, list)

    def test_entity_parser_round_trip(self):
        """End-to-end: Elastic → CanonicalAlert → EntityParser → AlertEntities."""
        adapter = ElasticAdapter()
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
            assert total > 0, f"No entities parsed from {payload['signal']['rule']['id']}"


class TestContractProcessExecution:
    """Specific assertions for the Process Execution (Endpoint) payload."""

    def test_multi_tactics(self):
        adapter = ElasticAdapter()
        alert = adapter.to_canonical(PAYLOAD_PROCESS_EXECUTION)
        assert alert is not None
        assert "Execution" in alert.tactics
        assert "Command and Control" in alert.tactics

    def test_subtechnique_extracted(self):
        adapter = ElasticAdapter()
        alert = adapter.to_canonical(PAYLOAD_PROCESS_EXECUTION)
        assert alert is not None
        assert "T1059" in alert.techniques
        assert "T1059.001" in alert.techniques
        assert "T1071" in alert.techniques

    def test_entities_have_host_user_process_ip(self):
        adapter = ElasticAdapter()
        alert = adapter.to_canonical(PAYLOAD_PROCESS_EXECUTION)
        assert alert is not None
        result = parse_alert_entities(alert.entities_raw)
        assert len(result.hosts) >= 1
        assert len(result.accounts) >= 1
        assert len(result.processes) >= 1
        assert len(result.ips) >= 1


class TestContractNetworkAnomaly:
    """Specific assertions for the Network Anomaly payload."""

    def test_two_ips_extracted(self):
        adapter = ElasticAdapter()
        alert = adapter.to_canonical(PAYLOAD_NETWORK_ANOMALY)
        assert alert is not None
        result = parse_alert_entities(alert.entities_raw)
        assert len(result.ips) >= 2
        ip_values = {e.primary_value for e in result.ips}
        assert "198.51.100.22" in ip_values
        assert "203.0.113.45" in ip_values

    def test_severity_is_medium(self):
        adapter = ElasticAdapter()
        alert = adapter.to_canonical(PAYLOAD_NETWORK_ANOMALY)
        assert alert is not None
        assert alert.severity == "medium"


class TestContractIndicatorMatch:
    """Specific assertions for the Indicator Match payload."""

    def test_severity_is_critical(self):
        adapter = ElasticAdapter()
        alert = adapter.to_canonical(PAYLOAD_INDICATOR_MATCH)
        assert alert is not None
        assert alert.severity == "critical"

    def test_c2_technique_present(self):
        adapter = ElasticAdapter()
        alert = adapter.to_canonical(PAYLOAD_INDICATOR_MATCH)
        assert alert is not None
        assert "T1071" in alert.techniques
        assert "T1071.001" in alert.techniques

    def test_destination_ip_in_entities(self):
        adapter = ElasticAdapter()
        alert = adapter.to_canonical(PAYLOAD_INDICATOR_MATCH)
        assert alert is not None
        result = parse_alert_entities(alert.entities_raw)
        ip_values = {e.primary_value for e in result.ips}
        assert "45.33.32.156" in ip_values
