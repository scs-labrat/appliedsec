"""Unit tests for SplunkAdapter — Story 16-4.

5 tests covering field mapping edge cases.
"""

from __future__ import annotations

from splunk_adapter.adapter import SplunkAdapter


def _make_notable(**overrides):
    """Build a minimal Splunk ES notable event with overrides."""
    base = {
        "event_id": "notable-001",
        "_time": "2026-02-14T14:32:45.000Z",
        "search_name": "Access - Brute Force Detected",
        "description": "Brute force login attempt",
        "urgency": "high",
        "annotations": {
            "mitre_attack": {
                "mitre_tactic": ["Credential Access"],
                "mitre_technique_id": ["T1110.001"],
            },
        },
        "src": "10.0.0.99",
        "dest": "192.168.1.10",
        "user": "admin",
    }
    base.update(overrides)
    return base


class TestSplunkAdapterFieldMapping:
    """Edge case tests for Splunk notable → CanonicalAlert mapping."""

    def test_health_check_event_dropped(self):
        """Events with search_name starting with 'Health' are dropped."""
        adapter = SplunkAdapter()
        payload = _make_notable(search_name="Health Check - Splunk Forwarders")
        assert adapter.to_canonical(payload) is None

    def test_epoch_timestamp_parsed(self):
        """Epoch timestamps are converted to ISO 8601."""
        adapter = SplunkAdapter()
        payload = _make_notable(_time="1707918765.0")
        alert = adapter.to_canonical(payload)
        assert alert is not None
        assert "T" in alert.timestamp
        assert "2024" in alert.timestamp  # epoch 1707918765 → 2024-02-14

    def test_urgency_mapping(self):
        """Splunk urgency values map to canonical severity."""
        adapter = SplunkAdapter()
        for urgency, expected in [
            ("critical", "critical"),
            ("high", "high"),
            ("medium", "medium"),
            ("low", "low"),
            ("informational", "informational"),
            ("info", "informational"),
        ]:
            payload = _make_notable(urgency=urgency)
            alert = adapter.to_canonical(payload)
            assert alert is not None
            assert alert.severity == expected, f"{urgency} → {alert.severity}"

    def test_csv_tactics_extracted(self):
        """CSV-formatted MITRE tactics are split into a list."""
        adapter = SplunkAdapter()
        payload = _make_notable()
        payload["annotations"]["mitre_attack"]["mitre_tactic"] = "Initial Access, Execution"
        alert = adapter.to_canonical(payload)
        assert alert is not None
        assert "Initial Access" in alert.tactics
        assert "Execution" in alert.tactics

    def test_entities_include_src_dest_user(self):
        """Entities contain src IP, dest IP, and user from CIM fields."""
        adapter = SplunkAdapter()
        payload = _make_notable()
        alert = adapter.to_canonical(payload)
        assert alert is not None
        import json
        entities = json.loads(alert.entities_raw)
        types = [e["Type"] for e in entities]
        assert "ip" in types
        assert "account" in types
