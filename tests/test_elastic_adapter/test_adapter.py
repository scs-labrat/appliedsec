"""Unit tests for ElasticAdapter — Story 16-1.

5 tests covering field mapping edge cases.
"""

from __future__ import annotations

from elastic_adapter.adapter import ElasticAdapter


def _make_signal(**overrides):
    """Build a minimal Elastic signal payload with overrides."""
    base = {
        "@timestamp": "2026-02-14T14:32:45.000Z",
        "signal": {
            "rule": {
                "id": "rule-001",
                "name": "Test Detection",
                "description": "A test detection rule",
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
                                    {"id": "T1059", "name": "Command and Scripting Interpreter"}
                                ],
                            }
                        ]
                    }
                }
            }
        },
        "host": {"name": "server-01", "os": {"family": "linux"}},
        "user": {"name": "testuser", "domain": "corp.local"},
        "source": {"ip": "10.0.0.1"},
    }
    base.update(overrides)
    return base


class TestElasticAdapterFieldMapping:
    """Edge case tests for Elastic signal → CanonicalAlert mapping."""

    def test_heartbeat_signal_dropped(self):
        """Signals matching _HEARTBEAT_NAMES are dropped."""
        adapter = ElasticAdapter()
        payload = _make_signal()
        payload["signal"]["rule"]["name"] = "Heartbeat"
        assert adapter.to_canonical(payload) is None

    def test_missing_severity_defaults_to_medium(self):
        """Missing severity field defaults to 'medium'."""
        adapter = ElasticAdapter()
        payload = _make_signal()
        payload["signal"]["rule"]["severity"] = None
        alert = adapter.to_canonical(payload)
        assert alert is not None
        assert alert.severity == "medium"

    def test_unknown_severity_defaults_to_medium(self):
        """Unrecognised severity values default to 'medium'."""
        adapter = ElasticAdapter()
        payload = _make_signal()
        payload["signal"]["rule"]["severity"] = "URGENT"
        alert = adapter.to_canonical(payload)
        assert alert is not None
        assert alert.severity == "medium"

    def test_tactics_from_fallback_signal_rule(self):
        """Tactics extracted from signal.rule.threat when kibana path empty."""
        adapter = ElasticAdapter()
        payload = _make_signal()
        # Remove Kibana path, add signal.rule.threat
        payload["kibana"] = {}
        payload["signal"]["rule"]["threat"] = [
            {"tactic": {"name": "Persistence"}, "technique": [{"id": "T1098"}]},
        ]
        alert = adapter.to_canonical(payload)
        assert alert is not None
        assert "Persistence" in alert.tactics
        assert "T1098" in alert.techniques

    def test_entities_include_host_user_ip(self):
        """Entities contain host, user, and source IP from ECS fields."""
        adapter = ElasticAdapter()
        payload = _make_signal()
        alert = adapter.to_canonical(payload)
        assert alert is not None
        import json
        entities = json.loads(alert.entities_raw)
        types = {e["Type"] for e in entities}
        assert "host" in types
        assert "account" in types
        assert "ip" in types
