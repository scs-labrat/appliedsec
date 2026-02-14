"""Tests for injection protection in entity parsing — Story 3.5."""

from __future__ import annotations

import json

from entity_parser.parser import parse_alert_entities


class TestPromptInjection:
    def test_injection_in_entity_name_stripped(self):
        entities = json.dumps([
            {
                "$id": "1",
                "Type": "account",
                "Name": "admin'; DROP TABLE users;--",
                "UPNSuffix": "evil.com",
            }
        ])
        result = parse_alert_entities(entities)
        assert len(result.accounts) == 1
        # Dangerous chars should be stripped from the primary value
        assert ";" not in result.accounts[0].primary_value
        assert "'" not in result.accounts[0].primary_value

    def test_injection_in_ip_rejected(self):
        entities = json.dumps([
            {
                "$id": "1",
                "Type": "ip",
                "Address": "1.2.3.4; cat /etc/passwd",
            }
        ])
        result = parse_alert_entities(entities)
        # IP validation should reject this
        assert len(result.ips) == 0
        assert len(result.parse_errors) > 0

    def test_injection_in_url_stripped(self):
        entities = json.dumps([
            {
                "$id": "1",
                "Type": "url",
                "Url": "https://evil.com/$(whoami)",
            }
        ])
        result = parse_alert_entities(entities)
        assert len(result.urls) == 1
        assert "$(" not in result.urls[0].primary_value

    def test_oversized_entity_truncated(self):
        entities = json.dumps([
            {
                "$id": "1",
                "Type": "url",
                "Url": "https://evil.com/" + "A" * 3000,
            }
        ])
        result = parse_alert_entities(entities)
        assert len(result.urls) == 1
        assert len(result.urls[0].primary_value) <= 2048


class TestEdgeCases:
    def test_empty_entities_raw(self):
        result = parse_alert_entities("")
        assert len(result.parse_errors) == 0
        assert len(result.raw_iocs) == 0

    def test_empty_json_array(self):
        result = parse_alert_entities("[]")
        assert len(result.parse_errors) == 0

    def test_non_dict_entity_logged(self):
        result = parse_alert_entities('["string_not_dict", 42]')
        assert len(result.parse_errors) == 2

    def test_unknown_entity_type(self):
        entities = json.dumps([
            {"$id": "1", "Type": "quantum_flux", "Value": "42"}
        ])
        result = parse_alert_entities(entities)
        assert any("Unknown entity type" in e for e in result.parse_errors)

    def test_missing_required_field(self):
        entities = json.dumps([
            {"$id": "1", "Type": "ip"}  # No Address field
        ])
        result = parse_alert_entities(entities)
        assert len(result.ips) == 0
        assert len(result.parse_errors) > 0

    def test_null_entities_raw_with_raw_payload(self):
        result = parse_alert_entities(
            None,  # type: ignore[arg-type]
            raw_payload={"data": "10.0.0.1"},
        )
        # Should fall back to regex
        assert len(result.ips) == 1
