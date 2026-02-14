"""Tests for CanonicalAlert model — AC-1.1.1, AC-1.1.2, AC-1.1.3."""

import pytest
from pydantic import ValidationError

from shared.schemas.alert import CanonicalAlert


def _valid_alert_dict() -> dict:
    return {
        "alert_id": "SENT-2026-001",
        "source": "sentinel",
        "timestamp": "2026-02-14T10:30:00+00:00",
        "title": "Suspicious PowerShell Execution",
        "description": "Encoded command detected on WKSTN-042",
        "severity": "high",
        "tactics": ["execution", "defense-evasion"],
        "techniques": ["T1059.001", "T1027"],
        "entities_raw": '{"accounts": ["admin@contoso.com"]}',
        "product": "Microsoft Defender for Endpoint",
        "tenant_id": "tenant-001",
        "raw_payload": {"SystemAlertId": "SENT-2026-001"},
    }


class TestCanonicalAlertValidation:
    """AC-1.1.1: Valid alert dict creates model with correct types."""

    def test_valid_alert_creates_model(self):
        alert = CanonicalAlert(**_valid_alert_dict())
        assert alert.alert_id == "SENT-2026-001"
        assert alert.source == "sentinel"
        assert alert.severity == "high"
        assert alert.tactics == ["execution", "defense-evasion"]
        assert alert.techniques == ["T1059.001", "T1027"]
        assert isinstance(alert.raw_payload, dict)

    def test_optional_fields_default_correctly(self):
        minimal = {
            "alert_id": "A1",
            "source": "elastic",
            "timestamp": "2026-01-01T00:00:00Z",
            "title": "Test",
            "description": "desc",
            "severity": "low",
        }
        alert = CanonicalAlert(**minimal)
        assert alert.tactics == []
        assert alert.techniques == []
        assert alert.entities_raw == ""
        assert alert.product == ""
        assert alert.tenant_id == ""
        assert alert.raw_payload == {}


class TestCanonicalAlertRejection:
    """AC-1.1.2: Missing required fields raise ValidationError."""

    @pytest.mark.parametrize(
        "missing_field",
        ["alert_id", "source", "timestamp", "title", "description", "severity"],
    )
    def test_missing_required_field_raises(self, missing_field: str):
        data = _valid_alert_dict()
        del data[missing_field]
        with pytest.raises(ValidationError) as exc_info:
            CanonicalAlert(**data)
        errors = exc_info.value.errors()
        assert any(missing_field in str(e["loc"]) for e in errors)


class TestSeverityEnumEnforcement:
    """AC-1.1.3: Invalid severity raises ValidationError."""

    def test_invalid_severity_rejected(self):
        data = _valid_alert_dict()
        data["severity"] = "urgent"
        with pytest.raises(ValidationError):
            CanonicalAlert(**data)

    @pytest.mark.parametrize(
        "sev", ["critical", "high", "medium", "low", "informational"]
    )
    def test_valid_severities_accepted(self, sev: str):
        data = _valid_alert_dict()
        data["severity"] = sev
        alert = CanonicalAlert(**data)
        assert alert.severity == sev

    def test_invalid_timestamp_rejected(self):
        data = _valid_alert_dict()
        data["timestamp"] = "not-a-date"
        with pytest.raises(ValidationError):
            CanonicalAlert(**data)
