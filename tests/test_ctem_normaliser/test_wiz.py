"""Tests for Wiz normaliser — Story 8.1."""

import pytest

from ctem_normaliser.wiz import WizNormaliser
from ctem_normaliser.models import generate_exposure_key


@pytest.fixture
def normaliser():
    return WizNormaliser()


@pytest.fixture
def wiz_finding():
    return {
        "title": "S3 Bucket Public Access",
        "resource_id": "arn:aws:s3:::my-bucket",
        "severity": "HIGH",
        "resource_type": "s3",
        "description": "Public access enabled on S3 bucket",
        "detected_at": "2026-01-15T10:00:00Z",
        "remediation": "Disable public access",
        "url": "https://app.wiz.io/finding/123",
        "tenant_id": "tenant-A",
    }


class TestWizNormaliser:
    def test_source_name(self, normaliser):
        assert normaliser.source_name() == "wiz"

    def test_normalises_basic_finding(self, normaliser, wiz_finding):
        e = normaliser.normalise(wiz_finding)
        assert e.source_tool == "wiz"
        assert e.title == "S3 Bucket Public Access"
        assert e.asset_id == "arn:aws:s3:::my-bucket"

    def test_deterministic_key(self, normaliser, wiz_finding):
        e1 = normaliser.normalise(wiz_finding)
        e2 = normaliser.normalise(wiz_finding)
        assert e1.exposure_key == e2.exposure_key
        assert len(e1.exposure_key) == 16

    def test_severity_mapping(self, normaliser, wiz_finding):
        e = normaliser.normalise(wiz_finding)
        # HIGH severity → high exploitability, default zone → Zone3 → data_loss
        # high + data_loss → MEDIUM
        assert e.severity == "MEDIUM"
        assert e.original_severity == "HIGH"

    def test_critical_severity(self, normaliser, wiz_finding):
        wiz_finding["severity"] = "CRITICAL"
        e = normaliser.normalise(wiz_finding)
        assert e.exploitability_score == 0.9

    def test_edge_zone(self, normaliser, wiz_finding):
        wiz_finding["resource_type"] = "edge"
        e = normaliser.normalise(wiz_finding)
        assert e.asset_zone == "Zone1_EdgeInference"
        # Zone1 → equipment, high exploit → CRITICAL
        assert e.severity == "CRITICAL"

    def test_default_zone(self, normaliser, wiz_finding):
        e = normaliser.normalise(wiz_finding)
        assert e.asset_zone == "Zone3_Enterprise"

    def test_ctem_score_positive(self, normaliser, wiz_finding):
        e = normaliser.normalise(wiz_finding)
        assert e.ctem_score > 0

    def test_sla_deadline_set(self, normaliser, wiz_finding):
        e = normaliser.normalise(wiz_finding)
        assert e.sla_deadline != ""

    def test_status_open(self, normaliser, wiz_finding):
        e = normaliser.normalise(wiz_finding)
        assert e.status == "Open"

    def test_preserves_tenant(self, normaliser, wiz_finding):
        e = normaliser.normalise(wiz_finding)
        assert e.tenant_id == "tenant-A"

    def test_low_severity(self, normaliser, wiz_finding):
        wiz_finding["severity"] = "LOW"
        e = normaliser.normalise(wiz_finding)
        assert e.exploitability_score == 0.2
        assert e.original_severity == "LOW"

    def test_informational_severity(self, normaliser, wiz_finding):
        wiz_finding["severity"] = "INFORMATIONAL"
        e = normaliser.normalise(wiz_finding)
        assert e.exploitability_score == 0.2
