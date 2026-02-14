"""Tests for Snyk normaliser — Story 8.2."""

import pytest

from ctem_normaliser.snyk import SnykNormaliser, _is_ml_package, _map_cvss_exploitability


@pytest.fixture
def normaliser():
    return SnykNormaliser()


@pytest.fixture
def snyk_finding():
    return {
        "title": "Prototype Pollution in lodash",
        "project_id": "proj-001",
        "severity": "HIGH",
        "packageName": "lodash",
        "packageManager": "npm",
        "exploitability_score": 8.0,
        "description": "Prototype pollution vulnerability",
        "cve": "CVE-2026-9999",
        "fixedIn": "4.17.22",
        "url": "https://snyk.io/vuln/npm:lodash",
        "tenant_id": "tenant-A",
    }


class TestSnykNormaliser:
    def test_source_name(self, normaliser):
        assert normaliser.source_name() == "snyk"

    def test_normalises_basic(self, normaliser, snyk_finding):
        e = normaliser.normalise(snyk_finding)
        assert e.source_tool == "snyk"
        assert e.title == "Prototype Pollution in lodash"
        assert e.asset_id == "proj-001"

    def test_zone_always_enterprise(self, normaliser, snyk_finding):
        e = normaliser.normalise(snyk_finding)
        assert e.asset_zone == "Zone3_Enterprise"

    def test_cvss_exploitability(self, normaliser, snyk_finding):
        e = normaliser.normalise(snyk_finding)
        assert e.exploitability_score == pytest.approx(0.8)

    def test_non_ml_package_data_loss(self, normaliser, snyk_finding):
        e = normaliser.normalise(snyk_finding)
        assert e.physical_consequence == "data_loss"

    def test_ml_package_safety_life(self, normaliser, snyk_finding):
        snyk_finding["packageName"] = "torch"
        e = normaliser.normalise(snyk_finding)
        assert e.physical_consequence == "safety_life"

    def test_ml_package_tensorflow(self, normaliser, snyk_finding):
        snyk_finding["packageName"] = "tensorflow-gpu"
        e = normaliser.normalise(snyk_finding)
        assert e.physical_consequence == "safety_life"

    def test_deterministic_key(self, normaliser, snyk_finding):
        e1 = normaliser.normalise(snyk_finding)
        e2 = normaliser.normalise(snyk_finding)
        assert e1.exposure_key == e2.exposure_key

    def test_cve_as_attack_technique(self, normaliser, snyk_finding):
        e = normaliser.normalise(snyk_finding)
        assert e.attack_technique == "CVE-2026-9999"

    def test_remediation_from_fixedIn(self, normaliser, snyk_finding):
        e = normaliser.normalise(snyk_finding)
        assert "4.17.22" in e.remediation_guidance


class TestCVSSMapping:
    def test_high(self):
        assert _map_cvss_exploitability(8.0) == "high"

    def test_medium(self):
        assert _map_cvss_exploitability(5.0) == "medium"

    def test_low(self):
        assert _map_cvss_exploitability(2.0) == "low"

    def test_boundary_high(self):
        assert _map_cvss_exploitability(7.0) == "high"

    def test_boundary_medium(self):
        assert _map_cvss_exploitability(3.0) == "medium"


class TestMLPackageDetection:
    def test_torch(self):
        assert _is_ml_package("torch") is True

    def test_tensorflow(self):
        assert _is_ml_package("tensorflow") is True

    def test_sklearn(self):
        assert _is_ml_package("scikit-learn") is True

    def test_not_ml(self):
        assert _is_ml_package("lodash") is False

    def test_partial_match(self):
        assert _is_ml_package("pytorch-lightning") is True
