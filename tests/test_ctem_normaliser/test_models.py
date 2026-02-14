"""Tests for CTEM models and scoring functions."""

import pytest
from datetime import datetime, timezone

from ctem_normaliser.models import (
    CONSEQUENCE_WEIGHTS,
    SEVERITY_MATRIX,
    SLA_DEADLINES,
    ZONE_CONSEQUENCE_FALLBACK,
    CTEMExposure,
    compute_ctem_score,
    compute_severity,
    compute_sla_deadline,
    generate_exposure_key,
)


class TestCTEMExposure:
    def test_defaults(self):
        e = CTEMExposure(exposure_key="abc", ts="2026-01-01T00:00:00Z", source_tool="wiz", title="test")
        assert e.status == "Open"
        assert e.severity == ""
        assert e.ctem_score == 0.0
        assert e.tenant_id == ""

    def test_all_fields(self):
        e = CTEMExposure(
            exposure_key="abc123",
            ts="2026-01-01T00:00:00Z",
            source_tool="snyk",
            title="CVE-2026-1234",
            description="Test vuln",
            severity="HIGH",
            original_severity="HIGH",
            asset_id="proj-001",
            asset_type="npm",
            asset_zone="Zone3_Enterprise",
            exploitability_score=0.8,
            physical_consequence="data_loss",
            ctem_score=2.4,
            atlas_technique="",
            attack_technique="CVE-2026-1234",
            status="Open",
            tenant_id="tenant-A",
        )
        assert e.source_tool == "snyk"
        assert e.ctem_score == 2.4


class TestGenerateExposureKey:
    def test_deterministic(self):
        k1 = generate_exposure_key("wiz", "finding-1", "asset-1")
        k2 = generate_exposure_key("wiz", "finding-1", "asset-1")
        assert k1 == k2

    def test_different_inputs(self):
        k1 = generate_exposure_key("wiz", "finding-1", "asset-1")
        k2 = generate_exposure_key("wiz", "finding-2", "asset-1")
        assert k1 != k2

    def test_length_16(self):
        key = generate_exposure_key("snyk", "title", "asset")
        assert len(key) == 16

    def test_hex_chars(self):
        key = generate_exposure_key("garak", "probe", "model")
        assert all(c in "0123456789abcdef" for c in key)


class TestSeverityMatrix:
    def test_high_safety_life_is_critical(self):
        assert compute_severity("high", "safety_life") == "CRITICAL"

    def test_high_equipment_is_critical(self):
        assert compute_severity("high", "equipment") == "CRITICAL"

    def test_high_downtime_is_high(self):
        assert compute_severity("high", "downtime") == "HIGH"

    def test_high_data_loss_is_medium(self):
        assert compute_severity("high", "data_loss") == "MEDIUM"

    def test_medium_safety_life_is_critical(self):
        assert compute_severity("medium", "safety_life") == "CRITICAL"

    def test_medium_data_loss_is_low(self):
        assert compute_severity("medium", "data_loss") == "LOW"

    def test_low_safety_life_is_high(self):
        assert compute_severity("low", "safety_life") == "HIGH"

    def test_low_data_loss_is_low(self):
        assert compute_severity("low", "data_loss") == "LOW"

    def test_unknown_defaults_medium(self):
        assert compute_severity("unknown", "unknown") == "MEDIUM"

    def test_case_insensitive(self):
        assert compute_severity("HIGH", "SAFETY_LIFE") == "CRITICAL"

    def test_matrix_completeness(self):
        assert len(SEVERITY_MATRIX) == 12  # 3 exploit × 4 consequence


class TestCTEMScore:
    def test_max_score(self):
        # 1.0 exploit * safety_life(1.0) * 10 = 10.0
        assert compute_ctem_score(1.0, "safety_life") == 10.0

    def test_min_score(self):
        assert compute_ctem_score(0.0, "data_loss") == 0.0

    def test_equipment_weight(self):
        assert compute_ctem_score(1.0, "equipment") == pytest.approx(8.0)

    def test_downtime_weight(self):
        assert compute_ctem_score(1.0, "downtime") == pytest.approx(5.0)

    def test_data_loss_weight(self):
        assert compute_ctem_score(1.0, "data_loss") == pytest.approx(3.0)

    def test_partial_score(self):
        score = compute_ctem_score(0.5, "equipment")
        assert score == pytest.approx(4.0)

    def test_unknown_consequence(self):
        score = compute_ctem_score(1.0, "unknown")
        assert score == pytest.approx(3.0)  # defaults to 0.3 weight


class TestSLADeadlines:
    def test_critical_24h(self):
        assert SLA_DEADLINES["CRITICAL"] == 24

    def test_high_72h(self):
        assert SLA_DEADLINES["HIGH"] == 72

    def test_medium_14d(self):
        assert SLA_DEADLINES["MEDIUM"] == 336

    def test_low_30d(self):
        assert SLA_DEADLINES["LOW"] == 720


class TestComputeSLADeadline:
    def test_returns_iso_string(self):
        result = compute_sla_deadline("CRITICAL")
        datetime.fromisoformat(result)  # should not raise

    def test_critical_24h_from_base(self):
        base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = compute_sla_deadline("CRITICAL", base)
        deadline = datetime.fromisoformat(result)
        assert deadline.day == 2  # Jan 2

    def test_unknown_severity_30d(self):
        base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = compute_sla_deadline("UNKNOWN", base)
        deadline = datetime.fromisoformat(result)
        assert deadline.day == 31  # Jan 31


class TestZoneFallback:
    def test_all_zones_present(self):
        expected = {"Zone0_PhysicalProcess", "Zone1_EdgeInference",
                    "Zone2_Operations", "Zone3_Enterprise", "Zone4_External"}
        assert set(ZONE_CONSEQUENCE_FALLBACK.keys()) == expected

    def test_zone0_safety_life(self):
        assert ZONE_CONSEQUENCE_FALLBACK["Zone0_PhysicalProcess"] == "safety_life"

    def test_zone3_data_loss(self):
        assert ZONE_CONSEQUENCE_FALLBACK["Zone3_Enterprise"] == "data_loss"


class TestConsequenceWeights:
    def test_safety_life_highest(self):
        assert CONSEQUENCE_WEIGHTS["safety_life"] == 1.0

    def test_data_loss_lowest(self):
        assert CONSEQUENCE_WEIGHTS["data_loss"] == 0.3

    def test_four_consequences(self):
        assert len(CONSEQUENCE_WEIGHTS) == 4
