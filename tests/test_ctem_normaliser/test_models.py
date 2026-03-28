"""Tests for CTEM models and scoring functions."""

import pytest
from datetime import datetime, timezone

from ctem_normaliser.models import (
    CONSEQUENCE_WEIGHTS,
    SEVERITY_MATRIX,
    SLA_DEADLINES,
    ZONE_CONSEQUENCE_DEFAULT,
    ZONE_CONSEQUENCE_FALLBACK,
    CTEMExposure,
    compute_ctem_score,
    compute_severity,
    compute_sla_deadline,
    generate_exposure_key,
    get_zone_consequence,
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
    """REM-H01: comprehensive zone-consequence fallback coverage."""

    def test_minimum_zone_coverage(self):
        """At least the 5 original Purdue zones plus expanded coverage."""
        assert len(ZONE_CONSEQUENCE_FALLBACK) >= 30

    def test_zone0_safety_life(self):
        assert get_zone_consequence("Zone0_PhysicalProcess") == "safety_life"

    def test_zone0_safety_zone(self):
        assert get_zone_consequence("Zone0_Safety") == "safety_life"

    def test_zone1_equipment(self):
        assert get_zone_consequence("Zone1_EdgeInference") == "equipment"

    def test_zone1_plc(self):
        assert get_zone_consequence("Zone1_PLCNetwork") == "equipment"

    def test_zone2_operations(self):
        assert get_zone_consequence("Zone2_Operations") == "downtime"

    def test_zone2_scada(self):
        assert get_zone_consequence("Zone2_SCADA") == "downtime"

    def test_zone3_enterprise(self):
        assert get_zone_consequence("Zone3_Enterprise") == "data_loss"

    def test_zone3_manufacturing(self):
        assert get_zone_consequence("Zone3_Manufacturing") == "downtime"

    def test_zone4_external(self):
        assert get_zone_consequence("Zone4_External") == "data_loss"

    def test_cloud_production_downtime(self):
        assert get_zone_consequence("Cloud_Production") == "downtime"

    def test_cloud_development_data_loss(self):
        assert get_zone_consequence("Cloud_Development") == "data_loss"

    def test_ot_safety_instrumented_system(self):
        assert get_zone_consequence("OT_SafetyInstrumentedSystem") == "safety_life"

    def test_ot_control_network(self):
        assert get_zone_consequence("OT_ControlNetwork") == "equipment"

    def test_unknown_zone_defaults_data_loss(self):
        """Unknown zones default to data_loss (least severe) to avoid false negatives."""
        assert get_zone_consequence("Zone99_Unknown") == "data_loss"
        assert get_zone_consequence("") == "data_loss"

    def test_every_zone_maps_to_valid_consequence(self):
        valid_consequences = {"safety_life", "equipment", "downtime", "data_loss"}
        for zone, consequence in ZONE_CONSEQUENCE_FALLBACK.items():
            assert consequence in valid_consequences, (
                f"Zone {zone} maps to invalid consequence '{consequence}'"
            )

    def test_safety_zones_exist(self):
        """At least one zone maps to each consequence category."""
        consequences = set(ZONE_CONSEQUENCE_FALLBACK.values())
        assert "safety_life" in consequences
        assert "equipment" in consequences
        assert "downtime" in consequences
        assert "data_loss" in consequences


class TestConsequenceWeights:
    def test_safety_life_highest(self):
        assert CONSEQUENCE_WEIGHTS["safety_life"] == 1.0

    def test_data_loss_lowest(self):
        assert CONSEQUENCE_WEIGHTS["data_loss"] == 0.3

    def test_four_consequences(self):
        assert len(CONSEQUENCE_WEIGHTS) == 4
