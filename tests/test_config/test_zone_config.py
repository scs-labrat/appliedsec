"""Tests for YAML-driven zone consequence config — Story 14.1."""

from __future__ import annotations

import os

import pytest

from shared.config.zone_config import (
    _reset_cache,
    get_consequence_class,
    get_consequence_for_zone,
    get_severity,
    load_zone_consequences,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    """Reset module cache before each test."""
    _reset_cache()
    yield
    _reset_cache()


# ---------------------------------------------------------------------------
# TestZoneConfig — YAML loading and lookup
# ---------------------------------------------------------------------------

class TestZoneConfig:
    """Task 2: YAML loader, all zones correct, unknown defaults, caching."""

    def test_yaml_loads_successfully(self):
        """YAML config loads without errors."""
        cfg = load_zone_consequences()
        assert "zone_consequence" in cfg
        assert "default_consequence_class" in cfg
        assert "default_severity" in cfg

    def test_all_five_zones_present(self):
        """All 5 zones are defined in the YAML."""
        cfg = load_zone_consequences()
        zones = cfg["zone_consequence"]
        expected = {
            "Zone0_PhysicalProcess",
            "Zone1_EdgeInference",
            "Zone2_Operations",
            "Zone3_Enterprise",
            "Zone4_External",
        }
        assert set(zones.keys()) == expected

    def test_zone0_consequence_class(self):
        assert get_consequence_class("Zone0_PhysicalProcess") == "safety_life"

    def test_zone1_consequence_class(self):
        assert get_consequence_class("Zone1_EdgeInference") == "equipment"

    def test_zone2_consequence_class(self):
        assert get_consequence_class("Zone2_Operations") == "downtime"

    def test_zone3_consequence_class(self):
        assert get_consequence_class("Zone3_Enterprise") == "data_loss"

    def test_zone4_consequence_class(self):
        assert get_consequence_class("Zone4_External") == "data_loss"

    def test_zone0_severity(self):
        assert get_severity("Zone0_PhysicalProcess") == "CRITICAL"

    def test_zone1_severity(self):
        assert get_severity("Zone1_EdgeInference") == "HIGH"

    def test_zone2_severity(self):
        assert get_severity("Zone2_Operations") == "MEDIUM"

    def test_zone3_severity(self):
        assert get_severity("Zone3_Enterprise") == "LOW"

    def test_unknown_zone_consequence_default(self):
        """Unknown zone returns default consequence class."""
        assert get_consequence_class("UnknownZone") == "data_loss"

    def test_unknown_zone_severity_default(self):
        """Unknown zone returns default severity."""
        assert get_severity("UnknownZone") == "LOW"

    def test_get_consequence_for_zone_tuple(self):
        """get_consequence_for_zone returns (class, severity) tuple."""
        cc, sev = get_consequence_for_zone("Zone0_PhysicalProcess")
        assert cc == "safety_life"
        assert sev == "CRITICAL"

    def test_caching_returns_same_object(self):
        """Subsequent calls return cached config."""
        cfg1 = load_zone_consequences()
        cfg2 = load_zone_consequences()
        assert cfg1 is cfg2


# ---------------------------------------------------------------------------
# TestZoneCoverage — every zone in CTEM fixtures has a YAML mapping
# ---------------------------------------------------------------------------

class TestZoneCoverage:
    """Task 4: Every zone in CTEM test fixtures has a mapping."""

    def test_wiz_zone_map_covered(self):
        """All zones in wiz.py _ZONE_MAP are covered by YAML config."""
        from ctem_normaliser.wiz import _ZONE_MAP
        cfg = load_zone_consequences()
        zones = set(cfg["zone_consequence"].keys())
        for zone in _ZONE_MAP.values():
            assert zone in zones, f"Zone '{zone}' from _ZONE_MAP not in YAML"

    def test_ctem_model_zones_covered(self):
        """The five standard asset zones all have YAML entries."""
        standard_zones = [
            "Zone0_PhysicalProcess",
            "Zone1_EdgeInference",
            "Zone2_Operations",
            "Zone3_Enterprise",
            "Zone4_External",
        ]
        for zone in standard_zones:
            cc = get_consequence_class(zone)
            assert cc != "", f"Zone '{zone}' has empty consequence class"


# ---------------------------------------------------------------------------
# TestFallbackBehavior — Neo4j unavailable → YAML produces correct results
# ---------------------------------------------------------------------------

class TestFallbackBehavior:
    """Task 4: Neo4j unavailable → YAML fallback produces correct severity."""

    def test_zone0_fallback_critical(self):
        """Zone0 (safety_life) → CRITICAL when Neo4j down."""
        cc, sev = get_consequence_for_zone("Zone0_PhysicalProcess")
        assert sev == "CRITICAL"
        assert cc == "safety_life"

    def test_zone1_fallback_high(self):
        """Zone1 (equipment) → HIGH when Neo4j down."""
        cc, sev = get_consequence_for_zone("Zone1_EdgeInference")
        assert sev == "HIGH"
        assert cc == "equipment"

    def test_zone2_fallback_medium(self):
        """Zone2 (downtime) → MEDIUM when Neo4j down."""
        cc, sev = get_consequence_for_zone("Zone2_Operations")
        assert sev == "MEDIUM"
        assert cc == "downtime"

    def test_zone3_fallback_low(self):
        """Zone3 (data_loss) → LOW when Neo4j down."""
        cc, sev = get_consequence_for_zone("Zone3_Enterprise")
        assert sev == "LOW"
        assert cc == "data_loss"

    def test_neo4j_graph_fallback_still_works(self):
        """The neo4j_graph module's ZONE_CONSEQUENCE_FALLBACK is now YAML-driven."""
        from shared.db.neo4j_graph import ZONE_CONSEQUENCE_FALLBACK
        assert ZONE_CONSEQUENCE_FALLBACK["safety_life"] == "CRITICAL"
        assert ZONE_CONSEQUENCE_FALLBACK["equipment"] == "HIGH"
        assert ZONE_CONSEQUENCE_FALLBACK["downtime"] == "MEDIUM"
        assert ZONE_CONSEQUENCE_FALLBACK["data_loss"] == "LOW"

    def test_ctem_models_fallback_still_works(self):
        """The ctem_normaliser models ZONE_CONSEQUENCE_FALLBACK is now YAML-driven."""
        from ctem_normaliser.models import ZONE_CONSEQUENCE_FALLBACK
        assert ZONE_CONSEQUENCE_FALLBACK["Zone0_PhysicalProcess"] == "safety_life"
        assert ZONE_CONSEQUENCE_FALLBACK["Zone3_Enterprise"] == "data_loss"
