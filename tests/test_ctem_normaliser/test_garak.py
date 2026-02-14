"""Tests for Garak normaliser — Story 8.3."""

import pytest

from ctem_normaliser.garak import GarakNormaliser, _map_success_rate


@pytest.fixture
def normaliser():
    return GarakNormaliser()


@pytest.fixture
def garak_finding():
    return {
        "title": "Prompt Injection via DAN",
        "model_name": "aluskort-reasoning-v1",
        "probe_type": "prompt_injection",
        "success_rate": 0.75,
        "description": "DAN jailbreak succeeded",
        "deployment_zone": "Zone3_Enterprise",
        "tested_at": "2026-02-01T12:00:00Z",
        "tenant_id": "tenant-A",
    }


class TestGarakNormaliser:
    def test_source_name(self, normaliser):
        assert normaliser.source_name() == "garak"

    def test_normalises_basic(self, normaliser, garak_finding):
        e = normaliser.normalise(garak_finding)
        assert e.source_tool == "garak"
        assert e.asset_type == "llm_model"
        assert e.asset_id == "aluskort-reasoning-v1"

    def test_prompt_injection_atlas(self, normaliser, garak_finding):
        e = normaliser.normalise(garak_finding)
        assert e.atlas_technique == "AML.T0051"

    def test_prompt_injection_safety_life(self, normaliser, garak_finding):
        e = normaliser.normalise(garak_finding)
        assert e.physical_consequence == "safety_life"

    def test_extraction_probe(self, normaliser, garak_finding):
        garak_finding["probe_type"] = "extraction"
        e = normaliser.normalise(garak_finding)
        assert e.physical_consequence == "data_loss"
        assert e.atlas_technique == "AML.T0044.001"

    def test_escalation_probe(self, normaliser, garak_finding):
        garak_finding["probe_type"] = "escalation"
        e = normaliser.normalise(garak_finding)
        assert e.physical_consequence == "safety_life"

    def test_tool_use_probe(self, normaliser, garak_finding):
        garak_finding["probe_type"] = "tool_use"
        e = normaliser.normalise(garak_finding)
        assert e.physical_consequence == "safety_life"

    def test_high_success_rate(self, normaliser, garak_finding):
        e = normaliser.normalise(garak_finding)
        assert e.exploitability_score == 0.75
        # high exploit + safety_life → CRITICAL
        assert e.severity == "CRITICAL"

    def test_low_success_rate(self, normaliser, garak_finding):
        garak_finding["success_rate"] = 0.1
        e = normaliser.normalise(garak_finding)
        # low exploit + safety_life → HIGH
        assert e.severity == "HIGH"

    def test_deterministic_key(self, normaliser, garak_finding):
        e1 = normaliser.normalise(garak_finding)
        e2 = normaliser.normalise(garak_finding)
        assert e1.exposure_key == e2.exposure_key

    def test_deployment_zone(self, normaliser, garak_finding):
        garak_finding["deployment_zone"] = "Zone1_EdgeInference"
        e = normaliser.normalise(garak_finding)
        assert e.asset_zone == "Zone1_EdgeInference"

    def test_ctem_score_positive(self, normaliser, garak_finding):
        e = normaliser.normalise(garak_finding)
        assert e.ctem_score > 0


class TestSuccessRateMapping:
    def test_high(self):
        assert _map_success_rate(0.8) == "high"

    def test_medium(self):
        assert _map_success_rate(0.5) == "medium"

    def test_low(self):
        assert _map_success_rate(0.1) == "low"

    def test_boundary_high(self):
        assert _map_success_rate(0.7) == "high"

    def test_boundary_medium(self):
        assert _map_success_rate(0.3) == "medium"
