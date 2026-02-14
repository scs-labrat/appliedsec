"""Tests for ART normaliser — Story 8.4."""

import pytest

from ctem_normaliser.art import ARTNormaliser, _map_success_rate


@pytest.fixture
def normaliser():
    return ARTNormaliser()


@pytest.fixture
def art_finding():
    return {
        "title": "Adversarial Evasion Attack",
        "model_id": "model-classifier-v2",
        "attack_type": "evasion",
        "success_rate": 0.65,
        "description": "FGSM evasion attack on image classifier",
        "attack_technique": "T1499",
        "tested_at": "2026-02-10T08:00:00Z",
        "asset_zone": "Zone2_Operations",
        "tenant_id": "tenant-B",
    }


class TestARTNormaliser:
    def test_source_name(self, normaliser):
        assert normaliser.source_name() == "art"

    def test_normalises_basic(self, normaliser, art_finding):
        e = normaliser.normalise(art_finding)
        assert e.source_tool == "art"
        assert e.asset_type == "ml_model"
        assert e.asset_id == "model-classifier-v2"

    def test_evasion_maps_equipment(self, normaliser, art_finding):
        e = normaliser.normalise(art_finding)
        assert e.physical_consequence == "equipment"
        assert e.atlas_technique == "AML.T0015"

    def test_poisoning_maps_safety_life(self, normaliser, art_finding):
        art_finding["attack_type"] = "poisoning"
        e = normaliser.normalise(art_finding)
        assert e.physical_consequence == "safety_life"
        assert e.atlas_technique == "AML.T0020"

    def test_extraction_maps_data_loss(self, normaliser, art_finding):
        art_finding["attack_type"] = "extraction"
        e = normaliser.normalise(art_finding)
        assert e.physical_consequence == "data_loss"
        assert e.atlas_technique == "AML.T0044"

    def test_inference_maps_data_loss(self, normaliser, art_finding):
        art_finding["attack_type"] = "inference"
        e = normaliser.normalise(art_finding)
        assert e.atlas_technique == "AML.T0044.001"

    def test_attack_technique_preserved(self, normaliser, art_finding):
        e = normaliser.normalise(art_finding)
        assert e.attack_technique == "T1499"

    def test_high_success_rate(self, normaliser, art_finding):
        art_finding["success_rate"] = 0.85
        e = normaliser.normalise(art_finding)
        assert e.exploitability_score == 0.85
        # high + equipment → CRITICAL
        assert e.severity == "CRITICAL"

    def test_medium_success_rate(self, normaliser, art_finding):
        e = normaliser.normalise(art_finding)
        assert e.exploitability_score == 0.65
        # medium + equipment → HIGH
        assert e.severity == "HIGH"

    def test_low_success_rate(self, normaliser, art_finding):
        art_finding["success_rate"] = 0.1
        e = normaliser.normalise(art_finding)
        # low + equipment → MEDIUM
        assert e.severity == "MEDIUM"

    def test_deterministic_key(self, normaliser, art_finding):
        e1 = normaliser.normalise(art_finding)
        e2 = normaliser.normalise(art_finding)
        assert e1.exposure_key == e2.exposure_key

    def test_asset_zone_from_raw(self, normaliser, art_finding):
        e = normaliser.normalise(art_finding)
        assert e.asset_zone == "Zone2_Operations"

    def test_poisoning_critical_at_high_rate(self, normaliser, art_finding):
        art_finding["attack_type"] = "poisoning"
        art_finding["success_rate"] = 0.9
        e = normaliser.normalise(art_finding)
        # high + safety_life → CRITICAL
        assert e.severity == "CRITICAL"
        assert e.ctem_score == pytest.approx(9.0)


class TestARTSuccessRate:
    def test_high(self):
        assert _map_success_rate(0.8) == "high"

    def test_medium(self):
        assert _map_success_rate(0.5) == "medium"

    def test_low(self):
        assert _map_success_rate(0.2) == "low"
