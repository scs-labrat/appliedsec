"""Tests for output validator — Story 5.4 + REM-C01 taxonomy validation."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from context_gateway.output_validator import validate_output, load_and_validate_output


class TestTechniqueValidation:
    def test_valid_technique_passes(self):
        content = "The attacker used T1059.001 for execution."
        valid, errors, quarantined = validate_output(
            content, known_technique_ids={"T1059.001", "T1078"}
        )
        assert valid is True
        assert len(errors) == 0
        assert len(quarantined) == 0

    def test_unknown_technique_quarantined(self):
        content = "Detected T9999.999 activity."
        valid, errors, quarantined = validate_output(
            content, known_technique_ids={"T1059.001"}
        )
        assert valid is False
        assert "T9999.999" in quarantined
        assert any("Unknown technique ID" in e for e in errors)

    def test_multiple_techniques_mixed(self):
        content = "Used T1059.001 and T9999 for attack."
        valid, errors, quarantined = validate_output(
            content, known_technique_ids={"T1059.001"}
        )
        assert valid is False
        assert "T9999" in quarantined
        assert "T1059.001" not in quarantined

    def test_atlas_technique_validated(self):
        content = "ML model attack using AML.T0043."
        valid, errors, quarantined = validate_output(
            content, known_technique_ids={"AML.T0043"}
        )
        assert valid is True

    def test_no_technique_ids_skips_validation(self):
        valid, errors, quarantined = validate_output(
            "Random text T9999", known_technique_ids=None
        )
        assert valid is True
        assert len(quarantined) == 0


class TestSchemaValidation:
    def test_valid_json_against_schema(self):
        schema = {
            "type": "object",
            "required": ["verdict", "confidence"],
            "properties": {
                "verdict": {"type": "string"},
                "confidence": {"type": "number"},
            },
        }
        content = json.dumps({"verdict": "malicious", "confidence": 0.95})
        valid, errors, _ = validate_output(content, output_schema=schema)
        assert valid is True
        assert len(errors) == 0

    def test_missing_required_field(self):
        schema = {
            "type": "object",
            "required": ["verdict", "confidence"],
        }
        content = json.dumps({"verdict": "clean"})
        valid, errors, _ = validate_output(content, output_schema=schema)
        assert valid is False
        assert any("confidence" in e for e in errors)

    def test_wrong_field_type(self):
        schema = {
            "type": "object",
            "properties": {
                "confidence": {"type": "number"},
            },
        }
        content = json.dumps({"confidence": "not a number"})
        valid, errors, _ = validate_output(content, output_schema=schema)
        assert valid is False
        assert any("expected number" in e for e in errors)

    def test_expected_object_got_array(self):
        schema = {"type": "object"}
        content = json.dumps([1, 2, 3])
        valid, errors, _ = validate_output(content, output_schema=schema)
        assert valid is False

    def test_expected_array_got_object(self):
        schema = {"type": "array"}
        content = json.dumps({"key": "value"})
        valid, errors, _ = validate_output(content, output_schema=schema)
        assert valid is False

    def test_malformed_json(self):
        schema = {"type": "object"}
        valid, errors, _ = validate_output("not json {", output_schema=schema)
        assert valid is False
        assert any("not valid JSON" in e for e in errors)

    def test_no_schema_skips_validation(self):
        valid, errors, _ = validate_output("any text", output_schema=None)
        assert valid is True


class TestCombinedValidation:
    def test_both_technique_and_schema(self):
        schema = {
            "type": "object",
            "required": ["technique"],
            "properties": {"technique": {"type": "string"}},
        }
        content = json.dumps({"technique": "T1059.001"})
        valid, errors, quarantined = validate_output(
            content,
            known_technique_ids={"T1059.001"},
            output_schema=schema,
        )
        assert valid is True

    def test_technique_invalid_schema_valid(self):
        schema = {"type": "object", "required": ["result"]}
        content = json.dumps({"result": "T9999 detected"})
        valid, errors, quarantined = validate_output(
            content,
            known_technique_ids={"T1059.001"},
            output_schema=schema,
        )
        assert valid is False
        assert "T9999" in quarantined


# ── REM-C01: Async DB-backed taxonomy validation ───────────────────────


class TestAsyncTaxonomyValidation:
    """TC-UNT-050 through TC-UNT-054: taxonomy validation with DB lookup."""

    @pytest.mark.asyncio
    async def test_valid_id_passes_from_db(self):
        """TC-UNT-050: valid technique ID found in taxonomy_ids table passes."""
        db = AsyncMock()
        db.get_technique_ids.return_value = {"T1059.001", "T1078", "AML.T0043"}
        db.get_taxonomy_version.return_value = "attack-16.1+atlas-4.5.2"

        content = "The attacker used T1059.001 for execution."
        valid, errors, quarantined, version = await load_and_validate_output(
            content, db=db
        )
        assert valid is True
        assert len(quarantined) == 0
        assert version == "attack-16.1+atlas-4.5.2"

    @pytest.mark.asyncio
    async def test_hallucinated_id_blocked(self):
        """TC-UNT-051: hallucinated technique ID is quarantined."""
        db = AsyncMock()
        db.get_technique_ids.return_value = {"T1059.001"}
        db.get_taxonomy_version.return_value = "attack-16.1+atlas-4.5.2"

        content = "Detected T9999 activity via T1059.001."
        valid, errors, quarantined, version = await load_and_validate_output(
            content, db=db
        )
        assert valid is False
        assert "T9999" in quarantined
        assert "T1059.001" not in quarantined

    @pytest.mark.asyncio
    async def test_hallucinated_atlas_id_blocked(self):
        """TC-UNT-052: hallucinated ATLAS technique ID is quarantined."""
        db = AsyncMock()
        db.get_technique_ids.return_value = {"AML.T0043"}
        db.get_taxonomy_version.return_value = "attack-16.1+atlas-4.5.2"

        content = "Attack used AML.T0099 and AML.T0043."
        valid, errors, quarantined, _ = await load_and_validate_output(
            content, db=db
        )
        assert valid is False
        assert "AML.T0099" in quarantined
        assert "AML.T0043" not in quarantined

    @pytest.mark.asyncio
    async def test_taxonomy_version_recorded(self):
        """TC-UNT-053: taxonomy version is returned for decision chain recording."""
        db = AsyncMock()
        db.get_technique_ids.return_value = {"T1059.001"}
        db.get_taxonomy_version.return_value = "attack-16.1+atlas-4.5.2"

        _, _, _, version = await load_and_validate_output(
            "Clean text.", db=db
        )
        assert version == "attack-16.1+atlas-4.5.2"

    @pytest.mark.asyncio
    async def test_empty_db_skips_validation(self):
        """TC-UNT-054: empty taxonomy_ids table skips technique validation."""
        db = AsyncMock()
        db.get_technique_ids.return_value = set()
        db.get_taxonomy_version.return_value = ""

        content = "T9999 should not be flagged when DB is empty."
        valid, errors, quarantined, version = await load_and_validate_output(
            content, db=db
        )
        assert valid is True
        assert len(quarantined) == 0

    @pytest.mark.asyncio
    async def test_deprecated_id_flagged(self):
        """Deprecated technique IDs not in active set are quarantined."""
        db = AsyncMock()
        # Only non-deprecated IDs loaded
        db.get_technique_ids.return_value = {"T1059.001"}
        db.get_taxonomy_version.return_value = "attack-16.1+atlas-4.5.2"

        content = "Used deprecated T1050 technique."
        valid, errors, quarantined, _ = await load_and_validate_output(
            content, db=db
        )
        assert valid is False
        assert "T1050" in quarantined
