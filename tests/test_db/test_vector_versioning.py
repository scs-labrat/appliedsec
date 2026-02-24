"""Tests for embedding versioning on Qdrant — Story 14.6."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from shared.db.vector import (
    CURRENT_EMBEDDING_DIMENSIONS,
    CURRENT_EMBEDDING_MODEL,
    CURRENT_EMBEDDING_VERSION,
    EMBEDDING_METADATA_KEYS,
    QdrantWrapper,
    enrich_payload,
    validate_embedding_metadata,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def wrapper() -> QdrantWrapper:
    """QdrantWrapper with mocked client."""
    with patch("shared.db.vector.QdrantClient") as MockClient:
        mock = MockClient.return_value
        w = QdrantWrapper()
        w._mock = mock
        return w


# ---------------------------------------------------------------------------
# TestEmbeddingMetadata (Task 1)
# ---------------------------------------------------------------------------

class TestEmbeddingMetadata:
    """AC-1: Embedding metadata on every Qdrant point."""

    def test_enrich_payload_adds_defaults(self):
        """enrich_payload adds missing embedding metadata."""
        payload = {"tenant_id": "t-001", "doc_id": "doc-1"}
        enriched = enrich_payload(payload)
        assert enriched["embedding_model_id"] == CURRENT_EMBEDDING_MODEL
        assert enriched["embedding_dimensions"] == CURRENT_EMBEDDING_DIMENSIONS
        assert enriched["embedding_version"] == CURRENT_EMBEDDING_VERSION
        # Original fields preserved
        assert enriched["tenant_id"] == "t-001"

    def test_enrich_payload_does_not_overwrite(self):
        """enrich_payload preserves existing metadata."""
        payload = {
            "embedding_model_id": "custom-model",
            "embedding_dimensions": 768,
            "embedding_version": "2025-06",
        }
        enriched = enrich_payload(payload)
        assert enriched["embedding_model_id"] == "custom-model"
        assert enriched["embedding_dimensions"] == 768

    def test_validate_metadata_raises_on_missing(self):
        """validate_embedding_metadata raises ValueError for missing keys."""
        payload = {"tenant_id": "t-001"}
        with pytest.raises(ValueError, match="embedding_model_id"):
            validate_embedding_metadata(payload)

    def test_validate_metadata_passes_with_all_keys(self):
        """validate_embedding_metadata passes when all keys present."""
        payload = {
            "embedding_model_id": "test",
            "embedding_dimensions": 1024,
            "embedding_version": "2026-01",
        }
        validate_embedding_metadata(payload)  # Should not raise

    def test_upsert_auto_enriches_payload(self, wrapper: QdrantWrapper):
        """upsert_vectors auto-enriches payloads with metadata."""
        points = [
            {"id": "p1", "vector": [0.1], "payload": {"tenant_id": "t1"}},
        ]
        wrapper.upsert_vectors("incident_embeddings", points)
        call_kwargs = wrapper._mock.upsert.call_args[1]
        payload = call_kwargs["points"][0].payload
        assert "embedding_model_id" in payload
        assert payload["embedding_model_id"] == CURRENT_EMBEDDING_MODEL

    def test_upsert_enforce_metadata_raises(self, wrapper: QdrantWrapper):
        """upsert_vectors with enforce_metadata=True raises on missing."""
        points = [
            {"id": "p1", "vector": [0.1], "payload": {"tenant_id": "t1"}},
        ]
        with pytest.raises(ValueError, match="embedding_model_id"):
            wrapper.upsert_vectors(
                "incident_embeddings", points, enforce_metadata=True
            )

    def test_metadata_keys_constant(self):
        """EMBEDDING_METADATA_KEYS contains the three required keys."""
        assert "embedding_model_id" in EMBEDDING_METADATA_KEYS
        assert "embedding_dimensions" in EMBEDDING_METADATA_KEYS
        assert "embedding_version" in EMBEDDING_METADATA_KEYS

    def test_current_constants_defined(self):
        """Current embedding constants are defined."""
        assert CURRENT_EMBEDDING_MODEL == "text-embedding-3-large"
        assert CURRENT_EMBEDDING_DIMENSIONS == 1024
        assert CURRENT_EMBEDDING_VERSION == "2026-01"


# ---------------------------------------------------------------------------
# TestDualReadSearch (Task 2)
# ---------------------------------------------------------------------------

class TestDualReadSearch:
    """AC-4: Mixed-version query with deduplication."""

    def test_deduplicates_by_doc_id(self, wrapper: QdrantWrapper):
        """Mixed-version results are deduplicated by doc_id."""
        hit_old = MagicMock()
        hit_old.id = "p1-old"
        hit_old.score = 0.85
        hit_old.payload = {
            "doc_id": "doc-1",
            "embedding_version": "2025-06",
        }
        hit_new = MagicMock()
        hit_new.id = "p1-new"
        hit_new.score = 0.90
        hit_new.payload = {
            "doc_id": "doc-1",
            "embedding_version": "2026-01",
        }
        hit_other = MagicMock()
        hit_other.id = "p2"
        hit_other.score = 0.80
        hit_other.payload = {
            "doc_id": "doc-2",
            "embedding_version": "2026-01",
        }

        mock_result = MagicMock()
        mock_result.points = [hit_old, hit_new, hit_other]
        wrapper._mock.query_points.return_value = mock_result

        results = wrapper.search_with_version_merge(
            "incident_embeddings", [0.1], limit=10
        )
        doc_ids = [r["payload"]["doc_id"] for r in results]
        assert len(doc_ids) == 2
        assert "doc-1" in doc_ids
        assert "doc-2" in doc_ids

    def test_prefers_specified_version(self, wrapper: QdrantWrapper):
        """Prefer version selects the specified embedding version."""
        hit_old = MagicMock()
        hit_old.id = "p1-old"
        hit_old.score = 0.90
        hit_old.payload = {"doc_id": "doc-1", "embedding_version": "2025-06"}
        hit_new = MagicMock()
        hit_new.id = "p1-new"
        hit_new.score = 0.85
        hit_new.payload = {"doc_id": "doc-1", "embedding_version": "2026-01"}

        mock_result = MagicMock()
        mock_result.points = [hit_old, hit_new]
        wrapper._mock.query_points.return_value = mock_result

        results = wrapper.search_with_version_merge(
            "incident_embeddings", [0.1], limit=10, prefer_version="2026-01"
        )
        assert results[0]["id"] == "p1-new"

    def test_newest_version_default(self, wrapper: QdrantWrapper):
        """Without prefer_version, newest version wins."""
        hit_old = MagicMock()
        hit_old.id = "p1-old"
        hit_old.score = 0.90
        hit_old.payload = {"doc_id": "doc-1", "embedding_version": "2025-06"}
        hit_new = MagicMock()
        hit_new.id = "p1-new"
        hit_new.score = 0.85
        hit_new.payload = {"doc_id": "doc-1", "embedding_version": "2026-01"}

        mock_result = MagicMock()
        mock_result.points = [hit_old, hit_new]
        wrapper._mock.query_points.return_value = mock_result

        results = wrapper.search_with_version_merge(
            "incident_embeddings", [0.1], limit=10
        )
        assert results[0]["payload"]["embedding_version"] == "2026-01"

    def test_single_version_returned_as_is(self, wrapper: QdrantWrapper):
        """Single-version doc returned without dedup logic."""
        hit = MagicMock()
        hit.id = "p1"
        hit.score = 0.90
        hit.payload = {"doc_id": "doc-1", "embedding_version": "2026-01"}

        mock_result = MagicMock()
        mock_result.points = [hit]
        wrapper._mock.query_points.return_value = mock_result

        results = wrapper.search_with_version_merge(
            "incident_embeddings", [0.1], limit=10
        )
        assert len(results) == 1
