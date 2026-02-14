"""Tests for Qdrant collection definitions — Story 2.4."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from infra.scripts.init_qdrant import (
    COLLECTIONS,
    HNSW_EF_CONSTRUCT,
    HNSW_M,
    VECTOR_SIZE,
    get_collection_names,
    init_collections,
)


class TestCollectionDefinitions:
    def test_four_collections_defined(self):
        assert len(COLLECTIONS) == 4

    def test_collection_names(self):
        names = get_collection_names()
        assert "aluskort-mitre" in names
        assert "aluskort-threat-intel" in names
        assert "aluskort-playbooks" in names
        assert "aluskort-incident-memory" in names

    def test_vector_size_is_1024(self):
        assert VECTOR_SIZE == 1024

    def test_hnsw_config(self):
        assert HNSW_M == 16
        assert HNSW_EF_CONSTRUCT == 200


class TestInitCollections:
    def test_creates_missing_collections(self):
        mock_client = MagicMock()
        coll_resp = MagicMock()
        coll_resp.collections = []  # No existing collections
        mock_client.get_collections.return_value = coll_resp
        mock_client.create_collection.return_value = True

        with patch("infra.scripts.init_qdrant.QdrantClient", return_value=mock_client):
            results = init_collections()

        assert all(v == "created" for v in results.values())
        assert mock_client.create_collection.call_count == 4

    def test_idempotent_when_all_exist(self):
        mock_client = MagicMock()
        existing = [MagicMock(name=n) for n in get_collection_names()]
        for e, name in zip(existing, get_collection_names()):
            e.name = name
        coll_resp = MagicMock()
        coll_resp.collections = existing
        mock_client.get_collections.return_value = coll_resp

        with patch("infra.scripts.init_qdrant.QdrantClient", return_value=mock_client):
            results = init_collections()

        assert all(v == "already_exists" for v in results.values())
        mock_client.create_collection.assert_not_called()

    def test_hnsw_params_passed(self):
        mock_client = MagicMock()
        coll_resp = MagicMock()
        coll_resp.collections = []
        mock_client.get_collections.return_value = coll_resp

        with patch("infra.scripts.init_qdrant.QdrantClient", return_value=mock_client):
            init_collections()

        call_kwargs = mock_client.create_collection.call_args_list[0][1]
        assert call_kwargs["hnsw_config"].m == 16
        assert call_kwargs["hnsw_config"].ef_construct == 200
        assert call_kwargs["vectors_config"].size == 1024
        assert call_kwargs["vectors_config"].distance.name == "COSINE"
