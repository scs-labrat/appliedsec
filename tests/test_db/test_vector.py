"""Tests for QdrantWrapper — all mocked, no live Qdrant required."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from shared.db.vector import (
    NonRetriableQdrantError,
    QdrantWrapper,
    RetriableQdrantError,
)


def _mock_qdrant_client() -> MagicMock:
    mock = MagicMock()
    # get_collections returns a response with .collections list
    coll_resp = MagicMock()
    coll_resp.collections = []
    mock.get_collections.return_value = coll_resp
    mock.create_collection.return_value = True
    mock.upsert.return_value = None
    mock.close.return_value = None
    return mock


@pytest.fixture
def wrapper() -> QdrantWrapper:
    with patch("shared.db.vector.QdrantClient") as MockClient:
        mock = _mock_qdrant_client()
        MockClient.return_value = mock
        w = QdrantWrapper(host="localhost", port=6333)
        w._mock = mock  # stash for assertions
        return w


class TestInit:
    """AC-1.4.1: Client initialization."""

    def test_client_created(self):
        with patch("shared.db.vector.QdrantClient") as MockClient:
            MockClient.return_value = MagicMock()
            w = QdrantWrapper(host="qdrant.local", port=6333, api_key="secret")
            MockClient.assert_called_once_with(
                host="qdrant.local",
                port=6333,
                grpc_port=6334,
                api_key="secret",
                prefer_grpc=True,
            )


class TestEnsureCollection:
    """AC-1.4.2, AC-1.4.3: Collection creation with HNSW config."""

    def test_creates_collection_with_hnsw(self, wrapper: QdrantWrapper):
        mock = wrapper._mock
        wrapper.ensure_collection("incident_embeddings", vector_size=1536)
        mock.create_collection.assert_called_once()
        call_kwargs = mock.create_collection.call_args[1]
        assert call_kwargs["collection_name"] == "incident_embeddings"

        # Check vector params
        vp = call_kwargs["vectors_config"]
        assert vp.size == 1536
        assert vp.distance.name == "COSINE"

        # Check HNSW params
        hnsw = call_kwargs["hnsw_config"]
        assert hnsw.m == 16
        assert hnsw.ef_construct == 200

    def test_idempotent_if_exists(self, wrapper: QdrantWrapper):
        mock = wrapper._mock
        existing = MagicMock()
        existing.name = "incident_embeddings"
        coll_resp = MagicMock()
        coll_resp.collections = [existing]
        mock.get_collections.return_value = coll_resp

        wrapper.ensure_collection("incident_embeddings", vector_size=1536)
        mock.create_collection.assert_not_called()


class TestUpsertVectors:
    """AC-1.4.4: Vector upsert."""

    def test_upsert_converts_dicts(self, wrapper: QdrantWrapper):
        mock = wrapper._mock
        points = [
            {"id": "p1", "vector": [0.1, 0.2, 0.3], "payload": {"tenant_id": "t1"}},
            {"id": "p2", "vector": [0.4, 0.5, 0.6], "payload": {"tenant_id": "t2"}},
        ]
        wrapper.upsert_vectors("incident_embeddings", points)
        mock.upsert.assert_called_once()
        call_kwargs = mock.upsert.call_args[1]
        assert call_kwargs["collection_name"] == "incident_embeddings"
        assert len(call_kwargs["points"]) == 2
        assert call_kwargs["points"][0].id == "p1"
        assert call_kwargs["points"][0].vector == [0.1, 0.2, 0.3]
        assert call_kwargs["points"][0].payload == {"tenant_id": "t1"}


class TestSearch:
    """AC-1.4.5, AC-1.4.6: Semantic search."""

    def test_search_returns_dicts(self, wrapper: QdrantWrapper):
        mock = wrapper._mock
        hit1 = MagicMock()
        hit1.id = "p1"
        hit1.score = 0.95
        hit1.payload = {"tenant_id": "t1"}
        hit2 = MagicMock()
        hit2.id = "p2"
        hit2.score = 0.80
        hit2.payload = {"tenant_id": "t2"}

        query_resp = MagicMock()
        query_resp.points = [hit1, hit2]
        mock.query_points.return_value = query_resp

        results = wrapper.search(
            "incident_embeddings",
            query_vector=[0.1, 0.2, 0.3],
            limit=10,
        )
        assert len(results) == 2
        assert results[0] == {"id": "p1", "score": 0.95, "payload": {"tenant_id": "t1"}}
        assert results[1] == {"id": "p2", "score": 0.80, "payload": {"tenant_id": "t2"}}

    def test_search_with_filter(self, wrapper: QdrantWrapper):
        mock = wrapper._mock
        query_resp = MagicMock()
        query_resp.points = []
        mock.query_points.return_value = query_resp

        wrapper.search(
            "incident_embeddings",
            query_vector=[0.1],
            search_filter={"tenant_id": "t1"},
        )
        call_kwargs = mock.query_points.call_args[1]
        assert call_kwargs["query_filter"] is not None
        assert len(call_kwargs["query_filter"].must) == 1
        assert call_kwargs["query_filter"].must[0].key == "tenant_id"


class TestErrorHandling:
    """AC-1.4.7, AC-1.4.8: Error classification."""

    def test_connection_error_is_retriable(self, wrapper: QdrantWrapper):
        mock = wrapper._mock
        mock.get_collections.side_effect = ConnectionError("refused")
        with pytest.raises(RetriableQdrantError):
            wrapper.ensure_collection("test", 1536)

    def test_timeout_error_is_retriable(self, wrapper: QdrantWrapper):
        mock = wrapper._mock
        mock.get_collections.side_effect = TimeoutError("timed out")
        with pytest.raises(RetriableQdrantError):
            wrapper.ensure_collection("test", 1536)

    def test_value_error_propagates(self, wrapper: QdrantWrapper):
        mock = wrapper._mock
        mock.query_points.side_effect = ValueError("bad vector")
        with pytest.raises(ValueError, match="bad vector"):
            wrapper.search("test", [0.1], limit=5)


class TestHealthCheck:
    def test_health_check_true(self, wrapper: QdrantWrapper):
        assert wrapper.health_check() is True

    def test_health_check_false_on_error(self, wrapper: QdrantWrapper):
        mock = wrapper._mock
        mock.get_collections.side_effect = ConnectionError("down")
        assert wrapper.health_check() is False


class TestClose:
    def test_close(self, wrapper: QdrantWrapper):
        mock = wrapper._mock
        wrapper.close()
        mock.close.assert_called_once()
