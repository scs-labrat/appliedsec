"""Qdrant vector database client wrapper with HNSW config and circuit-breaker-friendly errors."""

from __future__ import annotations

import logging
from typing import Any, Optional

from qdrant_client import QdrantClient, models
from qdrant_client.http.exceptions import UnexpectedResponse

logger = logging.getLogger(__name__)

# HNSW defaults tuned for security embedding workloads
_HNSW_M = 16
_HNSW_EF_CONSTRUCT = 200

# Standard ALUSKORT collections
COLLECTIONS = [
    "incident_embeddings",
    "technique_embeddings",
    "playbook_embeddings",
    "ti_report_embeddings",
]


class RetriableQdrantError(Exception):
    """Transient Qdrant error — upstream circuit breakers should retry."""


class NonRetriableQdrantError(Exception):
    """Permanent Qdrant error — do not retry."""


class QdrantWrapper:
    """Thin wrapper around qdrant-client with HNSW-tuned collection management,
    upsert/search operations, and circuit-breaker-friendly error classification.
    """

    def __init__(
        self,
        *,
        host: str = "localhost",
        port: int = 6333,
        grpc_port: int = 6334,
        api_key: Optional[str] = None,
        prefer_grpc: bool = True,
    ) -> None:
        self._client = QdrantClient(
            host=host,
            port=port,
            grpc_port=grpc_port,
            api_key=api_key,
            prefer_grpc=prefer_grpc,
        )
        logger.info("Qdrant client initialized (%s:%d)", host, port)

    @property
    def client(self) -> QdrantClient:
        return self._client

    def ensure_collection(self, name: str, vector_size: int) -> None:
        """Create a collection if it doesn't exist (idempotent)."""
        try:
            existing = {c.name for c in self._client.get_collections().collections}
            if name in existing:
                logger.debug("Collection '%s' already exists", name)
                return

            self._client.create_collection(
                collection_name=name,
                vectors_config=models.VectorParams(
                    size=vector_size,
                    distance=models.Distance.COSINE,
                ),
                hnsw_config=models.HnswConfigDiff(
                    m=_HNSW_M,
                    ef_construct=_HNSW_EF_CONSTRUCT,
                ),
            )
            logger.info("Created collection '%s' (dim=%d)", name, vector_size)
        except (ConnectionError, TimeoutError, OSError) as exc:
            raise RetriableQdrantError(str(exc)) from exc
        except UnexpectedResponse as exc:
            if exc.status_code and exc.status_code >= 500:
                raise RetriableQdrantError(str(exc)) from exc
            raise NonRetriableQdrantError(str(exc)) from exc

    def ensure_all_collections(self, vector_size: int = 1536) -> None:
        """Create all 4 standard ALUSKORT collections."""
        for name in COLLECTIONS:
            self.ensure_collection(name, vector_size)

    def upsert_vectors(
        self,
        collection: str,
        points: list[dict[str, Any]],
        batch_size: int = 100,
    ) -> None:
        """Upsert vectors into a collection.

        Each point dict must have keys: id, vector, payload.
        """
        try:
            structs = [
                models.PointStruct(
                    id=p["id"],
                    vector=p["vector"],
                    payload=p.get("payload", {}),
                )
                for p in points
            ]
            for i in range(0, len(structs), batch_size):
                batch = structs[i : i + batch_size]
                self._client.upsert(collection_name=collection, points=batch)
        except (ConnectionError, TimeoutError, OSError) as exc:
            raise RetriableQdrantError(str(exc)) from exc
        except UnexpectedResponse as exc:
            if exc.status_code and exc.status_code >= 500:
                raise RetriableQdrantError(str(exc)) from exc
            raise NonRetriableQdrantError(str(exc)) from exc

    def search(
        self,
        collection: str,
        query_vector: list[float],
        limit: int = 10,
        score_threshold: Optional[float] = None,
        search_filter: Optional[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        """Semantic search returning top-k results as dicts."""
        try:
            qdrant_filter = None
            if search_filter:
                must_conditions = [
                    models.FieldCondition(
                        key=k,
                        match=models.MatchValue(value=v),
                    )
                    for k, v in search_filter.items()
                ]
                qdrant_filter = models.Filter(must=must_conditions)

            results = self._client.query_points(
                collection_name=collection,
                query=query_vector,
                limit=limit,
                score_threshold=score_threshold,
                query_filter=qdrant_filter,
            )
            return [
                {
                    "id": hit.id,
                    "score": hit.score,
                    "payload": hit.payload or {},
                }
                for hit in results.points
            ]
        except (ConnectionError, TimeoutError, OSError) as exc:
            raise RetriableQdrantError(str(exc)) from exc
        except UnexpectedResponse as exc:
            if exc.status_code and exc.status_code >= 500:
                raise RetriableQdrantError(str(exc)) from exc
            raise NonRetriableQdrantError(str(exc)) from exc

    def search_by_id(
        self, collection: str, point_id: str | int
    ) -> Optional[dict[str, Any]]:
        """Retrieve a single point by ID."""
        try:
            results = self._client.retrieve(
                collection_name=collection,
                ids=[point_id],
                with_payload=True,
                with_vectors=True,
            )
            if not results:
                return None
            p = results[0]
            return {"id": p.id, "vector": p.vector, "payload": p.payload or {}}
        except (ConnectionError, TimeoutError, OSError) as exc:
            raise RetriableQdrantError(str(exc)) from exc

    def health_check(self) -> bool:
        """Check Qdrant connectivity."""
        try:
            self._client.get_collections()
            return True
        except Exception:
            logger.warning("Qdrant health check failed", exc_info=True)
            return False

    def delete_collection(self, name: str) -> None:
        """Delete a collection (for tests / cleanup)."""
        self._client.delete_collection(collection_name=name)

    def close(self) -> None:
        """Close the Qdrant client."""
        self._client.close()
        logger.info("Qdrant client closed")
