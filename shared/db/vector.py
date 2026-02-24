"""Qdrant vector database client wrapper with HNSW config, circuit-breaker-friendly errors,
and embedding versioning — Stories 8.1, 14.6."""

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

# Story 14.6: Embedding versioning constants
CURRENT_EMBEDDING_MODEL: str = "text-embedding-3-large"
CURRENT_EMBEDDING_DIMENSIONS: int = 1024
CURRENT_EMBEDDING_VERSION: str = "2026-01"

EMBEDDING_METADATA_KEYS: frozenset[str] = frozenset({
    "embedding_model_id",
    "embedding_dimensions",
    "embedding_version",
})


class RetriableQdrantError(Exception):
    """Transient Qdrant error — upstream circuit breakers should retry."""


class NonRetriableQdrantError(Exception):
    """Permanent Qdrant error — do not retry."""


# ---- Embedding metadata helpers (Story 14.6) ----

def enrich_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Add default embedding metadata to *payload* if missing.

    Does not overwrite existing metadata values.
    """
    result = dict(payload)
    if "embedding_model_id" not in result:
        result["embedding_model_id"] = CURRENT_EMBEDDING_MODEL
    if "embedding_dimensions" not in result:
        result["embedding_dimensions"] = CURRENT_EMBEDDING_DIMENSIONS
    if "embedding_version" not in result:
        result["embedding_version"] = CURRENT_EMBEDDING_VERSION
    return result


def validate_embedding_metadata(payload: dict[str, Any]) -> None:
    """Validate that all required embedding metadata keys are present.

    Raises ``ValueError`` if any key is missing.
    """
    for key in ("embedding_model_id", "embedding_dimensions", "embedding_version"):
        if key not in payload:
            raise ValueError(f"Missing required embedding metadata key: {key}")


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
        enforce_metadata: bool = False,
    ) -> None:
        """Upsert vectors into a collection.

        Each point dict must have keys: id, vector, payload.

        Story 14.6: When ``enforce_metadata=True``, raises ``ValueError``
        if any point is missing required embedding metadata.  Otherwise,
        auto-enriches payloads with default metadata.
        """
        try:
            structs = []
            for p in points:
                payload = p.get("payload", {})
                if enforce_metadata:
                    validate_embedding_metadata(payload)
                else:
                    payload = enrich_payload(payload)
                structs.append(
                    models.PointStruct(
                        id=p["id"],
                        vector=p["vector"],
                        payload=payload,
                    )
                )
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

    def search_with_version_merge(
        self,
        collection: str,
        query_vector: list[float],
        limit: int = 10,
        prefer_version: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Search with deduplication and version preference.

        Story 14.6: When multiple embedding versions exist for the same
        ``doc_id``, deduplicates by keeping the preferred version (or
        the newest version if no preference specified).
        """
        results = self._client.query_points(
            collection_name=collection,
            query=query_vector,
            limit=limit * 2,  # Over-fetch to account for dedup
        )

        raw = [
            {
                "id": hit.id,
                "score": hit.score,
                "payload": hit.payload or {},
            }
            for hit in results.points
        ]

        # Deduplicate by doc_id
        seen: dict[str, dict[str, Any]] = {}
        for hit in raw:
            doc_id = hit["payload"].get("doc_id", hit["id"])
            existing = seen.get(doc_id)
            if existing is None:
                seen[doc_id] = hit
            else:
                # Prefer specified version, then newest version, then higher score
                existing_ver = existing["payload"].get("embedding_version", "")
                hit_ver = hit["payload"].get("embedding_version", "")
                if prefer_version:
                    if hit_ver == prefer_version and existing_ver != prefer_version:
                        seen[doc_id] = hit
                else:
                    if hit_ver > existing_ver:
                        seen[doc_id] = hit

        deduped = list(seen.values())
        deduped.sort(key=lambda x: x["score"], reverse=True)
        return deduped[:limit]

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
