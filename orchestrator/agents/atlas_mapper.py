"""ATLAS Mapper agent — Story 7.7.

Maps alert techniques to ATLAS adversarial ML taxonomy via
Postgres lookup and Qdrant semantic search.
"""

from __future__ import annotations

import logging
from typing import Any

from shared.schemas.investigation import GraphState

logger = logging.getLogger(__name__)


class ATLASMapperAgent:
    """Correlates ATT&CK techniques to ATLAS adversarial ML techniques."""

    def __init__(
        self,
        postgres_client: Any,
        qdrant_client: Any,
    ) -> None:
        self._postgres = postgres_client
        self._qdrant = qdrant_client

    async def execute(self, state: GraphState) -> GraphState:
        """Map techniques to ATLAS IDs.

        Queries Postgres taxonomy_ids and Qdrant semantic search,
        then merges and deduplicates results.
        """
        techniques = state.entities.get("techniques", [])

        # Two parallel paths
        taxonomy_results = await self._query_taxonomy(techniques, state)
        semantic_results = await self._semantic_search(state)

        # Merge and deduplicate
        merged = self._merge_results(taxonomy_results, semantic_results)
        state.atlas_techniques = merged
        return state

    async def _query_taxonomy(
        self,
        attack_techniques: list[str],
        state: GraphState,
    ) -> list[dict[str, Any]]:
        """Cross-reference ATT&CK IDs with ATLAS taxonomy."""
        results: list[dict[str, Any]] = []
        for technique_id in attack_techniques:
            rows = await self._postgres.fetch_many(
                """
                SELECT technique_id, framework, name
                FROM taxonomy_ids
                WHERE related_attack_id = $1
                  AND framework = 'ATLAS'
                  AND deprecated = false
                """,
                technique_id,
            )
            state.queries_executed += 1
            for row in rows:
                results.append({
                    "atlas_id": row["technique_id"],
                    "atlas_name": row.get("name", ""),
                    "attack_id": technique_id,
                    "confidence": 1.0,
                    "source": "taxonomy",
                })
        return results

    async def _semantic_search(
        self, state: GraphState
    ) -> list[dict[str, Any]]:
        """Search Qdrant for ATLAS techniques by semantic similarity."""
        embedding = state.entities.get("embedding", [])
        if not embedding:
            return []

        try:
            hits = self._qdrant.search(
                collection="technique_embeddings",
                query_vector=embedding,
                limit=5,
                search_filter={"framework": "ATLAS"},
            )
            state.queries_executed += 1
        except Exception:
            logger.warning("Qdrant ATLAS search failed", exc_info=True)
            return []

        results: list[dict[str, Any]] = []
        for hit in hits:
            payload = hit.get("payload", {})
            results.append({
                "atlas_id": payload.get("technique_id", ""),
                "atlas_name": payload.get("name", ""),
                "attack_id": payload.get("related_attack_id", ""),
                "confidence": hit.get("score", 0.0),
                "source": "semantic_search",
            })
        return results

    def _merge_results(
        self,
        taxonomy: list[dict[str, Any]],
        semantic: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Merge and deduplicate, keeping highest confidence per atlas_id."""
        seen: dict[str, dict[str, Any]] = {}
        for item in taxonomy + semantic:
            atlas_id = item.get("atlas_id", "")
            if not atlas_id:
                continue
            if atlas_id not in seen or item.get("confidence", 0) > seen[atlas_id].get("confidence", 0):
                seen[atlas_id] = item
        return list(seen.values())
