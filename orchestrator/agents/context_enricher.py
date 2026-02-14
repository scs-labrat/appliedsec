"""Context Enricher agent — Story 7.3.

Parallel lookups: Redis IOC, Postgres UEBA, Qdrant similar incidents.
"""

from __future__ import annotations

import asyncio
import logging
import math
from typing import Any, Optional

from shared.schemas.investigation import GraphState, InvestigationState
from shared.schemas.scoring import score_incident

logger = logging.getLogger(__name__)


class ContextEnricherAgent:
    """Parallel context enrichment from Redis, Postgres, and Qdrant."""

    def __init__(
        self,
        redis_client: Any,
        postgres_client: Any,
        qdrant_client: Any,
    ) -> None:
        self._redis = redis_client
        self._postgres = postgres_client
        self._qdrant = qdrant_client

    async def execute(self, state: GraphState) -> GraphState:
        """Execute parallel enrichment.

        State transition: PARSING → ENRICHING.
        """
        state.state = InvestigationState.ENRICHING

        # Parallel enrichment
        ioc_task = self._enrich_iocs(state)
        ueba_task = self._query_ueba(state)
        similar_task = self._search_similar_incidents(state)

        ioc_results, ueba_results, similar_results = await asyncio.gather(
            ioc_task, ueba_task, similar_task,
            return_exceptions=True,
        )

        # Merge results (graceful on failures)
        if isinstance(ioc_results, list):
            state.ioc_matches = ioc_results
        elif isinstance(ioc_results, Exception):
            logger.warning("IOC enrichment failed: %s", ioc_results)

        if isinstance(ueba_results, list):
            state.ueba_context = ueba_results
            state.risk_state = _determine_risk_state(ueba_results)
        elif isinstance(ueba_results, Exception):
            logger.warning("UEBA query failed: %s", ueba_results)
            state.risk_state = "unknown"

        if isinstance(similar_results, list):
            state.similar_incidents = similar_results
        elif isinstance(similar_results, Exception):
            logger.warning("Similar incident search failed: %s", similar_results)

        return state

    async def _enrich_iocs(self, state: GraphState) -> list[dict[str, Any]]:
        """Re-enrich IOCs from Redis (supplements IOC Extractor)."""
        enriched: list[dict[str, Any]] = []
        for ioc in state.ioc_matches:
            ioc_type = ioc.get("type", "")
            ioc_value = ioc.get("value", "")
            if not ioc_type or not ioc_value:
                enriched.append(ioc)
                continue
            cached = await self._redis.get_ioc(ioc_type, ioc_value)
            state.queries_executed += 1
            if cached:
                enriched.append({**ioc, **cached})
            else:
                enriched.append(ioc)
        return enriched

    async def _query_ueba(self, state: GraphState) -> list[dict[str, Any]]:
        """Query Postgres for UEBA context on alert entities."""
        entities = state.entities
        results: list[dict[str, Any]] = []

        # Extract entity values to query
        entity_values: list[tuple[str, str]] = []
        for etype in ("accounts", "hosts", "ips"):
            for entity in entities.get(etype, []):
                value = entity.get("primary_value", "") if isinstance(entity, dict) else ""
                if value:
                    entity_values.append((etype.rstrip("s"), value))

        for etype, value in entity_values:
            row = await self._postgres.fetch_one(
                "SELECT * FROM user_entity_behavior WHERE entity_value = $1",
                value,
            )
            state.queries_executed += 1
            if row:
                results.append({
                    "entity_type": etype,
                    "entity_value": value,
                    "risk_score": row.get("risk_score", 0),
                    "risk_state": row.get("risk_state", "unknown"),
                    "anomalies": row.get("anomalies", []),
                })

        return results

    async def _search_similar_incidents(
        self, state: GraphState
    ) -> list[dict[str, Any]]:
        """Search Qdrant for similar past incidents."""
        # Build a simple query vector placeholder (in production, use embeddings)
        # For now, use the alert description text as context
        description = state.entities.get("description", "")
        if not description:
            return []

        try:
            raw_results = self._qdrant.search(
                collection="incident_embeddings",
                query_vector=state.entities.get("embedding", [0.0] * 1536),
                limit=5,
            )
            state.queries_executed += 1
        except Exception:
            logger.warning("Qdrant search failed", exc_info=True)
            return []

        # Score each result
        scored: list[dict[str, Any]] = []
        for hit in raw_results:
            payload = hit.get("payload", {})
            techniques = set(state.entities.get("techniques", []))
            hit_techniques = set(payload.get("techniques", []))
            overlap = (
                len(techniques & hit_techniques) / len(techniques | hit_techniques)
                if (techniques | hit_techniques)
                else 0.0
            )

            incident_score = score_incident(
                vector_similarity=hit.get("score", 0.0),
                age_days=payload.get("age_days", 30),
                same_tenant=payload.get("tenant_id") == state.tenant_id,
                technique_overlap=overlap,
            )

            scored.append({
                "incident_id": payload.get("incident_id", str(hit.get("id", ""))),
                "title": payload.get("title", ""),
                "vector_similarity": hit.get("score", 0.0),
                "composite_score": incident_score.composite,
                "techniques": list(hit_techniques),
            })

        # Sort by composite score
        scored.sort(key=lambda x: x["composite_score"], reverse=True)
        return scored[:5]


def _determine_risk_state(ueba_results: list[dict[str, Any]]) -> str:
    """Determine overall risk state from UEBA results.

    Key rule: absent data is 'no_baseline', not 'low'.
    """
    if not ueba_results:
        return "no_baseline"

    risk_scores = [r.get("risk_score", 0) for r in ueba_results]
    max_score = max(risk_scores) if risk_scores else 0

    # Check if any entity has an explicit risk_state
    states = [r.get("risk_state", "unknown") for r in ueba_results]
    if "high" in states:
        return "high"
    if "medium" in states:
        return "medium"
    if "low" in states:
        return "low"
    return "no_baseline"
