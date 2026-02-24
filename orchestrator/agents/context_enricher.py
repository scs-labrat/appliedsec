"""Context Enricher agent — Stories 7.3, 15.1.

Parallel lookups: Redis IOC, Postgres UEBA, Qdrant similar incidents.

Story 15.1 adds hierarchical retrieval with tier-based context budgets
and structured case facts for cross-step token reuse.
"""

from __future__ import annotations

import asyncio
import logging
import math
from dataclasses import dataclass, field
from typing import Any, Optional

from shared.schemas.investigation import GraphState, InvestigationState
from shared.schemas.scoring import score_incident

logger = logging.getLogger(__name__)

# ---- Structured case facts (Story 15.1, Task 2) ----------------------------

# Approximate tokens-per-char ratio (4 chars ≈ 1 token)
_CHARS_PER_TOKEN = 4


@dataclass
class CaseFacts:
    """Compact structured representation of first-pass retrieval results.

    Stored in ``GraphState.case_facts`` so subsequent investigation steps
    do not re-pay the token cost of re-retrieving the same data.
    """

    entities: list[str] = field(default_factory=list)
    iocs: list[dict[str, Any]] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    similar_incidents: list[dict[str, Any]] = field(default_factory=list)
    token_estimate: int = 0


def extract_case_facts(state: GraphState) -> CaseFacts:
    """Extract structured case facts from the current investigation state.

    Pulls entities, IOCs, techniques, timeline, and similar incidents
    from the first-pass retrieval results and computes a token estimate.
    """
    # Flatten entity values
    entity_values: list[str] = []
    for etype in ("accounts", "hosts", "ips"):
        for entity in state.entities.get(etype, []):
            val = entity.get("primary_value", "") if isinstance(entity, dict) else str(entity)
            if val:
                entity_values.append(val)

    # IOC summaries (compact: type+value only)
    iocs = [
        {"type": ioc.get("type", ""), "value": ioc.get("value", "")}
        for ioc in state.ioc_matches
        if isinstance(ioc, dict) and ioc.get("value")
    ]

    # Techniques from entities (if present)
    techniques: list[str] = list(state.entities.get("techniques", []))

    # Timeline from UEBA anomalies
    timeline: list[dict[str, Any]] = []
    for ueba in state.ueba_context:
        if isinstance(ueba, dict):
            for anomaly in ueba.get("anomalies", []):
                if isinstance(anomaly, dict):
                    timeline.append(anomaly)

    # Similar incident summaries (compact)
    similar = [
        {"incident_id": s.get("incident_id", ""), "title": s.get("title", "")}
        for s in state.similar_incidents
        if isinstance(s, dict)
    ]

    facts = CaseFacts(
        entities=entity_values,
        iocs=iocs,
        techniques=techniques,
        timeline=timeline,
        similar_incidents=similar,
    )

    # Estimate token cost of these facts
    text_repr = str(facts)
    facts.token_estimate = len(text_repr) // _CHARS_PER_TOKEN
    return facts


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

    async def execute(
        self, state: GraphState, *, tier: str = "tier_0",
    ) -> GraphState:
        """Execute parallel enrichment with optional hierarchical retrieval.

        State transition: PARSING → ENRICHING.

        Story 15.1: For Tier 1+ tasks, a second-pass deep retrieval is
        performed after structuring first-pass results into case facts.
        Tier 0 uses a single broad pass only.

        Args:
            state: Current investigation graph state.
            tier: LLM routing tier (default ``"tier_0"`` for backward compat).
        """
        state.state = InvestigationState.ENRICHING

        # ---- First pass: broad, parallel enrichment ----
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

        # ---- Structure case facts from first-pass results ----
        facts = extract_case_facts(state)
        state.case_facts = {
            "entities": facts.entities,
            "iocs": facts.iocs,
            "techniques": facts.techniques,
            "timeline": facts.timeline,
            "similar_incidents": facts.similar_incidents,
            "token_estimate": facts.token_estimate,
        }

        # ---- Second pass: deep retrieval for Tier 1+ only ----
        if tier in ("tier_1", "tier_1_plus", "tier_2"):
            await self._deep_retrieval(state, facts)

        return state

    async def _deep_retrieval(
        self, state: GraphState, facts: CaseFacts,
    ) -> None:
        """Second-pass deep retrieval using structured case facts.

        Fetches detailed threat intel for identified techniques and
        additional UEBA context for high-risk entities.
        """
        tasks: list[Any] = []

        # Deep technique intel: query each identified technique
        for technique in facts.techniques:
            tasks.append(self._fetch_technique_intel(technique))

        # Deep entity context for entities with IOC matches
        matched_entities = {ioc.get("value", "") for ioc in facts.iocs if ioc.get("value")}
        for entity in facts.entities:
            if entity in matched_entities:
                tasks.append(self._fetch_deep_entity_context(entity))

        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        deep_context: list[dict[str, Any]] = []
        for result in results:
            if isinstance(result, dict):
                deep_context.append(result)
            elif isinstance(result, Exception):
                logger.warning("Deep retrieval task failed: %s", result)

        # Store deep context in case_facts
        state.case_facts["deep_context"] = deep_context

    async def _fetch_technique_intel(self, technique: str) -> dict[str, Any]:
        """Fetch detailed threat intelligence for a specific technique."""
        try:
            row = await self._postgres.fetch_one(
                "SELECT technique_id, name, description, severity, data_sources, mitigations FROM threat_intel WHERE technique_id = $1",
                technique,
            )
            if row:
                return {"type": "technique_intel", "technique": technique, **row}
        except Exception:
            logger.warning("Technique intel fetch failed for %s", technique, exc_info=True)
        return {"type": "technique_intel", "technique": technique, "detail": "unavailable"}

    async def _fetch_deep_entity_context(self, entity_value: str) -> dict[str, Any]:
        """Fetch additional UEBA context for a high-risk entity."""
        try:
            row = await self._postgres.fetch_one(
                "SELECT entity_id, entity_type, first_seen, last_seen, context, risk_score FROM user_entity_behavior_detail WHERE entity_value = $1",
                entity_value,
            )
            if row:
                return {"type": "entity_deep_context", "entity": entity_value, **row}
        except Exception:
            logger.warning("Deep entity context failed for %s", entity_value, exc_info=True)
        return {"type": "entity_deep_context", "entity": entity_value, "detail": "unavailable"}

    async def _enrich_iocs(self, state: GraphState) -> list[dict[str, Any]]:
        """Re-enrich IOCs from Redis (supplements IOC Extractor)."""
        enriched: list[dict[str, Any]] = []
        for ioc in state.ioc_matches:
            ioc_type = ioc.get("type", "")
            ioc_value = ioc.get("value", "")
            if not ioc_type or not ioc_value:
                enriched.append(ioc)
                continue
            cached = await self._redis.get_ioc(state.tenant_id, ioc_type, ioc_value)
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
            # F11: wrap synchronous Qdrant client in asyncio.to_thread
            raw_results = await asyncio.to_thread(
                self._qdrant.search,
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

            # F2: pass is_rare_important from Qdrant payload metadata
            is_rare_important = payload.get("is_rare_important", False)
            incident_score = score_incident(
                vector_similarity=hit.get("score", 0.0),
                age_days=payload.get("age_days", 30),
                same_tenant=payload.get("tenant_id") == state.tenant_id,
                technique_overlap=overlap,
                is_rare_important=is_rare_important,
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
