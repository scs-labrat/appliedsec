"""Investigation Graph — Story 7.8.

State machine executor: consumes alerts, runs agent nodes in
topological order, handles parallelism, branching, and persistence.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Optional

from shared.schemas.investigation import (
    AgentRole,
    GraphState,
    InvestigationState,
)
from orchestrator.persistence import InvestigationRepository
from orchestrator.fp_shortcircuit import FPShortCircuit

logger = logging.getLogger(__name__)


class InvestigationGraph:
    """Executes the full investigation lifecycle as a state machine.

    Graph topology::

        RECEIVED → IOC_EXTRACTOR → FP_CHECK
            ├→ CLOSED (if FP match)
            └→ ENRICHING (parallel: CONTEXT_ENRICHER, CTEM_CORRELATOR, ATLAS_MAPPER)
                → REASONING_AGENT
                    ├→ RESPONDING → CLOSED
                    └→ AWAITING_HUMAN
                        ├→ RESPONDING (approved) → CLOSED
                        └→ CLOSED (rejected / timeout)
    """

    def __init__(
        self,
        *,
        repository: InvestigationRepository,
        ioc_extractor: Any,
        context_enricher: Any,
        ctem_correlator: Any,
        atlas_mapper: Any,
        reasoning_agent: Any,
        response_agent: Any,
        fp_shortcircuit: FPShortCircuit | None = None,
    ) -> None:
        self._repo = repository
        self._ioc = ioc_extractor
        self._enricher = context_enricher
        self._ctem = ctem_correlator
        self._atlas = atlas_mapper
        self._reasoning = reasoning_agent
        self._response = response_agent
        self._fp = fp_shortcircuit

    async def run(
        self,
        alert_id: str,
        tenant_id: str,
        entities: dict[str, Any],
        alert_title: str = "",
        severity: str = "medium",
    ) -> GraphState:
        """Execute the full investigation pipeline.

        Returns the final GraphState.
        """
        investigation_id = str(uuid.uuid4())
        state = GraphState(
            investigation_id=investigation_id,
            alert_id=alert_id,
            tenant_id=tenant_id,
            entities=entities,
            severity=severity,
        )

        try:
            state = await self._execute_pipeline(state, alert_title)
        except Exception as exc:
            logger.error(
                "Investigation %s failed: %s", investigation_id, exc,
                exc_info=True,
            )
            state.state = InvestigationState.FAILED
            state.decision_chain.append({
                "agent": "graph",
                "action": "unrecoverable_error",
                "error": str(exc),
            })

        # Final persist
        await self._repo.save(state)
        return state

    async def _execute_pipeline(
        self, state: GraphState, alert_title: str
    ) -> GraphState:
        """Execute all pipeline stages."""
        # Stage 1: IOC Extraction (RECEIVED → PARSING)
        state = await self._repo.transition(
            state, InvestigationState.PARSING,
            agent=AgentRole.IOC_EXTRACTOR.value,
            action="start_ioc_extraction",
        )
        state = await self._ioc.execute(state)

        # Stage 1.5: FP Short-Circuit
        if self._fp is not None:
            fp_result = await self._fp.check(state, alert_title)
            if fp_result.matched:
                state = self._fp.apply_shortcircuit(state, fp_result)
                return state

        # Stage 2: Parallel Enrichment (PARSING → ENRICHING)
        state = await self._repo.transition(
            state, InvestigationState.ENRICHING,
            agent="graph",
            action="start_enrichment",
        )

        enricher_task = self._enricher.execute(state)
        ctem_task = self._ctem.execute(state)
        atlas_task = self._atlas.execute(state)

        results = await asyncio.gather(
            enricher_task, ctem_task, atlas_task,
            return_exceptions=True,
        )

        # Merge parallel results
        state = self._merge_parallel_results(state, results)

        # Stage 3: Reasoning (ENRICHING → REASONING)
        state = await self._repo.transition(
            state, InvestigationState.REASONING,
            agent=AgentRole.REASONING_AGENT.value,
            action="start_reasoning",
        )
        state = await self._reasoning.execute(state)

        # Stage 4: Branch — RESPONDING or AWAITING_HUMAN
        if state.state == InvestigationState.AWAITING_HUMAN:
            await self._repo.save(state)
            # In production: pause here and wait for approval signal.
            # For now, the graph returns and callers handle the gate.
            return state

        # Stage 5: Response (RESPONDING → CLOSED)
        state = await self._repo.transition(
            state, InvestigationState.RESPONDING,
            agent=AgentRole.RESPONSE_AGENT.value,
            action="start_response",
        )
        state = await self._response.execute(state)

        return state

    def _merge_parallel_results(
        self, state: GraphState, results: list[Any]
    ) -> GraphState:
        """Merge results from parallel enrichment agents."""
        enricher_result, ctem_result, atlas_result = results

        if isinstance(enricher_result, GraphState):
            state.ioc_matches = enricher_result.ioc_matches
            state.ueba_context = enricher_result.ueba_context
            state.similar_incidents = enricher_result.similar_incidents
            state.risk_state = enricher_result.risk_state
            state.queries_executed += enricher_result.queries_executed
        elif isinstance(enricher_result, Exception):
            logger.warning("Context enricher failed: %s", enricher_result)

        if isinstance(ctem_result, GraphState):
            state.ctem_exposures = ctem_result.ctem_exposures
            state.queries_executed += ctem_result.queries_executed
        elif isinstance(ctem_result, Exception):
            logger.warning("CTEM correlator failed: %s", ctem_result)

        if isinstance(atlas_result, GraphState):
            state.atlas_techniques = atlas_result.atlas_techniques
            state.queries_executed += atlas_result.queries_executed
        elif isinstance(atlas_result, Exception):
            logger.warning("ATLAS mapper failed: %s", atlas_result)

        return state

    async def resume_from_approval(
        self,
        investigation_id: str,
        approved: bool,
    ) -> GraphState | None:
        """Resume an investigation after human approval decision."""
        state = await self._repo.load(investigation_id)
        if state is None:
            logger.error("Investigation %s not found", investigation_id)
            return None

        if state.state != InvestigationState.AWAITING_HUMAN:
            logger.warning(
                "Investigation %s not awaiting approval (state=%s)",
                investigation_id, state.state.value,
            )
            return state

        if approved:
            state = await self._repo.transition(
                state, InvestigationState.RESPONDING,
                agent="human",
                action="approval_granted",
            )
            state = await self._response.execute(state)
        else:
            state = await self._repo.transition(
                state, InvestigationState.CLOSED,
                agent="human",
                action="approval_rejected",
            )

        await self._repo.save(state)
        return state
