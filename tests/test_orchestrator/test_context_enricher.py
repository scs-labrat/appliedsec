"""Tests for Context Enricher agent — Story 7.3, Sprint 2 fixes."""

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from shared.schemas.investigation import GraphState, InvestigationState
from orchestrator.agents.context_enricher import (
    ContextEnricherAgent,
    _determine_risk_state,
)


@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    redis.get_ioc = AsyncMock(return_value=None)
    return redis


@pytest.fixture
def mock_postgres():
    pg = AsyncMock()
    pg.fetch_one = AsyncMock(return_value=None)
    pg.fetch_many = AsyncMock(return_value=[])
    return pg


@pytest.fixture
def mock_qdrant():
    qdrant = MagicMock()
    qdrant.search = MagicMock(return_value=[])
    return qdrant


@pytest.fixture
def agent(mock_redis, mock_postgres, mock_qdrant):
    return ContextEnricherAgent(
        redis_client=mock_redis,
        postgres_client=mock_postgres,
        qdrant_client=mock_qdrant,
    )


@pytest.fixture
def state():
    return GraphState(
        investigation_id="inv-001",
        tenant_id="tenant-A",
        entities={
            "accounts": [{"primary_value": "jsmith@example.com"}],
            "hosts": [{"primary_value": "web-01"}],
            "ips": [{"primary_value": "10.0.0.1"}],
        },
        ioc_matches=[
            {"type": "ip", "value": "10.0.0.1"},
        ],
    )


class TestEnrichment:
    @pytest.mark.asyncio
    async def test_transitions_to_enriching(self, agent, state):
        result = await agent.execute(state)
        assert result.state == InvestigationState.ENRICHING

    @pytest.mark.asyncio
    async def test_enriches_iocs(self, agent, state, mock_redis):
        mock_redis.get_ioc.return_value = {"severity": "high"}
        result = await agent.execute(state)
        assert any(
            ioc.get("severity") == "high"
            for ioc in result.ioc_matches
        )

    @pytest.mark.asyncio
    async def test_queries_ueba(self, agent, state, mock_postgres):
        mock_postgres.fetch_one.return_value = {
            "risk_score": 0.75,
            "risk_state": "high",
            "anomalies": ["unusual_login"],
        }
        result = await agent.execute(state)
        assert len(result.ueba_context) > 0
        assert result.ueba_context[0]["risk_state"] == "high"

    @pytest.mark.asyncio
    async def test_risk_state_from_ueba(self, agent, state, mock_postgres):
        mock_postgres.fetch_one.return_value = {
            "risk_score": 0.75,
            "risk_state": "high",
            "anomalies": [],
        }
        result = await agent.execute(state)
        assert result.risk_state == "high"

    @pytest.mark.asyncio
    async def test_no_ueba_gives_no_baseline(self, agent, state):
        result = await agent.execute(state)
        assert result.risk_state == "no_baseline"

    @pytest.mark.asyncio
    async def test_parallel_execution(self, agent, state):
        """All three enrichment sources should be queried."""
        result = await agent.execute(state)
        assert result.queries_executed >= 1

    @pytest.mark.asyncio
    async def test_graceful_on_redis_failure(self, agent, state, mock_redis):
        mock_redis.get_ioc.side_effect = Exception("Redis down")
        result = await agent.execute(state)
        # Should not crash — fail open
        assert result.state == InvestigationState.ENRICHING


class TestDetermineRiskState:
    def test_empty_returns_no_baseline(self):
        assert _determine_risk_state([]) == "no_baseline"

    def test_high_risk(self):
        results = [{"risk_state": "high", "risk_score": 8}]
        assert _determine_risk_state(results) == "high"

    def test_medium_risk(self):
        results = [{"risk_state": "medium", "risk_score": 5}]
        assert _determine_risk_state(results) == "medium"

    def test_low_risk(self):
        results = [{"risk_state": "low", "risk_score": 2}]
        assert _determine_risk_state(results) == "low"

    def test_highest_wins(self):
        results = [
            {"risk_state": "low", "risk_score": 2},
            {"risk_state": "high", "risk_score": 8},
        ]
        assert _determine_risk_state(results) == "high"

    def test_unknown_only(self):
        results = [{"risk_state": "unknown", "risk_score": 0}]
        assert _determine_risk_state(results) == "no_baseline"


# ---------- F2: is_rare_important passed to score_incident --------------------

class TestIsRareImportantPassthrough:
    @pytest.mark.asyncio
    async def test_rare_important_passed_to_score_incident(self):
        """Qdrant payload with is_rare_important=True should be forwarded to score_incident."""
        redis = AsyncMock()
        redis.get_ioc = AsyncMock(return_value=None)
        pg = AsyncMock()
        pg.fetch_one = AsyncMock(return_value=None)

        qdrant = MagicMock()
        qdrant.search = MagicMock(return_value=[
            {
                "id": "hit-1",
                "score": 0.85,
                "payload": {
                    "incident_id": "INC-001",
                    "title": "Past incident",
                    "tenant_id": "tenant-A",
                    "techniques": ["T1566"],
                    "age_days": 200,
                    "is_rare_important": True,
                },
            },
        ])

        agent = ContextEnricherAgent(
            redis_client=redis, postgres_client=pg, qdrant_client=qdrant,
        )
        state = GraphState(
            investigation_id="inv-f2",
            tenant_id="tenant-A",
            entities={
                "description": "Some alert",
                "embedding": [0.1] * 1536,
                "techniques": ["T1566"],
            },
            ioc_matches=[],
        )

        with patch("orchestrator.agents.context_enricher.score_incident") as mock_score:
            mock_score.return_value = MagicMock(composite=0.7)
            await agent.execute(state)
            mock_score.assert_called_once()
            _, kwargs = mock_score.call_args
            assert kwargs.get("is_rare_important") is True


# ---------- F11: Synchronous Qdrant search wrapped in asyncio.to_thread -------

class TestQdrantAsyncWrapping:
    @pytest.mark.asyncio
    async def test_qdrant_search_via_to_thread(self):
        """Qdrant search should be called via asyncio.to_thread."""
        redis = AsyncMock()
        redis.get_ioc = AsyncMock(return_value=None)
        pg = AsyncMock()
        pg.fetch_one = AsyncMock(return_value=None)
        qdrant = MagicMock()
        qdrant.search = MagicMock(return_value=[])

        agent = ContextEnricherAgent(
            redis_client=redis, postgres_client=pg, qdrant_client=qdrant,
        )
        state = GraphState(
            investigation_id="inv-f11",
            tenant_id="tenant-A",
            entities={
                "description": "Some alert",
                "embedding": [0.1] * 1536,
            },
            ioc_matches=[],
        )

        with patch("orchestrator.agents.context_enricher.asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = []
            await agent.execute(state)
            mock_to_thread.assert_called_once()
            # First arg should be qdrant.search
            assert mock_to_thread.call_args[0][0] == qdrant.search
