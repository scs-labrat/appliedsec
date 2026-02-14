"""Tests for CTEM Correlator agent — Story 7.6."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

from shared.schemas.investigation import GraphState
from orchestrator.agents.ctem_correlator import (
    CTEMCorrelatorAgent,
    SLA_DEADLINES,
    STALENESS_HOURS,
)


@pytest.fixture
def mock_postgres():
    pg = AsyncMock()
    pg.fetch_many = AsyncMock(return_value=[])
    return pg


@pytest.fixture
def agent(mock_postgres):
    return CTEMCorrelatorAgent(postgres_client=mock_postgres)


@pytest.fixture
def state():
    return GraphState(
        investigation_id="inv-001",
        entities={
            "hosts": [{"primary_value": "web-01"}],
            "ips": [{"primary_value": "10.0.0.1"}],
        },
    )


class TestCTEMCorrelation:
    @pytest.mark.asyncio
    async def test_queries_by_asset_id(self, agent, state, mock_postgres):
        await agent.execute(state)
        assert mock_postgres.fetch_many.call_count == 2  # web-01 + 10.0.0.1

    @pytest.mark.asyncio
    async def test_returns_exposures(self, agent, state, mock_postgres):
        fresh = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        mock_postgres.fetch_many.return_value = [
            {
                "exposure_key": "exp-001",
                "asset_id": "web-01",
                "asset_zone": "prod",
                "severity": "HIGH",
                "ctem_score": 8.5,
                "source_tool": "wiz",
                "status": "Open",
                "updated_at": fresh,
            },
        ]
        result = await agent.execute(state)
        assert len(result.ctem_exposures) >= 1
        assert result.ctem_exposures[0]["exposure_key"] == "exp-001"

    @pytest.mark.asyncio
    async def test_staleness_detection(self, agent, state, mock_postgres):
        stale = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        mock_postgres.fetch_many.return_value = [
            {
                "exposure_key": "exp-002",
                "asset_id": "web-01",
                "severity": "MEDIUM",
                "ctem_score": 5.0,
                "source_tool": "snyk",
                "status": "Open",
                "updated_at": stale,
            },
        ]
        result = await agent.execute(state)
        assert result.ctem_exposures[0]["stale"] is True

    @pytest.mark.asyncio
    async def test_fresh_data_not_stale(self, agent, state, mock_postgres):
        fresh = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        mock_postgres.fetch_many.return_value = [
            {
                "exposure_key": "exp-003",
                "asset_id": "web-01",
                "severity": "CRITICAL",
                "ctem_score": 9.0,
                "source_tool": "wiz",
                "status": "Open",
                "updated_at": fresh,
            },
        ]
        result = await agent.execute(state)
        assert result.ctem_exposures[0]["stale"] is False

    @pytest.mark.asyncio
    async def test_no_entities_returns_empty(self, agent, mock_postgres):
        state = GraphState(investigation_id="inv-002", entities={})
        result = await agent.execute(state)
        assert result.ctem_exposures == []
        mock_postgres.fetch_many.assert_not_called()

    @pytest.mark.asyncio
    async def test_sla_deadline_added(self, agent, state, mock_postgres):
        fresh = datetime.now(timezone.utc).isoformat()
        mock_postgres.fetch_many.return_value = [
            {
                "exposure_key": "exp-004",
                "asset_id": "web-01",
                "severity": "CRITICAL",
                "ctem_score": 9.5,
                "source_tool": "art",
                "status": "Open",
                "updated_at": fresh,
            },
        ]
        result = await agent.execute(state)
        assert result.ctem_exposures[0]["sla_deadline_hours"] == 24

    @pytest.mark.asyncio
    async def test_tracks_query_count(self, agent, state):
        result = await agent.execute(state)
        assert result.queries_executed == 2


class TestSLADeadlines:
    def test_critical_24h(self):
        assert SLA_DEADLINES["CRITICAL"] == 24

    def test_high_72h(self):
        assert SLA_DEADLINES["HIGH"] == 72

    def test_medium_14d(self):
        assert SLA_DEADLINES["MEDIUM"] == 336

    def test_low_30d(self):
        assert SLA_DEADLINES["LOW"] == 720


class TestStalenessConstant:
    def test_staleness_threshold(self):
        assert STALENESS_HOURS == 24
