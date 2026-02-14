"""Tests for ATLAS Mapper agent — Story 7.7."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from shared.schemas.investigation import GraphState
from orchestrator.agents.atlas_mapper import ATLASMapperAgent


@pytest.fixture
def mock_postgres():
    pg = AsyncMock()
    pg.fetch_many = AsyncMock(return_value=[])
    return pg


@pytest.fixture
def mock_qdrant():
    qdrant = MagicMock()
    qdrant.search = MagicMock(return_value=[])
    return qdrant


@pytest.fixture
def agent(mock_postgres, mock_qdrant):
    return ATLASMapperAgent(
        postgres_client=mock_postgres,
        qdrant_client=mock_qdrant,
    )


@pytest.fixture
def state():
    return GraphState(
        investigation_id="inv-001",
        entities={
            "techniques": ["T1078", "T1566"],
            "embedding": [0.1] * 1536,
        },
    )


class TestTaxonomyLookup:
    @pytest.mark.asyncio
    async def test_queries_per_technique(self, agent, state, mock_postgres):
        await agent.execute(state)
        assert mock_postgres.fetch_many.call_count == 2  # T1078, T1566

    @pytest.mark.asyncio
    async def test_maps_taxonomy_results(self, agent, state, mock_postgres):
        mock_postgres.fetch_many.side_effect = [
            [{"technique_id": "AML.T0020", "framework": "ATLAS", "name": "Model Theft"}],
            [],
        ]
        result = await agent.execute(state)
        assert len(result.atlas_techniques) >= 1
        assert result.atlas_techniques[0]["atlas_id"] == "AML.T0020"
        assert result.atlas_techniques[0]["source"] == "taxonomy"
        assert result.atlas_techniques[0]["confidence"] == 1.0


class TestSemanticSearch:
    @pytest.mark.asyncio
    async def test_searches_qdrant(self, agent, state, mock_qdrant):
        mock_qdrant.search.return_value = [
            {
                "id": 1,
                "score": 0.87,
                "payload": {
                    "technique_id": "AML.T0042",
                    "name": "Adversarial Example",
                    "related_attack_id": "T1566",
                },
            },
        ]
        result = await agent.execute(state)
        atlas = [t for t in result.atlas_techniques if t["atlas_id"] == "AML.T0042"]
        assert len(atlas) == 1
        assert atlas[0]["source"] == "semantic_search"
        assert atlas[0]["confidence"] == pytest.approx(0.87)

    @pytest.mark.asyncio
    async def test_no_embedding_skips_search(self, agent, mock_qdrant):
        state = GraphState(
            investigation_id="inv-002",
            entities={"techniques": ["T1078"]},
        )
        await agent.execute(state)
        mock_qdrant.search.assert_not_called()

    @pytest.mark.asyncio
    async def test_qdrant_failure_graceful(self, agent, state, mock_qdrant):
        mock_qdrant.search.side_effect = Exception("Qdrant unavailable")
        result = await agent.execute(state)
        # Should not crash
        assert isinstance(result.atlas_techniques, list)


class TestMergeAndDedup:
    @pytest.mark.asyncio
    async def test_deduplicates_by_atlas_id(self, agent, state, mock_postgres, mock_qdrant):
        mock_postgres.fetch_many.side_effect = [
            [{"technique_id": "AML.T0020", "framework": "ATLAS", "name": "Model Theft"}],
            [],
        ]
        mock_qdrant.search.return_value = [
            {
                "id": 1,
                "score": 0.75,
                "payload": {
                    "technique_id": "AML.T0020",
                    "name": "Model Theft",
                    "related_attack_id": "T1078",
                },
            },
        ]
        result = await agent.execute(state)
        atlas_ids = [t["atlas_id"] for t in result.atlas_techniques]
        assert atlas_ids.count("AML.T0020") == 1

    @pytest.mark.asyncio
    async def test_keeps_highest_confidence(self, agent, state, mock_postgres, mock_qdrant):
        mock_postgres.fetch_many.side_effect = [
            [{"technique_id": "AML.T0020", "framework": "ATLAS", "name": "Model Theft"}],
            [],
        ]
        mock_qdrant.search.return_value = [
            {
                "id": 1,
                "score": 0.75,
                "payload": {
                    "technique_id": "AML.T0020",
                    "name": "Model Theft",
                    "related_attack_id": "T1078",
                },
            },
        ]
        result = await agent.execute(state)
        atlas = [t for t in result.atlas_techniques if t["atlas_id"] == "AML.T0020"]
        # taxonomy has confidence=1.0, semantic has 0.75 — taxonomy wins
        assert atlas[0]["confidence"] == 1.0

    @pytest.mark.asyncio
    async def test_tracks_queries(self, agent, state):
        result = await agent.execute(state)
        assert result.queries_executed >= 2  # 2 taxonomy + 1 qdrant
