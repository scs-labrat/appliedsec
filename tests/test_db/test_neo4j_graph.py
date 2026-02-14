"""Tests for Neo4jClient — all mocked, no live Neo4j required."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.db.neo4j_graph import (
    CONSEQUENCE_QUERY,
    ZONE_CONSEQUENCE_FALLBACK,
    Neo4jClient,
    _fallback_consequence,
    _map_consequence_severity,
)


@pytest.fixture
def client() -> Neo4jClient:
    return Neo4jClient(
        uri="bolt://localhost:7687",
        user="neo4j",
        password="secret",
    )


def _mock_driver() -> AsyncMock:
    driver = AsyncMock()
    driver.verify_connectivity = AsyncMock()
    driver.close = AsyncMock()
    driver.execute_query = AsyncMock(return_value=([], None, None))
    return driver


class TestConnect:
    """AC-1.5.1: Driver initialization."""

    @pytest.mark.asyncio
    async def test_connect_creates_driver(self, client: Neo4jClient):
        mock_driver = _mock_driver()
        with patch(
            "shared.db.neo4j_graph.neo4j.AsyncGraphDatabase.driver",
            return_value=mock_driver,
        ) as mock_create:
            await client.connect()
            mock_create.assert_called_once_with(
                "bolt://localhost:7687",
                auth=("neo4j", "secret"),
                max_connection_pool_size=50,
            )
            mock_driver.verify_connectivity.assert_called_once()


class TestExecuteQuery:
    """AC-1.5.2: Cypher query execution."""

    @pytest.mark.asyncio
    async def test_execute_returns_list_of_dicts(self, client: Neo4jClient):
        mock_driver = _mock_driver()
        record1 = MagicMock()
        record1.__iter__ = MagicMock(return_value=iter([("id", 1), ("name", "test")]))
        record1.keys.return_value = ["id", "name"]
        # Make dict(record) work
        record1.__getitem__ = MagicMock(side_effect=lambda k: {"id": 1, "name": "test"}[k])
        # Simulating dict() on a neo4j Record - use data() method workaround
        # Actually, the simplest mock: make the record behave like a dict
        mock_driver.execute_query = AsyncMock(
            return_value=([{"id": 1, "name": "test"}, {"id": 2, "name": "test2"}], None, None)
        )
        client._driver = mock_driver

        results = await client.execute_query(
            "MATCH (n:Asset) RETURN n LIMIT 10", params={}
        )
        assert len(results) == 2
        assert results[0] == {"id": 1, "name": "test"}

    @pytest.mark.asyncio
    async def test_execute_raises_if_not_connected(self, client: Neo4jClient):
        with pytest.raises(RuntimeError, match="not connected"):
            await client.execute_query("RETURN 1")


class TestConsequenceSeverity:
    """AC-1.5.3, AC-1.5.4: Consequence reasoning query."""

    @pytest.mark.asyncio
    async def test_consequence_query_executed(self, client: Neo4jClient):
        mock_driver = _mock_driver()
        row = {
            "finding_id": "f-001",
            "directly_affected_asset": "server-1",
            "reachable_consequences": ["safety_life", "equipment"],
            "max_consequence_severity": "CRITICAL",
        }
        mock_driver.execute_query = AsyncMock(return_value=([row], None, None))
        client._driver = mock_driver

        result = await client.get_consequence_severity("f-001")
        assert result["max_consequence_severity"] == "CRITICAL"
        assert result["fallback"] is False

        # Verify the correct query was used
        call_args = mock_driver.execute_query.call_args
        assert call_args[0][0] == CONSEQUENCE_QUERY
        assert call_args[1]["parameters_"] == {"finding_id": "f-001"}


class TestConsequenceMapping:
    """AC-1.5.4: Consequence severity mapping."""

    def test_safety_life_is_critical(self):
        assert _map_consequence_severity(["safety_life", "equipment"]) == "CRITICAL"

    def test_equipment_is_high(self):
        assert _map_consequence_severity(["equipment", "downtime"]) == "HIGH"

    def test_downtime_is_medium(self):
        assert _map_consequence_severity(["downtime"]) == "MEDIUM"

    def test_unknown_is_low(self):
        assert _map_consequence_severity(["data_loss"]) == "LOW"

    def test_empty_is_low(self):
        assert _map_consequence_severity([]) == "LOW"


class TestFallback:
    """AC-1.5.5, AC-1.5.6: Fallback when Neo4j is down."""

    @pytest.mark.asyncio
    async def test_fallback_on_exception(self, client: Neo4jClient):
        mock_driver = _mock_driver()
        mock_driver.execute_query = AsyncMock(side_effect=Exception("Neo4j down"))
        client._driver = mock_driver

        result = await client.get_consequence_severity(
            "f-001", zone_class="safety_life"
        )
        assert result["max_consequence_severity"] == "CRITICAL"
        assert result["fallback"] is True

    @pytest.mark.asyncio
    async def test_fallback_equipment(self, client: Neo4jClient):
        mock_driver = _mock_driver()
        mock_driver.execute_query = AsyncMock(side_effect=Exception("down"))
        client._driver = mock_driver

        result = await client.get_consequence_severity("f-001", zone_class="equipment")
        assert result["max_consequence_severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_fallback_unknown_zone_returns_low(self, client: Neo4jClient):
        mock_driver = _mock_driver()
        mock_driver.execute_query = AsyncMock(side_effect=Exception("down"))
        client._driver = mock_driver

        result = await client.get_consequence_severity("f-001", zone_class="unknown_zone")
        assert result["max_consequence_severity"] == "LOW"

    @pytest.mark.asyncio
    async def test_fallback_none_zone_returns_low(self, client: Neo4jClient):
        mock_driver = _mock_driver()
        mock_driver.execute_query = AsyncMock(side_effect=Exception("down"))
        client._driver = mock_driver

        result = await client.get_consequence_severity("f-001")
        assert result["max_consequence_severity"] == "LOW"

    def test_fallback_function_directly(self):
        assert _fallback_consequence("safety_life") == "CRITICAL"
        assert _fallback_consequence("equipment") == "HIGH"
        assert _fallback_consequence("downtime") == "MEDIUM"
        assert _fallback_consequence("data_loss") == "LOW"
        assert _fallback_consequence("other") == "LOW"
        assert _fallback_consequence(None) == "LOW"

    def test_zone_consequence_fallback_dict(self):
        assert ZONE_CONSEQUENCE_FALLBACK == {
            "safety_life": "CRITICAL",
            "equipment": "HIGH",
            "downtime": "MEDIUM",
            "data_loss": "LOW",
        }


class TestHealthCheck:
    """AC-1.5.8: Health check."""

    @pytest.mark.asyncio
    async def test_health_check_true(self, client: Neo4jClient):
        mock_driver = _mock_driver()
        mock_driver.execute_query = AsyncMock(return_value=([{"1": 1}], None, None))
        client._driver = mock_driver
        assert await client.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_false_on_error(self, client: Neo4jClient):
        mock_driver = _mock_driver()
        mock_driver.execute_query = AsyncMock(side_effect=Exception("down"))
        client._driver = mock_driver
        assert await client.health_check() is False

    @pytest.mark.asyncio
    async def test_health_check_false_not_connected(self, client: Neo4jClient):
        assert await client.health_check() is False


class TestClose:
    """AC-1.5.7: Graceful shutdown."""

    @pytest.mark.asyncio
    async def test_close(self, client: Neo4jClient):
        mock_driver = _mock_driver()
        client._driver = mock_driver
        await client.close()
        mock_driver.close.assert_called_once()
        assert client._driver is None
