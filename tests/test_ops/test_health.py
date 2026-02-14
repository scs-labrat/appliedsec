"""Tests for ops.health — Story 11.5."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from ops.health import (
    DEPENDENCY_CHECKERS,
    SERVICE_DEPENDENCIES,
    SERVICES,
    DependencyStatus,
    HealthCheck,
    HealthResponse,
    HealthStatus,
    check_kafka,
    check_neo4j,
    check_postgres,
    check_qdrant,
    check_redis,
)


# ── HealthStatus ──────────────────────────────────────────────────

class TestHealthStatus:
    def test_values(self):
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"


# ── DependencyStatus ──────────────────────────────────────────────

class TestDependencyStatus:
    def test_healthy(self):
        d = DependencyStatus(name="postgres", healthy=True)
        assert d.healthy is True
        assert d.error == ""
        assert d.checked_at != ""

    def test_unhealthy(self):
        d = DependencyStatus(name="redis", healthy=False, error="connection refused")
        assert d.healthy is False
        assert d.error == "connection refused"


# ── HealthResponse ────────────────────────────────────────────────

class TestHealthResponse:
    def test_healthy_response(self):
        r = HealthResponse(status=HealthStatus.HEALTHY, service="test")
        assert r.http_status_code == 200
        assert r.timestamp != ""

    def test_degraded_response(self):
        r = HealthResponse(status=HealthStatus.DEGRADED, service="test")
        assert r.http_status_code == 200

    def test_unhealthy_response(self):
        r = HealthResponse(status=HealthStatus.UNHEALTHY, service="test")
        assert r.http_status_code == 503


# ── Individual checkers ───────────────────────────────────────────

class TestPostgresCheck:
    @pytest.mark.asyncio
    async def test_healthy(self):
        client = AsyncMock()
        client.fetch_one = AsyncMock(return_value={"ok": 1})
        result = await check_postgres(client)
        assert result.name == "postgres"
        assert result.healthy is True

    @pytest.mark.asyncio
    async def test_unhealthy(self):
        client = AsyncMock()
        client.fetch_one = AsyncMock(side_effect=RuntimeError("conn refused"))
        result = await check_postgres(client)
        assert result.healthy is False
        assert "conn refused" in result.error


class TestRedisCheck:
    @pytest.mark.asyncio
    async def test_healthy(self):
        client = AsyncMock()
        client.ping = AsyncMock(return_value=True)
        result = await check_redis(client)
        assert result.healthy is True

    @pytest.mark.asyncio
    async def test_unhealthy(self):
        client = AsyncMock()
        client.ping = AsyncMock(side_effect=RuntimeError("timeout"))
        result = await check_redis(client)
        assert result.healthy is False


class TestKafkaCheck:
    @pytest.mark.asyncio
    async def test_healthy(self):
        producer = AsyncMock()
        producer.list_topics = AsyncMock(return_value={"topics": []})
        result = await check_kafka(producer)
        assert result.healthy is True

    @pytest.mark.asyncio
    async def test_unhealthy(self):
        producer = AsyncMock()
        producer.list_topics = AsyncMock(side_effect=RuntimeError("no brokers"))
        result = await check_kafka(producer)
        assert result.healthy is False


class TestQdrantCheck:
    @pytest.mark.asyncio
    async def test_healthy(self):
        client = AsyncMock()
        client.health = AsyncMock(return_value=True)
        result = await check_qdrant(client)
        assert result.healthy is True

    @pytest.mark.asyncio
    async def test_unhealthy(self):
        client = AsyncMock()
        client.health = AsyncMock(side_effect=RuntimeError("fail"))
        result = await check_qdrant(client)
        assert result.healthy is False


class TestNeo4jCheck:
    @pytest.mark.asyncio
    async def test_healthy(self):
        client = AsyncMock()
        client.verify_connectivity = AsyncMock(return_value=True)
        result = await check_neo4j(client)
        assert result.healthy is True

    @pytest.mark.asyncio
    async def test_unhealthy(self):
        client = AsyncMock()
        client.verify_connectivity = AsyncMock(side_effect=RuntimeError("fail"))
        result = await check_neo4j(client)
        assert result.healthy is False


# ── SERVICE_DEPENDENCIES ──────────────────────────────────────────

class TestServiceDependencies:
    def test_all_services_present(self):
        expected = {
            "entity-parser", "ctem-normaliser", "orchestrator",
            "context-gateway", "llm-router", "batch-scheduler",
            "sentinel-adapter", "atlas-detection",
        }
        assert set(SERVICE_DEPENDENCIES.keys()) == expected

    def test_services_list(self):
        assert len(SERVICES) == 8

    def test_orchestrator_has_most_deps(self):
        assert len(SERVICE_DEPENDENCIES["orchestrator"]) == 4
        assert "postgres" in SERVICE_DEPENDENCIES["orchestrator"]
        assert "redis" in SERVICE_DEPENDENCIES["orchestrator"]
        assert "kafka" in SERVICE_DEPENDENCIES["orchestrator"]
        assert "qdrant" in SERVICE_DEPENDENCIES["orchestrator"]

    def test_sentinel_adapter_minimal_deps(self):
        assert SERVICE_DEPENDENCIES["sentinel-adapter"] == ["kafka"]


# ── DEPENDENCY_CHECKERS ──────────────────────────────────────────

class TestDependencyCheckers:
    def test_all_checkers_registered(self):
        expected = {"postgres", "redis", "kafka", "qdrant", "neo4j"}
        assert set(DEPENDENCY_CHECKERS.keys()) == expected

    def test_all_are_callable(self):
        for name, checker in DEPENDENCY_CHECKERS.items():
            assert callable(checker), f"{name} checker is not callable"


# ── HealthCheck class ─────────────────────────────────────────────

class TestHealthCheckLiveness:
    @pytest.mark.asyncio
    async def test_liveness_always_healthy(self):
        hc = HealthCheck("test-service", version="1.0.0")
        response = await hc.liveness()
        assert response.status == HealthStatus.HEALTHY
        assert response.service == "test-service"
        assert response.version == "1.0.0"
        assert response.uptime_seconds >= 0

    @pytest.mark.asyncio
    async def test_service_name(self):
        hc = HealthCheck("orchestrator")
        assert hc.service_name == "orchestrator"


class TestHealthCheckReadiness:
    @pytest.mark.asyncio
    async def test_all_healthy(self):
        pg = AsyncMock()
        pg.fetch_one = AsyncMock(return_value={"ok": 1})
        kafka = AsyncMock()
        kafka.list_topics = AsyncMock(return_value={"topics": []})
        hc = HealthCheck(
            "entity-parser",
            clients={"postgres": pg, "kafka": kafka},
        )
        response = await hc.readiness()
        assert response.status == HealthStatus.HEALTHY
        assert len(response.dependencies) == 2
        assert all(d.healthy for d in response.dependencies)
        assert response.http_status_code == 200

    @pytest.mark.asyncio
    async def test_partial_failure_degraded(self):
        pg = AsyncMock()
        pg.fetch_one = AsyncMock(return_value={"ok": 1})
        kafka = AsyncMock()
        kafka.list_topics = AsyncMock(side_effect=RuntimeError("no brokers"))
        hc = HealthCheck(
            "entity-parser",
            clients={"postgres": pg, "kafka": kafka},
        )
        response = await hc.readiness()
        assert response.status == HealthStatus.DEGRADED
        assert response.http_status_code == 200

    @pytest.mark.asyncio
    async def test_all_failed_unhealthy(self):
        pg = AsyncMock()
        pg.fetch_one = AsyncMock(side_effect=RuntimeError("down"))
        kafka = AsyncMock()
        kafka.list_topics = AsyncMock(side_effect=RuntimeError("down"))
        hc = HealthCheck(
            "entity-parser",
            clients={"postgres": pg, "kafka": kafka},
        )
        response = await hc.readiness()
        assert response.status == HealthStatus.UNHEALTHY
        assert response.http_status_code == 503

    @pytest.mark.asyncio
    async def test_missing_client(self):
        hc = HealthCheck("entity-parser", clients={})
        response = await hc.readiness()
        assert response.status == HealthStatus.UNHEALTHY
        for dep in response.dependencies:
            assert dep.healthy is False
            assert "no client" in dep.error

    @pytest.mark.asyncio
    async def test_unknown_service_no_deps(self):
        hc = HealthCheck("unknown-service", clients={})
        response = await hc.readiness()
        assert response.status == HealthStatus.HEALTHY
        assert len(response.dependencies) == 0

    @pytest.mark.asyncio
    async def test_orchestrator_four_deps(self):
        pg = AsyncMock()
        pg.fetch_one = AsyncMock(return_value={"ok": 1})
        redis = AsyncMock()
        redis.ping = AsyncMock(return_value=True)
        kafka = AsyncMock()
        kafka.list_topics = AsyncMock(return_value={})
        qdrant = AsyncMock()
        qdrant.health = AsyncMock(return_value=True)
        hc = HealthCheck(
            "orchestrator",
            clients={"postgres": pg, "redis": redis, "kafka": kafka, "qdrant": qdrant},
        )
        response = await hc.readiness()
        assert response.status == HealthStatus.HEALTHY
        assert len(response.dependencies) == 4
