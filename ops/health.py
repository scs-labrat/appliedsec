"""Health check endpoints — Story 11.5.

Provides /health (liveness) and /ready (readiness) logic for all services.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    """Health check status values."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class DependencyStatus:
    """Status of a single infrastructure dependency."""

    name: str
    healthy: bool
    latency_ms: float = 0.0
    error: str = ""
    checked_at: str = ""

    def __post_init__(self) -> None:
        if not self.checked_at:
            self.checked_at = datetime.now(timezone.utc).isoformat()


@dataclass
class HealthResponse:
    """Response from a health or readiness check."""

    status: HealthStatus
    service: str
    version: str = ""
    uptime_seconds: float = 0.0
    dependencies: list[DependencyStatus] = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def http_status_code(self) -> int:
        """Return HTTP status code: 200 for healthy/degraded, 503 for unhealthy."""
        return 200 if self.status != HealthStatus.UNHEALTHY else 503


# ── Dependency checkers ───────────────────────────────────────────

async def check_postgres(client: Any) -> DependencyStatus:
    """Verify Postgres connectivity."""
    try:
        result = await client.fetch_one("SELECT 1 as ok")
        return DependencyStatus(name="postgres", healthy=result is not None)
    except Exception as exc:
        return DependencyStatus(name="postgres", healthy=False, error=str(exc))


async def check_redis(client: Any) -> DependencyStatus:
    """Verify Redis connectivity."""
    try:
        pong = await client.ping()
        return DependencyStatus(name="redis", healthy=bool(pong))
    except Exception as exc:
        return DependencyStatus(name="redis", healthy=False, error=str(exc))


async def check_kafka(producer: Any) -> DependencyStatus:
    """Verify Kafka connectivity via producer metadata."""
    try:
        metadata = await producer.list_topics(timeout=5)
        return DependencyStatus(
            name="kafka", healthy=metadata is not None,
        )
    except Exception as exc:
        return DependencyStatus(name="kafka", healthy=False, error=str(exc))


async def check_qdrant(client: Any) -> DependencyStatus:
    """Verify Qdrant connectivity."""
    try:
        result = await client.health()
        return DependencyStatus(name="qdrant", healthy=bool(result))
    except Exception as exc:
        return DependencyStatus(name="qdrant", healthy=False, error=str(exc))


async def check_neo4j(client: Any) -> DependencyStatus:
    """Verify Neo4j connectivity."""
    try:
        result = await client.verify_connectivity()
        return DependencyStatus(name="neo4j", healthy=result is not False)
    except Exception as exc:
        return DependencyStatus(name="neo4j", healthy=False, error=str(exc))


# ── dependency map per service ────────────────────────────────────

DEPENDENCY_CHECKERS = {
    "postgres": check_postgres,
    "redis": check_redis,
    "kafka": check_kafka,
    "qdrant": check_qdrant,
    "neo4j": check_neo4j,
}

SERVICE_DEPENDENCIES: dict[str, list[str]] = {
    "entity-parser": ["postgres", "kafka"],
    "ctem-normaliser": ["postgres", "kafka"],
    "orchestrator": ["postgres", "redis", "kafka", "qdrant"],
    "context-gateway": ["redis"],
    "llm-router": ["redis"],
    "batch-scheduler": ["postgres", "kafka"],
    "sentinel-adapter": ["kafka"],
    "atlas-detection": ["postgres", "kafka"],
}

SERVICES = list(SERVICE_DEPENDENCIES.keys())


# ── HealthCheck class ─────────────────────────────────────────────

class HealthCheck:
    """Health check manager for a single service."""

    def __init__(
        self,
        service_name: str,
        version: str = "0.1.0",
        clients: dict[str, Any] | None = None,
    ) -> None:
        self._service = service_name
        self._version = version
        self._clients = clients or {}
        self._start_time = datetime.now(timezone.utc)

    @property
    def service_name(self) -> str:
        return self._service

    @property
    def uptime_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self._start_time).total_seconds()

    async def liveness(self) -> HealthResponse:
        """Liveness probe — returns healthy if the process is alive."""
        return HealthResponse(
            status=HealthStatus.HEALTHY,
            service=self._service,
            version=self._version,
            uptime_seconds=self.uptime_seconds,
        )

    async def readiness(self) -> HealthResponse:
        """Readiness probe — verifies all dependency connections."""
        dep_names = SERVICE_DEPENDENCIES.get(self._service, [])
        statuses: list[DependencyStatus] = []

        for dep_name in dep_names:
            checker = DEPENDENCY_CHECKERS.get(dep_name)
            client = self._clients.get(dep_name)

            if checker is None or client is None:
                statuses.append(DependencyStatus(
                    name=dep_name,
                    healthy=False,
                    error="no client configured",
                ))
                continue

            try:
                status = await checker(client)
                statuses.append(status)
            except Exception as exc:
                statuses.append(DependencyStatus(
                    name=dep_name, healthy=False, error=str(exc),
                ))

        all_healthy = all(d.healthy for d in statuses)
        any_healthy = any(d.healthy for d in statuses) if statuses else True

        if all_healthy:
            overall = HealthStatus.HEALTHY
        elif any_healthy:
            overall = HealthStatus.DEGRADED
        else:
            overall = HealthStatus.UNHEALTHY

        return HealthResponse(
            status=overall,
            service=self._service,
            version=self._version,
            uptime_seconds=self.uptime_seconds,
            dependencies=statuses,
        )
