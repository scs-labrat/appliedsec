"""Async Redis client wrapper with IOC caching, FP patterns, and fail-open behavior."""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

# TTL tiers (seconds) based on IOC confidence
_TTL_HIGH = 2_592_000    # 30 days — confidence > 80
_TTL_MEDIUM = 604_800     # 7 days  — confidence 50-80
_TTL_LOW = 86_400         # 24 hours — confidence < 50


def _compute_ttl(confidence: float) -> int:
    """Return TTL in seconds based on confidence tier."""
    if confidence > 80:
        return _TTL_HIGH
    if confidence >= 50:
        return _TTL_MEDIUM
    return _TTL_LOW


class RedisClient:
    """Async Redis wrapper for IOC cache and FP pattern store.

    Fail-open: all get/set operations swallow connection errors and log warnings
    rather than propagating exceptions. Redis is a cache, not the source of truth.
    """

    def __init__(
        self,
        *,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        socket_timeout: float = 5.0,
        socket_connect_timeout: float = 5.0,
    ) -> None:
        self._host = host
        self._port = port
        self._db = db
        self._password = password
        self._socket_timeout = socket_timeout
        self._socket_connect_timeout = socket_connect_timeout
        self._client: Optional[aioredis.Redis] = None

    async def connect(self) -> None:
        """Create the Redis connection."""
        self._client = aioredis.Redis(
            host=self._host,
            port=self._port,
            db=self._db,
            password=self._password,
            socket_timeout=self._socket_timeout,
            socket_connect_timeout=self._socket_connect_timeout,
            decode_responses=True,
        )
        await self._client.ping()
        logger.info("Redis connected (%s:%d/%d)", self._host, self._port, self._db)

    async def close(self) -> None:
        """Gracefully close the Redis connection."""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("Redis connection closed")

    # --- IOC Cache ---

    async def set_ioc(
        self,
        tenant_id: str,
        ioc_type: str,
        value: str,
        data: dict[str, Any],
        confidence: float,
    ) -> None:
        """Cache an IOC with confidence-based TTL (tenant-scoped key)."""
        key = f"ioc:{tenant_id}:{ioc_type}:{value}"
        ttl = _compute_ttl(confidence)
        try:
            await self._client.set(key, json.dumps(data), ex=ttl)  # type: ignore[union-attr]
        except Exception:
            logger.warning("Redis set_ioc failed for %s", key, exc_info=True)

    async def get_ioc(
        self, tenant_id: str, ioc_type: str, value: str
    ) -> Optional[dict[str, Any]]:
        """Get a cached IOC. Returns None on miss or connection error (fail-open)."""
        key = f"ioc:{tenant_id}:{ioc_type}:{value}"
        try:
            raw = await self._client.get(key)  # type: ignore[union-attr]
            if raw is None:
                return None
            return json.loads(raw)
        except Exception:
            logger.warning("Redis get_ioc failed for %s", key, exc_info=True)
            return None

    async def delete_ioc(self, tenant_id: str, ioc_type: str, value: str) -> bool:
        """Delete a cached IOC. Returns True if deleted."""
        key = f"ioc:{tenant_id}:{ioc_type}:{value}"
        try:
            result = await self._client.delete(key)  # type: ignore[union-attr]
            return result > 0
        except Exception:
            logger.warning("Redis delete_ioc failed for %s", key, exc_info=True)
            return False

    # --- FP Pattern Cache ---

    async def set_fp_pattern(
        self,
        tenant_id: str,
        pattern_id: str,
        pattern_data: dict[str, Any],
        ttl: int = 86_400,
    ) -> None:
        """Cache a false positive pattern (tenant-scoped key)."""
        key = f"fp:{tenant_id}:{pattern_id}"
        try:
            await self._client.set(key, json.dumps(pattern_data), ex=ttl)  # type: ignore[union-attr]
        except Exception:
            logger.warning("Redis set_fp_pattern failed for %s", key, exc_info=True)

    async def get_fp_pattern(
        self, tenant_id: str, pattern_id: str,
    ) -> Optional[dict[str, Any]]:
        """Get a cached FP pattern. Returns None on miss or error (fail-open)."""
        key = f"fp:{tenant_id}:{pattern_id}"
        try:
            raw = await self._client.get(key)  # type: ignore[union-attr]
            if raw is None:
                return None
            return json.loads(raw)
        except Exception:
            logger.warning("Redis get_fp_pattern failed for %s", key, exc_info=True)
            return None

    async def list_fp_patterns(self, tenant_id: str) -> list[str]:
        """List FP pattern keys for a tenant using SCAN."""
        try:
            keys: list[str] = []
            async for key in self._client.scan_iter(match=f"fp:{tenant_id}:*"):  # type: ignore[union-attr]
                keys.append(key)
            return keys
        except Exception:
            logger.warning("Redis list_fp_patterns failed for tenant %s", tenant_id, exc_info=True)
            return []

    # --- Health & Lifecycle ---

    async def health_check(self) -> bool:
        """Ping Redis and return True if healthy."""
        try:
            if self._client is None:
                return False
            await self._client.ping()
            return True
        except Exception:
            logger.warning("Redis health check failed", exc_info=True)
            return False

    async def __aenter__(self) -> RedisClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        await self.close()
