"""Tests for RedisClient — all mocked, no live Redis required."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
import redis.exceptions

from shared.db.redis_cache import RedisClient, _compute_ttl


class TestComputeTtl:
    """TTL tiers based on confidence."""

    def test_high_confidence(self):
        assert _compute_ttl(81) == 2_592_000  # 30 days
        assert _compute_ttl(100) == 2_592_000

    def test_medium_confidence(self):
        assert _compute_ttl(50) == 604_800  # 7 days
        assert _compute_ttl(80) == 604_800
        assert _compute_ttl(65) == 604_800

    def test_low_confidence(self):
        assert _compute_ttl(49) == 86_400  # 24 hours
        assert _compute_ttl(0) == 86_400
        assert _compute_ttl(30) == 86_400

    def test_boundary_80(self):
        assert _compute_ttl(80) == 604_800   # 80 is medium (50-80)
        assert _compute_ttl(80.1) == 2_592_000  # > 80 is high


def _mock_redis() -> AsyncMock:
    mock = AsyncMock()
    mock.ping = AsyncMock(return_value=True)
    mock.set = AsyncMock()
    mock.get = AsyncMock(return_value=None)
    mock.delete = AsyncMock(return_value=1)
    mock.aclose = AsyncMock()
    return mock


@pytest.fixture
def client() -> RedisClient:
    return RedisClient(host="localhost", port=6379, db=0, password="secret")


class TestConnect:
    """AC-1.3.1: Connection pool initialization."""

    @pytest.mark.asyncio
    async def test_connect_pings(self, client: RedisClient):
        mock = _mock_redis()
        with patch("shared.db.redis_cache.aioredis.Redis", return_value=mock):
            await client.connect()
            mock.ping.assert_called_once()


class TestSetIoc:
    """AC-1.3.2, AC-1.3.3, AC-1.3.4: IOC set with confidence-based TTL."""

    @pytest.mark.asyncio
    async def test_high_confidence_ttl(self, client: RedisClient):
        mock = _mock_redis()
        client._client = mock
        await client.set_ioc("tenant-A", "ip", "1.2.3.4", {"family": "emotet"}, confidence=85)
        mock.set.assert_called_once_with(
            "ioc:tenant-A:ip:1.2.3.4", json.dumps({"family": "emotet"}), ex=2_592_000
        )

    @pytest.mark.asyncio
    async def test_medium_confidence_ttl(self, client: RedisClient):
        mock = _mock_redis()
        client._client = mock
        await client.set_ioc("tenant-A", "domain", "evil.com", {"status": "active"}, confidence=65)
        mock.set.assert_called_once_with(
            "ioc:tenant-A:domain:evil.com",
            json.dumps({"status": "active"}),
            ex=604_800,
        )

    @pytest.mark.asyncio
    async def test_low_confidence_ttl(self, client: RedisClient):
        mock = _mock_redis()
        client._client = mock
        await client.set_ioc("tenant-A", "hash", "abc123", {"type": "md5"}, confidence=30)
        mock.set.assert_called_once_with(
            "ioc:tenant-A:hash:abc123", json.dumps({"type": "md5"}), ex=86_400
        )


class TestGetIoc:
    """AC-1.3.5, AC-1.3.6: IOC get."""

    @pytest.mark.asyncio
    async def test_cache_hit_returns_dict(self, client: RedisClient):
        mock = _mock_redis()
        mock.get = AsyncMock(return_value=json.dumps({"family": "emotet"}))
        client._client = mock
        result = await client.get_ioc("tenant-A", "hash", "abc123")
        assert result == {"family": "emotet"}

    @pytest.mark.asyncio
    async def test_cache_miss_returns_none(self, client: RedisClient):
        mock = _mock_redis()
        mock.get = AsyncMock(return_value=None)
        client._client = mock
        result = await client.get_ioc("tenant-A", "ip", "8.8.8.8")
        assert result is None


class TestFailOpen:
    """AC-1.3.7: Fail-open on connection error."""

    @pytest.mark.asyncio
    async def test_get_ioc_fail_open(self, client: RedisClient):
        mock = _mock_redis()
        mock.get = AsyncMock(side_effect=redis.exceptions.ConnectionError("down"))
        client._client = mock
        result = await client.get_ioc("tenant-A", "ip", "1.2.3.4")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_fp_pattern_fail_open(self, client: RedisClient):
        mock = _mock_redis()
        mock.get = AsyncMock(side_effect=redis.exceptions.TimeoutError("timeout"))
        client._client = mock
        result = await client.get_fp_pattern("tenant-A", "fp-001")
        assert result is None

    @pytest.mark.asyncio
    async def test_set_ioc_fail_open(self, client: RedisClient):
        mock = _mock_redis()
        mock.set = AsyncMock(side_effect=redis.exceptions.ConnectionError("down"))
        client._client = mock
        # Should not raise
        await client.set_ioc("tenant-A", "ip", "1.2.3.4", {"x": 1}, confidence=90)

    @pytest.mark.asyncio
    async def test_health_check_fail_open(self, client: RedisClient):
        mock = _mock_redis()
        mock.ping = AsyncMock(side_effect=redis.exceptions.ConnectionError("down"))
        client._client = mock
        assert await client.health_check() is False


class TestFpPattern:
    """AC-1.3.8, AC-1.3.9: FP pattern cache with tenant isolation (F5)."""

    @pytest.mark.asyncio
    async def test_set_and_get_fp_pattern(self, client: RedisClient):
        mock = _mock_redis()
        pattern = {"regex": ".*test.*", "confidence": 0.95}
        mock.get = AsyncMock(return_value=json.dumps(pattern))
        client._client = mock

        await client.set_fp_pattern("tenant-A", "fp-001", pattern)
        mock.set.assert_called_once_with(
            "fp:tenant-A:fp-001", json.dumps(pattern), ex=86_400
        )

        result = await client.get_fp_pattern("tenant-A", "fp-001")
        assert result == pattern

    @pytest.mark.asyncio
    async def test_get_fp_pattern_miss(self, client: RedisClient):
        mock = _mock_redis()
        mock.get = AsyncMock(return_value=None)
        client._client = mock
        result = await client.get_fp_pattern("tenant-A", "fp-missing")
        assert result is None

    @pytest.mark.asyncio
    async def test_fp_key_includes_tenant_id(self, client: RedisClient):
        """F5: FP pattern keys must include tenant_id for isolation."""
        mock = _mock_redis()
        client._client = mock
        await client.set_fp_pattern("tenant-X", "fp-100", {"test": True})
        call_args = mock.set.call_args
        key = call_args[0][0]
        assert key == "fp:tenant-X:fp-100"
        assert "tenant-X" in key

    @pytest.mark.asyncio
    async def test_cross_tenant_isolation(self, client: RedisClient):
        """F5: Tenant A's patterns should not be visible to tenant B."""
        mock = _mock_redis()
        client._client = mock

        # Store pattern for tenant-A
        await client.set_fp_pattern("tenant-A", "fp-001", {"data": "a"})
        # Get for tenant-B should use different key
        mock.get = AsyncMock(return_value=None)
        result = await client.get_fp_pattern("tenant-B", "fp-001")
        assert result is None
        # Verify it queried the tenant-B scoped key
        mock.get.assert_called_with("fp:tenant-B:fp-001")


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_health_check_true(self, client: RedisClient):
        mock = _mock_redis()
        client._client = mock
        assert await client.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_no_client(self, client: RedisClient):
        assert await client.health_check() is False


class TestClose:
    @pytest.mark.asyncio
    async def test_close(self, client: RedisClient):
        mock = _mock_redis()
        client._client = mock
        await client.close()
        mock.aclose.assert_called_once()
        assert client._client is None
