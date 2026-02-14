"""Tests for PostgresClient — all mocked, no live DB required."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.db.postgres import PostgresClient


@pytest.fixture
def client() -> PostgresClient:
    return PostgresClient(
        host="localhost",
        port=5432,
        database="aluskort",
        user="aluskort",
        password="secret",
        min_size=2,
        max_size=10,
        statement_timeout=30,
    )


@pytest.fixture
def dsn_client() -> PostgresClient:
    return PostgresClient(dsn="postgresql://user:pass@host:5432/db")


def _mock_pool() -> AsyncMock:
    pool = AsyncMock()
    pool.execute = AsyncMock(return_value="INSERT 0 1")
    pool.fetchrow = AsyncMock(return_value={"id": 1, "name": "test"})
    pool.fetch = AsyncMock(
        return_value=[{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]
    )
    pool.fetchval = AsyncMock(return_value=1)
    pool.close = AsyncMock()

    # Transaction support: acquire() returns an async context manager
    conn = AsyncMock()
    conn.execute = AsyncMock(return_value="UPDATE 1")
    conn.fetchrow = AsyncMock(return_value={"id": 1})
    conn.fetch = AsyncMock(return_value=[{"id": 1}])

    # conn.transaction() must be an async context manager
    tx_cm = AsyncMock()
    tx_cm.__aenter__ = AsyncMock(return_value=None)
    tx_cm.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=tx_cm)

    # pool.acquire() must be an async context manager yielding conn
    acq_cm = AsyncMock()
    acq_cm.__aenter__ = AsyncMock(return_value=conn)
    acq_cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acq_cm)

    return pool


class TestConnect:
    """AC-1.2.1: Connection pool initialization."""

    @pytest.mark.asyncio
    async def test_connect_with_individual_params(self, client: PostgresClient):
        mock_pool = _mock_pool()
        with patch("shared.db.postgres.asyncpg.create_pool", new_callable=AsyncMock, return_value=mock_pool) as create:
            await client.connect()
            create.assert_called_once_with(
                host="localhost",
                port=5432,
                database="aluskort",
                user="aluskort",
                password="secret",
                min_size=2,
                max_size=10,
                command_timeout=30,
            )

    @pytest.mark.asyncio
    async def test_connect_with_dsn(self, dsn_client: PostgresClient):
        mock_pool = _mock_pool()
        with patch("shared.db.postgres.asyncpg.create_pool", new_callable=AsyncMock, return_value=mock_pool) as create:
            await dsn_client.connect()
            create.assert_called_once_with(
                dsn="postgresql://user:pass@host:5432/db",
                min_size=5,
                max_size=20,
                command_timeout=30,
            )


class TestNotConnected:
    """All methods raise RuntimeError if pool not created."""

    @pytest.mark.asyncio
    async def test_execute_before_connect(self, client: PostgresClient):
        with pytest.raises(RuntimeError, match="not connected"):
            await client.execute("SELECT 1")

    @pytest.mark.asyncio
    async def test_fetch_one_before_connect(self, client: PostgresClient):
        with pytest.raises(RuntimeError, match="not connected"):
            await client.fetch_one("SELECT 1")

    @pytest.mark.asyncio
    async def test_fetch_many_before_connect(self, client: PostgresClient):
        with pytest.raises(RuntimeError, match="not connected"):
            await client.fetch_many("SELECT 1")

    @pytest.mark.asyncio
    async def test_health_check_before_connect(self, client: PostgresClient):
        result = await client.health_check()
        assert result is False


class TestExecute:
    """AC-1.2.2: Parameterised query execution."""

    @pytest.mark.asyncio
    async def test_execute_returns_status(self, client: PostgresClient):
        mock_pool = _mock_pool()
        client._pool = mock_pool
        result = await client.execute(
            "INSERT INTO alerts (id, title) VALUES ($1, $2)", "a1", "test"
        )
        assert result == "INSERT 0 1"
        mock_pool.execute.assert_called_once_with(
            "INSERT INTO alerts (id, title) VALUES ($1, $2)", "a1", "test"
        )


class TestFetchOne:
    """AC-1.2.3: Fetch one row."""

    @pytest.mark.asyncio
    async def test_fetch_one_returns_dict(self, client: PostgresClient):
        mock_pool = _mock_pool()
        client._pool = mock_pool
        result = await client.fetch_one("SELECT * FROM alerts WHERE id = $1", "a1")
        assert result == {"id": 1, "name": "test"}

    @pytest.mark.asyncio
    async def test_fetch_one_returns_none_when_no_match(self, client: PostgresClient):
        mock_pool = _mock_pool()
        mock_pool.fetchrow = AsyncMock(return_value=None)
        client._pool = mock_pool
        result = await client.fetch_one("SELECT * FROM alerts WHERE id = $1", "missing")
        assert result is None


class TestFetchMany:
    """AC-1.2.4: Fetch many rows."""

    @pytest.mark.asyncio
    async def test_fetch_many_returns_list_of_dicts(self, client: PostgresClient):
        mock_pool = _mock_pool()
        client._pool = mock_pool
        result = await client.fetch_many("SELECT * FROM alerts")
        assert result == [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]

    @pytest.mark.asyncio
    async def test_fetch_many_returns_empty_list(self, client: PostgresClient):
        mock_pool = _mock_pool()
        mock_pool.fetch = AsyncMock(return_value=[])
        client._pool = mock_pool
        result = await client.fetch_many("SELECT * FROM alerts WHERE 1=0")
        assert result == []


class TestTransaction:
    """AC-1.2.5: Transaction context manager."""

    @pytest.mark.asyncio
    async def test_transaction_commits_on_success(self, client: PostgresClient):
        mock_pool = _mock_pool()
        client._pool = mock_pool
        async with client.transaction() as tx:
            result = await tx.execute("UPDATE alerts SET title = $1 WHERE id = $2", "new", "a1")
            assert result == "UPDATE 1"

    @pytest.mark.asyncio
    async def test_transaction_rollback_on_exception(self, client: PostgresClient):
        mock_pool = _mock_pool()
        # Make the transaction __aexit__ propagate exceptions
        conn = AsyncMock()
        conn.execute = AsyncMock(side_effect=ValueError("boom"))
        tx_cm = AsyncMock()
        tx_cm.__aenter__ = AsyncMock(return_value=None)
        tx_cm.__aexit__ = AsyncMock(return_value=False)
        conn.transaction = MagicMock(return_value=tx_cm)
        acq_cm = AsyncMock()
        acq_cm.__aenter__ = AsyncMock(return_value=conn)
        acq_cm.__aexit__ = AsyncMock(return_value=False)
        mock_pool.acquire = MagicMock(return_value=acq_cm)
        client._pool = mock_pool

        with pytest.raises(ValueError, match="boom"):
            async with client.transaction() as tx:
                await tx.execute("BAD QUERY")

    @pytest.mark.asyncio
    async def test_transaction_fetch_one(self, client: PostgresClient):
        mock_pool = _mock_pool()
        client._pool = mock_pool
        async with client.transaction() as tx:
            result = await tx.fetch_one("SELECT * FROM alerts WHERE id = $1", "a1")
            assert result == {"id": 1}

    @pytest.mark.asyncio
    async def test_transaction_fetch_many(self, client: PostgresClient):
        mock_pool = _mock_pool()
        client._pool = mock_pool
        async with client.transaction() as tx:
            result = await tx.fetch_many("SELECT * FROM alerts")
            assert result == [{"id": 1}]


class TestHealthCheck:
    """AC-1.2.8: Health check."""

    @pytest.mark.asyncio
    async def test_health_check_returns_true(self, client: PostgresClient):
        mock_pool = _mock_pool()
        client._pool = mock_pool
        assert await client.health_check() is True
        mock_pool.fetchval.assert_called_once_with("SELECT 1")

    @pytest.mark.asyncio
    async def test_health_check_returns_false_on_error(self, client: PostgresClient):
        mock_pool = _mock_pool()
        mock_pool.fetchval = AsyncMock(side_effect=ConnectionError("down"))
        client._pool = mock_pool
        assert await client.health_check() is False


class TestClose:
    """AC-1.2.7: Graceful shutdown."""

    @pytest.mark.asyncio
    async def test_close_terminates_pool(self, client: PostgresClient):
        mock_pool = _mock_pool()
        client._pool = mock_pool
        await client.close()
        mock_pool.close.assert_called_once()
        assert client._pool is None


class TestContextManager:
    """Async context manager support."""

    @pytest.mark.asyncio
    async def test_async_with(self):
        mock_pool = _mock_pool()
        with patch("shared.db.postgres.asyncpg.create_pool", new_callable=AsyncMock, return_value=mock_pool):
            async with PostgresClient(dsn="postgresql://test") as db:
                result = await db.health_check()
                assert result is True
            mock_pool.close.assert_called_once()
