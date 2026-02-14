"""Async PostgreSQL client wrapper using asyncpg with connection pooling."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, Optional

import asyncpg

logger = logging.getLogger(__name__)


class PostgresClient:
    """Thin async wrapper around asyncpg with pooling, parameterised queries,
    and transaction support.

    Usage::

        db = PostgresClient(dsn="postgresql://user:pass@host/db")
        await db.connect()
        row = await db.fetch_one("SELECT * FROM alerts WHERE id = $1", alert_id)
        await db.close()

    Or as an async context manager::

        async with PostgresClient(dsn="...") as db:
            rows = await db.fetch_many("SELECT * FROM alerts")
    """

    def __init__(
        self,
        *,
        dsn: Optional[str] = None,
        host: str = "localhost",
        port: int = 5432,
        database: str = "aluskort",
        user: str = "aluskort",
        password: str = "",
        min_size: int = 5,
        max_size: int = 20,
        statement_timeout: int = 30,
    ) -> None:
        self._dsn = dsn
        self._host = host
        self._port = port
        self._database = database
        self._user = user
        self._password = password
        self._min_size = min_size
        self._max_size = max_size
        self._statement_timeout = statement_timeout
        self._pool: Optional[asyncpg.Pool] = None

    def _ensure_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError(
                "PostgresClient is not connected. Call connect() first."
            )
        return self._pool

    async def connect(self) -> None:
        """Create the connection pool."""
        if self._dsn:
            self._pool = await asyncpg.create_pool(
                dsn=self._dsn,
                min_size=self._min_size,
                max_size=self._max_size,
                command_timeout=self._statement_timeout,
            )
        else:
            self._pool = await asyncpg.create_pool(
                host=self._host,
                port=self._port,
                database=self._database,
                user=self._user,
                password=self._password,
                min_size=self._min_size,
                max_size=self._max_size,
                command_timeout=self._statement_timeout,
            )
        logger.info(
            "PostgreSQL pool created (min=%d, max=%d, timeout=%ds)",
            self._min_size,
            self._max_size,
            self._statement_timeout,
        )

    async def close(self) -> None:
        """Gracefully close all pool connections."""
        pool = self._ensure_pool()
        await pool.close()
        self._pool = None
        logger.info("PostgreSQL pool closed")

    async def execute(self, query: str, *args: Any) -> str:
        """Execute a query with positional params. Returns status string."""
        pool = self._ensure_pool()
        return await pool.execute(query, *args)

    async def fetch_one(self, query: str, *args: Any) -> Optional[dict[str, Any]]:
        """Fetch a single row as a dict, or None if no match."""
        pool = self._ensure_pool()
        row = await pool.fetchrow(query, *args)
        return dict(row) if row is not None else None

    async def fetch_many(self, query: str, *args: Any) -> list[dict[str, Any]]:
        """Fetch all matching rows as a list of dicts."""
        pool = self._ensure_pool()
        rows = await pool.fetch(query, *args)
        return [dict(r) for r in rows]

    @asynccontextmanager
    async def transaction(self):
        """Async context manager for transactions.

        Yields a TransactionProxy with execute/fetch_one/fetch_many bound to
        the transaction connection. Commits on clean exit, rolls back on exception.
        """
        pool = self._ensure_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                yield _TransactionProxy(conn)

    async def health_check(self) -> bool:
        """Run SELECT 1 and return True if the pool is healthy."""
        try:
            pool = self._ensure_pool()
            await pool.fetchval("SELECT 1")
            return True
        except Exception:
            logger.warning("PostgreSQL health check failed", exc_info=True)
            return False

    async def __aenter__(self) -> PostgresClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        await self.close()


class _TransactionProxy:
    """Exposes query methods bound to a single transaction connection."""

    def __init__(self, conn: asyncpg.Connection) -> None:
        self._conn = conn

    async def execute(self, query: str, *args: Any) -> str:
        return await self._conn.execute(query, *args)

    async def fetch_one(self, query: str, *args: Any) -> Optional[dict[str, Any]]:
        row = await self._conn.fetchrow(query, *args)
        return dict(row) if row is not None else None

    async def fetch_many(self, query: str, *args: Any) -> list[dict[str, Any]]:
        rows = await self._conn.fetch(query, *args)
        return [dict(r) for r in rows]
