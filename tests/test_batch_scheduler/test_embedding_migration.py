"""Tests for embedding migration job — Story 14.6."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from batch_scheduler.embedding_migration import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_RATE_LIMIT_RPS,
    EmbeddingMigrationJob,
    MigrationProgress,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_qdrant_mock() -> AsyncMock:
    """Create mock Qdrant client with async methods."""
    mock = AsyncMock()
    mock.fetch_points_by_model = AsyncMock(return_value=[])
    mock.upsert_point = AsyncMock()
    return mock


def _make_pg_mock() -> AsyncMock:
    """Create mock Postgres client."""
    mock = AsyncMock()
    mock.execute = AsyncMock()
    mock.fetch = AsyncMock(return_value=[])
    return mock


# ---------------------------------------------------------------------------
# TestEmbeddingMigration (Task 3)
# ---------------------------------------------------------------------------

class TestEmbeddingMigration:
    """AC-2,3,5: Migration checkpoint, resume, idempotent, rate limiting."""

    @pytest.mark.asyncio
    async def test_checkpoint_saves_to_postgres(self):
        """checkpoint() calls Postgres with correct params."""
        qdrant = _make_qdrant_mock()
        pg = _make_pg_mock()
        job = EmbeddingMigrationJob(qdrant, pg, "old-model", "new-model")

        await job.checkpoint("point-50", 50)
        pg.execute.assert_awaited_once()
        args = pg.execute.call_args[0]
        assert "embedding_migration" in args[0]
        assert args[4] == "point-50"
        assert args[5] == 50

    @pytest.mark.asyncio
    async def test_get_checkpoint_returns_last_id(self):
        """get_checkpoint returns the last processed point_id."""
        qdrant = _make_qdrant_mock()
        pg = _make_pg_mock()
        pg.fetch = AsyncMock(return_value=[{"last_point_id": "point-42"}])
        job = EmbeddingMigrationJob(qdrant, pg, "old-model", "new-model")

        result = await job.get_checkpoint()
        assert result == "point-42"

    @pytest.mark.asyncio
    async def test_get_checkpoint_returns_none_when_empty(self):
        """get_checkpoint returns None when no checkpoint exists."""
        qdrant = _make_qdrant_mock()
        pg = _make_pg_mock()
        pg.fetch = AsyncMock(return_value=[])
        job = EmbeddingMigrationJob(qdrant, pg, "old-model", "new-model")

        result = await job.get_checkpoint()
        assert result is None

    @pytest.mark.asyncio
    async def test_run_with_no_points_returns_zero(self):
        """Migration with no old-model points returns 0 migrated."""
        qdrant = _make_qdrant_mock()
        pg = _make_pg_mock()
        job = EmbeddingMigrationJob(qdrant, pg, "old-model", "new-model")

        result = await job.run()
        assert result["points_migrated"] == 0
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_run_migrates_points(self):
        """Migration processes each point and checkpoints."""
        qdrant = _make_qdrant_mock()
        qdrant.fetch_points_by_model = AsyncMock(return_value=[
            {"id": "p1", "vector": [0.1, 0.2], "payload": {"doc_id": "d1"}},
            {"id": "p2", "vector": [0.3, 0.4], "payload": {"doc_id": "d2"}},
        ])
        pg = _make_pg_mock()
        job = EmbeddingMigrationJob(
            qdrant, pg, "old-model", "new-model",
            batch_size=10, rate_limit_rps=1000,
        )

        result = await job.run()
        assert result["points_migrated"] == 2
        assert result["last_point_id"] == "p2"
        assert qdrant.upsert_point.await_count == 2

    @pytest.mark.asyncio
    async def test_idempotent_rerun(self):
        """Re-running migration on same points produces same result."""
        qdrant = _make_qdrant_mock()
        points = [
            {"id": "p1", "vector": [0.1], "payload": {"doc_id": "d1"}},
        ]
        qdrant.fetch_points_by_model = AsyncMock(return_value=points)
        pg = _make_pg_mock()
        job = EmbeddingMigrationJob(
            qdrant, pg, "old-model", "new-model",
            rate_limit_rps=1000,
        )

        result1 = await job.run()
        result2 = await job.run()
        assert result1["points_migrated"] == result2["points_migrated"]

    @pytest.mark.asyncio
    async def test_resume_from_checkpoint(self):
        """Migration resumes from provided checkpoint."""
        qdrant = _make_qdrant_mock()
        qdrant.fetch_points_by_model = AsyncMock(return_value=[
            {"id": "p3", "vector": [0.5], "payload": {"doc_id": "d3"}},
        ])
        pg = _make_pg_mock()
        job = EmbeddingMigrationJob(
            qdrant, pg, "old-model", "new-model",
            rate_limit_rps=1000,
        )

        result = await job.run(resume_from="p2")
        # fetch should have been called with start_after="p2"
        qdrant.fetch_points_by_model.assert_awaited_once_with(
            "incident_embeddings", "old-model", start_after="p2",
        )

    def test_migration_progress_dataclass(self):
        """MigrationProgress defaults are sensible."""
        p = MigrationProgress()
        assert p.status == "in_progress"
        assert p.points_migrated == 0

    def test_default_constants(self):
        """Default constants are correct."""
        assert DEFAULT_BATCH_SIZE == 100
        assert DEFAULT_RATE_LIMIT_RPS == 10.0
