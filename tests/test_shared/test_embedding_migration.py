"""Tests for embedding migration orchestrator — REM-H03."""

import pytest
from unittest.mock import MagicMock, call

from shared.db.embedding_migration import (
    EmbeddingMigrationOrchestrator,
    MigrationPhase,
    MigrationState,
)


@pytest.fixture
def mock_qdrant():
    q = MagicMock()
    q.upsert_vectors = MagicMock()
    return q


@pytest.fixture
def embed_fn():
    """Mock embedding function returning a fixed-length vector."""
    return MagicMock(return_value=[0.1] * 1024)


@pytest.fixture
def orchestrator(mock_qdrant, embed_fn):
    return EmbeddingMigrationOrchestrator(mock_qdrant, embed_fn)


class TestMigrationLifecycle:
    def test_start_migration(self, orchestrator):
        state = orchestrator.start_migration(
            "incident_embeddings", "2025-06", "2026-01"
        )
        assert state.phase == MigrationPhase.DUAL_WRITE
        assert state.source_version == "2025-06"
        assert state.target_version == "2026-01"
        assert state.started_at != ""

    def test_migration_id_format(self, orchestrator):
        state = orchestrator.start_migration(
            "technique_embeddings", "2025-06", "2026-01"
        )
        assert state.migration_id == "technique_embeddings:2025-06->2026-01"

    def test_get_migration(self, orchestrator):
        state = orchestrator.start_migration(
            "incident_embeddings", "2025-06", "2026-01"
        )
        found = orchestrator.get_migration(state.migration_id)
        assert found is state

    def test_active_migrations(self, orchestrator):
        orchestrator.start_migration("incident_embeddings", "2025-06", "2026-01")
        assert len(orchestrator.active_migrations()) == 1

    def test_completed_migration_not_active(self, orchestrator):
        state = orchestrator.start_migration(
            "incident_embeddings", "2025-06", "2026-01"
        )
        orchestrator.cutover(state)
        assert len(orchestrator.active_migrations()) == 0


class TestDualWrite:
    def test_writes_both_versions(self, orchestrator, mock_qdrant, embed_fn):
        orchestrator.start_migration("coll", "2025-06", "2026-01")
        orchestrator.dual_write(
            "coll", "point-1", "some text", [0.5] * 1024, {"doc_id": "d1"}
        )
        # Two upsert calls: old vector + new vector
        assert mock_qdrant.upsert_vectors.call_count == 2
        embed_fn.assert_called_once_with("some text")


class TestBackfill:
    def test_backfill_processes_points(self, orchestrator, mock_qdrant, embed_fn):
        state = orchestrator.start_migration("coll", "2025-06", "2026-01")
        points = [
            {"id": f"p{i}", "payload": {"text": f"doc {i}", "doc_id": f"d{i}"}}
            for i in range(5)
        ]
        state = orchestrator.backfill(state, points)
        assert state.migrated_vectors == 5
        assert state.phase == MigrationPhase.DUAL_READ  # auto-transition

    def test_backfill_skips_missing_text(self, orchestrator, mock_qdrant):
        state = orchestrator.start_migration("coll", "2025-06", "2026-01")
        points = [{"id": "p1", "payload": {"doc_id": "d1"}}]  # no text
        state = orchestrator.backfill(state, points)
        assert state.failed_vectors == 1
        assert state.migrated_vectors == 0

    def test_backfill_handles_embed_failure(self, orchestrator, mock_qdrant, embed_fn):
        embed_fn.side_effect = RuntimeError("model unavailable")
        state = orchestrator.start_migration("coll", "2025-06", "2026-01")
        points = [{"id": "p1", "payload": {"text": "hello", "doc_id": "d1"}}]
        state = orchestrator.backfill(state, points)
        assert state.failed_vectors == 1

    def test_progress_percentage(self, orchestrator, mock_qdrant):
        state = orchestrator.start_migration("coll", "2025-06", "2026-01")
        points = [
            {"id": f"p{i}", "payload": {"text": f"doc {i}"}}
            for i in range(10)
        ]
        state = orchestrator.backfill(state, points[:5])
        # 5 migrated out of 5 total (first batch)
        assert state.progress_pct == 100.0


class TestCutover:
    def test_cutover_marks_completed(self, orchestrator):
        state = orchestrator.start_migration("coll", "2025-06", "2026-01")
        state = orchestrator.cutover(state)
        assert state.phase == MigrationPhase.COMPLETED
        assert state.completed_at != ""

    def test_cutover_from_dual_read(self, orchestrator, mock_qdrant):
        state = orchestrator.start_migration("coll", "2025-06", "2026-01")
        points = [{"id": "p1", "payload": {"text": "hello"}}]
        state = orchestrator.backfill(state, points)
        assert state.phase == MigrationPhase.DUAL_READ
        state = orchestrator.cutover(state)
        assert state.phase == MigrationPhase.COMPLETED
