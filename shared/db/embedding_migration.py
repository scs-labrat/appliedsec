"""Embedding migration orchestrator — REM-H03.

Manages dual-read/dual-write embedding migration when the embedding model
or dimensions change.  Supports:

1. **Dual-write**: new upserts write both old and new embeddings
2. **Dual-read**: searches query both versions and merge-deduplicate
3. **Backfill**: re-embeds existing vectors with the new model
4. **Cutover**: drops old-version vectors once backfill completes
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from shared.db.vector import (
    CURRENT_EMBEDDING_MODEL,
    CURRENT_EMBEDDING_VERSION,
    CURRENT_EMBEDDING_DIMENSIONS,
    QdrantWrapper,
    enrich_payload,
)

logger = logging.getLogger(__name__)


class MigrationPhase(str, Enum):
    NOT_STARTED = "not_started"
    DUAL_WRITE = "dual_write"
    BACKFILLING = "backfilling"
    DUAL_READ = "dual_read"
    CUTOVER = "cutover"
    COMPLETED = "completed"


@dataclass
class MigrationState:
    """Tracks progress of an embedding migration."""

    migration_id: str
    collection: str
    source_version: str
    target_version: str
    target_model: str = CURRENT_EMBEDDING_MODEL
    target_dimensions: int = CURRENT_EMBEDDING_DIMENSIONS
    phase: MigrationPhase = MigrationPhase.NOT_STARTED
    total_vectors: int = 0
    migrated_vectors: int = 0
    failed_vectors: int = 0
    started_at: str = ""
    completed_at: str = ""

    @property
    def progress_pct(self) -> float:
        if self.total_vectors == 0:
            return 0.0
        return round(self.migrated_vectors / self.total_vectors * 100, 2)

    @property
    def is_active(self) -> bool:
        return self.phase in (
            MigrationPhase.DUAL_WRITE,
            MigrationPhase.BACKFILLING,
            MigrationPhase.DUAL_READ,
        )


# Type alias for an embedding function: text → vector
EmbedFn = Callable[[str], list[float]]


class EmbeddingMigrationOrchestrator:
    """Orchestrates embedding version migrations with zero-downtime.

    Usage::

        orch = EmbeddingMigrationOrchestrator(qdrant, embed_fn)
        state = orch.start_migration("incident_embeddings", "2025-06", "2026-01")

        # Phase 1: dual-write (new upserts go to both versions)
        orch.dual_write(collection, point_id, text, old_vector, payload)

        # Phase 2: backfill existing vectors
        await orch.backfill(state, batch_size=50)

        # Phase 3: dual-read is automatic via search_with_version_merge()

        # Phase 4: cutover — delete old-version vectors
        orch.cutover(state)
    """

    def __init__(
        self,
        qdrant: QdrantWrapper,
        embed_fn: EmbedFn,
    ) -> None:
        self._qdrant = qdrant
        self._embed_fn = embed_fn
        self._migrations: dict[str, MigrationState] = {}

    def start_migration(
        self,
        collection: str,
        source_version: str,
        target_version: str,
        target_model: str = CURRENT_EMBEDDING_MODEL,
        target_dimensions: int = CURRENT_EMBEDDING_DIMENSIONS,
    ) -> MigrationState:
        """Begin a new migration. Transitions to DUAL_WRITE phase."""
        migration_id = f"{collection}:{source_version}->{target_version}"
        state = MigrationState(
            migration_id=migration_id,
            collection=collection,
            source_version=source_version,
            target_version=target_version,
            target_model=target_model,
            target_dimensions=target_dimensions,
            phase=MigrationPhase.DUAL_WRITE,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self._migrations[migration_id] = state
        logger.info("Started embedding migration %s", migration_id)
        return state

    def dual_write(
        self,
        collection: str,
        point_id: str | int,
        text: str,
        old_vector: list[float],
        payload: dict[str, Any],
    ) -> None:
        """Write both old and new embedding versions for a single point.

        Call this for every new upsert during the DUAL_WRITE and
        BACKFILLING phases.
        """
        # Write old version (preserves existing payload metadata)
        old_payload = dict(payload)
        self._qdrant.upsert_vectors(
            collection,
            [{"id": point_id, "vector": old_vector, "payload": old_payload}],
        )

        # Compute new embedding and write with updated metadata
        new_vector = self._embed_fn(text)
        new_payload = dict(payload)
        new_payload["embedding_model_id"] = CURRENT_EMBEDDING_MODEL
        new_payload["embedding_dimensions"] = CURRENT_EMBEDDING_DIMENSIONS
        new_payload["embedding_version"] = CURRENT_EMBEDDING_VERSION
        # Use a distinct point ID for the new version
        new_id = f"{point_id}_v{CURRENT_EMBEDDING_VERSION}"
        self._qdrant.upsert_vectors(
            collection,
            [{"id": new_id, "vector": new_vector, "payload": new_payload}],
        )

    def backfill(
        self,
        state: MigrationState,
        source_points: list[dict[str, Any]],
        batch_size: int = 50,
    ) -> MigrationState:
        """Re-embed a batch of existing vectors with the new model.

        Parameters
        ----------
        state:
            The migration state to update.
        source_points:
            Points to re-embed. Each must have keys: id, payload.
            payload must include a ``text`` or ``doc_text`` field.
        batch_size:
            Number of points to process per Qdrant upsert call.
        """
        state.phase = MigrationPhase.BACKFILLING
        state.total_vectors = max(state.total_vectors, len(source_points))

        new_points: list[dict[str, Any]] = []
        for point in source_points:
            text = point.get("payload", {}).get("text", "") or point.get("payload", {}).get("doc_text", "")
            if not text:
                state.failed_vectors += 1
                continue

            try:
                new_vector = self._embed_fn(text)
            except Exception:
                logger.warning("Failed to embed point %s", point.get("id"))
                state.failed_vectors += 1
                continue

            new_payload = dict(point.get("payload", {}))
            new_payload["embedding_model_id"] = state.target_model
            new_payload["embedding_dimensions"] = state.target_dimensions
            new_payload["embedding_version"] = state.target_version

            new_points.append({
                "id": f"{point['id']}_v{state.target_version}",
                "vector": new_vector,
                "payload": new_payload,
            })

            if len(new_points) >= batch_size:
                self._qdrant.upsert_vectors(
                    state.collection, new_points, enforce_metadata=True,
                )
                state.migrated_vectors += len(new_points)
                new_points = []

        # Flush remaining
        if new_points:
            self._qdrant.upsert_vectors(
                state.collection, new_points, enforce_metadata=True,
            )
            state.migrated_vectors += len(new_points)

        logger.info(
            "Backfill progress for %s: %d/%d (%.1f%%)",
            state.migration_id, state.migrated_vectors,
            state.total_vectors, state.progress_pct,
        )

        # Auto-transition to DUAL_READ once backfill covers all points
        if state.migrated_vectors >= state.total_vectors - state.failed_vectors:
            state.phase = MigrationPhase.DUAL_READ
            logger.info("Migration %s entering DUAL_READ phase", state.migration_id)

        return state

    def cutover(self, state: MigrationState) -> MigrationState:
        """Finalize migration: mark as completed.

        In production, this would also delete old-version vectors.
        For safety, we only mark the phase — actual deletion should be
        a separate, operator-confirmed step.
        """
        state.phase = MigrationPhase.CUTOVER
        state.completed_at = datetime.now(timezone.utc).isoformat()
        logger.info(
            "Migration %s cutover complete. Old vectors (%s) ready for cleanup.",
            state.migration_id, state.source_version,
        )
        state.phase = MigrationPhase.COMPLETED
        return state

    def get_migration(self, migration_id: str) -> MigrationState | None:
        return self._migrations.get(migration_id)

    def active_migrations(self) -> list[MigrationState]:
        return [m for m in self._migrations.values() if m.is_active]
