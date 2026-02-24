"""Batch Result Processor — Story 10.3.

Routes completed batch results to the appropriate storage:
- FP patterns → Postgres fp_patterns table + Kafka knowledge.fp.approved
- Playbook drafts → Kafka playbooks.draft topic
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from batch_scheduler.models import (
    BatchJob,
    BatchTaskType,
    FPPattern,
    FPPatternStatus,
    PlaybookDraft,
)

logger = logging.getLogger(__name__)

FP_APPROVED_TOPIC = "knowledge.fp.approved"
PLAYBOOK_DRAFT_TOPIC = "playbooks.draft"
AUDIT_TOPIC = "audit.events"


class BatchResultProcessor:
    """Processes completed batch results and routes to storage."""

    def __init__(
        self,
        postgres_client: Any,
        kafka_producer: Any | None = None,
        redis_client: Any | None = None,
        audit_producer: Any | None = None,
    ) -> None:
        self._db = postgres_client
        self._producer = kafka_producer
        self._redis = redis_client
        self._audit = audit_producer

    async def process_job(self, job: BatchJob) -> dict[str, int]:
        """Process all results in a completed batch job.

        Returns a summary dict with counts for each outcome.
        """
        summary: dict[str, int] = {
            "fp_patterns_stored": 0,
            "playbooks_published": 0,
            "errors": 0,
        }

        for i, result in enumerate(job.results):
            if result.get("status") != "success" or not result.get("valid", False):
                summary["errors"] += 1
                continue

            # Determine task type from corresponding task
            task = job.tasks[i] if i < len(job.tasks) else None
            if task is None:
                summary["errors"] += 1
                continue

            task_type = task.metadata.get("task_type", task.task_type)

            try:
                if task_type == BatchTaskType.FP_PATTERN_GENERATION.value:
                    pattern = self._parse_fp_pattern(result["content"], task)
                    await self._store_fp_pattern(pattern)
                    self._emit_audit("fp_pattern.created", {
                        "pattern_id": pattern.pattern_id,
                        "alert_name": pattern.alert_name,
                    })
                    summary["fp_patterns_stored"] += 1

                elif task_type == BatchTaskType.PLAYBOOK_GENERATION.value:
                    draft = self._parse_playbook_draft(result["content"], task)
                    await self._publish_playbook(draft)
                    self._emit_audit("playbook.generated", {
                        "playbook_id": draft.playbook_id,
                        "name": draft.name,
                    })
                    summary["playbooks_published"] += 1
                else:
                    logger.warning("Unknown task type: %s", task_type)
                    summary["errors"] += 1

            except Exception as exc:
                logger.error(
                    "Failed to process result %s: %s",
                    result.get("request_id", i), exc,
                )
                summary["errors"] += 1

        await self._publish_audit(job, summary)
        return summary

    def _parse_fp_pattern(self, content: str, task: Any) -> FPPattern:
        """Parse LLM output into an FPPattern."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = {}

        investigations = task.metadata.get("source_investigations", [])
        return FPPattern(
            alert_name=data.get("alert_name", ""),
            alert_name_regex=data.get("alert_name_regex", ""),
            entity_patterns=data.get("entity_patterns", []),
            severity=data.get("severity", ""),
            confidence=data.get("confidence", 0.0),
            status=FPPatternStatus.PENDING_REVIEW.value,
            reason=data.get("reason", "Auto-generated from closed investigations"),
            source_investigations=investigations,
        )

    def _parse_playbook_draft(self, content: str, task: Any) -> PlaybookDraft:
        """Parse LLM output into a PlaybookDraft."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = {}

        investigations = task.metadata.get("source_investigations", [])
        return PlaybookDraft(
            name=data.get("name", "Untitled Playbook"),
            description=data.get("description", ""),
            tactics=data.get("tactics", []),
            techniques=data.get("techniques", []),
            remediation_steps=data.get("remediation_steps", []),
            confidence=data.get("confidence", 0.0),
            source_investigations=investigations,
        )

    async def _store_fp_pattern(self, pattern: FPPattern) -> None:
        """Store FP pattern in Postgres with pending_review status."""
        await self._db.execute(
            """
            INSERT INTO fp_patterns
                (pattern_id, alert_name, alert_name_regex, entity_patterns,
                 severity, confidence, status, reason,
                 source_investigations, created_at, updated_at)
            VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9::jsonb, $10, $11)
            ON CONFLICT (pattern_id) DO UPDATE SET
                alert_name = $2,
                alert_name_regex = $3,
                entity_patterns = $4::jsonb,
                confidence = $6,
                updated_at = $11
            """,
            pattern.pattern_id,
            pattern.alert_name,
            pattern.alert_name_regex,
            json.dumps(pattern.entity_patterns),
            pattern.severity,
            pattern.confidence,
            pattern.status,
            pattern.reason,
            json.dumps(pattern.source_investigations),
            pattern.created_at,
            pattern.updated_at,
        )
        logger.info("Stored FP pattern %s (status=%s)", pattern.pattern_id, pattern.status)

    async def approve_fp_pattern(
        self,
        pattern_id: str,
        approved_by: str,
        tenant_id: str = "default",
    ) -> None:
        """Approve an FP pattern and push to Redis hot cache + Kafka."""
        now = datetime.now(timezone.utc).isoformat()
        await self._db.execute(
            """
            UPDATE fp_patterns
            SET status = $1, approved_by = $2, approval_date = $3, updated_at = $3
            WHERE pattern_id = $4
            """,
            FPPatternStatus.APPROVED.value,
            approved_by,
            now,
            pattern_id,
        )

        # Load pattern for cache + publish
        row = await self._db.fetch_one(
            "SELECT * FROM fp_patterns WHERE pattern_id = $1",
            pattern_id,
        )
        if row and self._redis:
            cache_entry = {
                "alert_name_regex": row.get("alert_name_regex", ""),
                "entity_patterns": row.get("entity_patterns", []),
                "confidence": row.get("confidence", 0.0),
                "status": "approved",
            }
            await self._redis.set_fp_pattern(tenant_id, pattern_id, cache_entry)
            logger.info("FP pattern %s pushed to Redis hot cache", pattern_id)

        if row and self._producer:
            await self._producer.produce(FP_APPROVED_TOPIC, row)

    async def _publish_playbook(self, draft: PlaybookDraft) -> None:
        """Publish playbook draft to Kafka for analyst review."""
        if self._producer is None:
            return
        payload = {
            "playbook_id": draft.playbook_id,
            "name": draft.name,
            "description": draft.description,
            "tactics": draft.tactics,
            "techniques": draft.techniques,
            "remediation_steps": draft.remediation_steps,
            "confidence": draft.confidence,
            "source_investigations": draft.source_investigations,
            "status": draft.status,
            "created_at": draft.created_at,
        }
        try:
            await self._producer.produce(PLAYBOOK_DRAFT_TOPIC, payload)
            logger.info("Published playbook draft %s", draft.playbook_id)
        except Exception:
            logger.warning(
                "Failed to publish playbook %s", draft.playbook_id, exc_info=True,
            )

    def _emit_audit(self, event_type: str, context: dict[str, Any]) -> None:
        """Emit audit event via AuditProducer (fire-and-forget)."""
        if self._audit is None:
            return
        try:
            self._audit.emit(
                tenant_id="system",
                event_type=event_type,
                event_category="action",
                actor_type="system",
                actor_id="batch-scheduler",
                context=context,
            )
        except Exception:
            logger.warning("Audit emit failed for %s", event_type, exc_info=True)

    async def _publish_audit(
        self, job: BatchJob, summary: dict[str, int]
    ) -> None:
        """Publish batch processing audit event."""
        if self._producer is None:
            return
        event = {
            "event_type": "batch_processing_complete",
            "job_id": job.job_id,
            "task_count": job.task_count,
            "success_count": job.success_count,
            "error_count": job.error_count,
            "summary": summary,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            await self._producer.produce(AUDIT_TOPIC, event)
        except Exception:
            logger.warning("Failed to publish audit event for %s", job.job_id)
