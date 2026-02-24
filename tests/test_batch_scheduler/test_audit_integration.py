"""Tests for AuditProducer integration in Batch Scheduler — Story 13.8, Task 6.3."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from batch_scheduler.processor import BatchResultProcessor
from batch_scheduler.models import BatchJob, BatchTask, BatchTaskType


def _make_job(task_type: str, content: str) -> BatchJob:
    """Create a minimal BatchJob with one successful result."""
    task = MagicMock(spec=BatchTask)
    task.task_type = task_type
    task.metadata = {"task_type": task_type, "source_investigations": ["inv-1"]}

    job = MagicMock(spec=BatchJob)
    job.job_id = "job-1"
    job.task_count = 1
    job.success_count = 1
    job.error_count = 0
    job.tasks = [task]
    job.results = [{"status": "success", "valid": True, "content": content, "request_id": "r1"}]
    return job


class TestBatchSchedulerAudit:
    """playbook.generated and fp_pattern.created emitted after batch processing."""

    @pytest.mark.asyncio
    async def test_fp_pattern_created_emitted(self):
        """After FP pattern is stored, fp_pattern.created is emitted."""
        audit = MagicMock()
        db = AsyncMock()
        db.execute = AsyncMock()
        producer = AsyncMock()
        producer.produce = AsyncMock()

        processor = BatchResultProcessor(
            postgres_client=db, kafka_producer=producer, audit_producer=audit,
        )

        content = json.dumps({
            "alert_name": "Test Alert",
            "alert_name_regex": "Test.*",
            "entity_patterns": [],
            "confidence": 0.85,
        })
        job = _make_job(BatchTaskType.FP_PATTERN_GENERATION.value, content)

        await processor.process_job(job)

        fp_calls = [c for c in audit.emit.call_args_list
                    if c[1].get("event_type") == "fp_pattern.created"]
        assert len(fp_calls) == 1

    @pytest.mark.asyncio
    async def test_playbook_generated_emitted(self):
        """After playbook draft is published, playbook.generated is emitted."""
        audit = MagicMock()
        db = AsyncMock()
        producer = AsyncMock()
        producer.produce = AsyncMock()

        processor = BatchResultProcessor(
            postgres_client=db, kafka_producer=producer, audit_producer=audit,
        )

        content = json.dumps({
            "name": "Brute Force Playbook",
            "description": "Steps for brute force response",
            "tactics": ["TA0006"],
            "techniques": ["T1110"],
            "remediation_steps": ["Block IP", "Reset password"],
        })
        job = _make_job(BatchTaskType.PLAYBOOK_GENERATION.value, content)

        await processor.process_job(job)

        pb_calls = [c for c in audit.emit.call_args_list
                    if c[1].get("event_type") == "playbook.generated"]
        assert len(pb_calls) == 1

    @pytest.mark.asyncio
    async def test_no_exception_when_audit_producer_is_none(self):
        """Backward compat: works without audit_producer."""
        db = AsyncMock()
        db.execute = AsyncMock()
        producer = AsyncMock()
        producer.produce = AsyncMock()

        processor = BatchResultProcessor(postgres_client=db, kafka_producer=producer)

        content = json.dumps({"alert_name": "X", "confidence": 0.5})
        job = _make_job(BatchTaskType.FP_PATTERN_GENERATION.value, content)

        summary = await processor.process_job(job)
        assert summary["fp_patterns_stored"] == 1
