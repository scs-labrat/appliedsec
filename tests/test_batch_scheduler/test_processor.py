"""Tests for batch_scheduler.processor — Story 10.3."""

from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from batch_scheduler.models import (
    BatchJob,
    BatchJobStatus,
    BatchTask,
    BatchTaskType,
    FPPatternStatus,
)
from batch_scheduler.processor import (
    AUDIT_TOPIC,
    FP_APPROVED_TOPIC,
    PLAYBOOK_DRAFT_TOPIC,
    BatchResultProcessor,
)


def _processor(producer=True, redis=True):
    db = AsyncMock()
    kafka = AsyncMock() if producer else None
    red = AsyncMock() if redis else None
    return BatchResultProcessor(postgres_client=db, kafka_producer=kafka, redis_client=red), db, kafka, red


def _fp_task(task_id="t-1"):
    return BatchTask(
        task_id=task_id,
        task_type=BatchTaskType.FP_PATTERN_GENERATION.value,
        metadata={
            "task_type": BatchTaskType.FP_PATTERN_GENERATION.value,
            "source_investigations": ["inv-1", "inv-2"],
        },
    )


def _playbook_task(task_id="t-2"):
    return BatchTask(
        task_id=task_id,
        task_type=BatchTaskType.PLAYBOOK_GENERATION.value,
        metadata={
            "task_type": BatchTaskType.PLAYBOOK_GENERATION.value,
            "source_investigations": ["inv-3"],
        },
    )


def _fp_result():
    return json.dumps({
        "alert_name": "Test Alert",
        "alert_name_regex": "Test.*",
        "entity_patterns": [{"type": "ip", "value_regex": "10\\..*"}],
        "severity": "low",
        "confidence": 0.92,
        "reason": "Known benign traffic",
    })


def _playbook_result():
    return json.dumps({
        "name": "Phishing Response",
        "description": "Handle phishing",
        "tactics": ["Initial Access"],
        "techniques": ["T1566"],
        "remediation_steps": ["Block sender", "Reset creds"],
        "confidence": 0.85,
    })


# ── process_job — FP patterns ────────────────────────────────────

class TestProcessFPPatterns:
    @pytest.mark.asyncio
    async def test_stores_fp_pattern(self):
        proc, db, kafka, _ = _processor()
        job = BatchJob(
            status=BatchJobStatus.COMPLETED,
            tasks=[_fp_task()],
            results=[{"request_id": "t-1", "content": _fp_result(), "valid": True, "status": "success"}],
        )
        summary = await proc.process_job(job)
        assert summary["fp_patterns_stored"] == 1
        db.execute.assert_awaited()

    @pytest.mark.asyncio
    async def test_fp_pattern_stored_as_pending_review(self):
        proc, db, _, _ = _processor(producer=False)
        job = BatchJob(
            status=BatchJobStatus.COMPLETED,
            tasks=[_fp_task()],
            results=[{"request_id": "t-1", "content": _fp_result(), "valid": True, "status": "success"}],
        )
        await proc.process_job(job)
        call_args = db.execute.call_args_list[0]
        # $7 is the status parameter
        assert call_args[0][7] == FPPatternStatus.PENDING_REVIEW.value

    @pytest.mark.asyncio
    async def test_invalid_json_creates_empty_pattern(self):
        proc, db, _, _ = _processor(producer=False)
        job = BatchJob(
            status=BatchJobStatus.COMPLETED,
            tasks=[_fp_task()],
            results=[{"request_id": "t-1", "content": "not json", "valid": True, "status": "success"}],
        )
        summary = await proc.process_job(job)
        assert summary["fp_patterns_stored"] == 1


# ── process_job — playbooks ──────────────────────────────────────

class TestProcessPlaybooks:
    @pytest.mark.asyncio
    async def test_publishes_playbook(self):
        proc, _, kafka, _ = _processor()
        job = BatchJob(
            status=BatchJobStatus.COMPLETED,
            tasks=[_playbook_task()],
            results=[{"request_id": "t-2", "content": _playbook_result(), "valid": True, "status": "success"}],
        )
        summary = await proc.process_job(job)
        assert summary["playbooks_published"] == 1
        # Check published to correct topic
        produce_calls = [c for c in kafka.produce.call_args_list
                         if c[0][0] == PLAYBOOK_DRAFT_TOPIC]
        assert len(produce_calls) >= 1

    @pytest.mark.asyncio
    async def test_no_producer_skips_publish(self):
        proc, _, _, _ = _processor(producer=False)
        job = BatchJob(
            status=BatchJobStatus.COMPLETED,
            tasks=[_playbook_task()],
            results=[{"request_id": "t-2", "content": _playbook_result(), "valid": True, "status": "success"}],
        )
        summary = await proc.process_job(job)
        assert summary["playbooks_published"] == 1


# ── process_job — error handling ──────────────────────────────────

class TestProcessErrors:
    @pytest.mark.asyncio
    async def test_failed_results_counted(self):
        proc, _, _, _ = _processor()
        job = BatchJob(
            status=BatchJobStatus.COMPLETED,
            tasks=[_fp_task()],
            results=[{"request_id": "t-1", "content": "", "valid": False, "status": "error"}],
        )
        summary = await proc.process_job(job)
        assert summary["errors"] == 1
        assert summary["fp_patterns_stored"] == 0

    @pytest.mark.asyncio
    async def test_no_task_for_result(self):
        proc, _, _, _ = _processor()
        job = BatchJob(
            status=BatchJobStatus.COMPLETED,
            tasks=[],
            results=[{"request_id": "t-1", "content": "ok", "valid": True, "status": "success"}],
        )
        summary = await proc.process_job(job)
        assert summary["errors"] == 1

    @pytest.mark.asyncio
    async def test_mixed_results(self):
        proc, _, kafka, _ = _processor()
        job = BatchJob(
            status=BatchJobStatus.COMPLETED,
            tasks=[_fp_task("t-1"), _playbook_task("t-2"), _fp_task("t-3")],
            results=[
                {"request_id": "t-1", "content": _fp_result(), "valid": True, "status": "success"},
                {"request_id": "t-2", "content": _playbook_result(), "valid": True, "status": "success"},
                {"request_id": "t-3", "content": "", "valid": False, "status": "error"},
            ],
        )
        summary = await proc.process_job(job)
        assert summary["fp_patterns_stored"] == 1
        assert summary["playbooks_published"] == 1
        assert summary["errors"] == 1


# ── approve_fp_pattern ────────────────────────────────────────────

class TestApproveFPPattern:
    @pytest.mark.asyncio
    async def test_approve_updates_db(self):
        proc, db, kafka, redis = _processor()
        db.fetch_one = AsyncMock(return_value={
            "pattern_id": "fp-1",
            "alert_name_regex": "Test.*",
            "entity_patterns": [],
            "confidence": 0.92,
        })
        await proc.approve_fp_pattern("fp-1", "analyst-bob")
        # First call should be UPDATE
        update_call = db.execute.call_args_list[0]
        assert update_call[0][1] == FPPatternStatus.APPROVED.value
        assert update_call[0][2] == "analyst-bob"

    @pytest.mark.asyncio
    async def test_approve_pushes_to_redis(self):
        proc, db, kafka, redis = _processor()
        db.fetch_one = AsyncMock(return_value={
            "pattern_id": "fp-1",
            "alert_name_regex": "Test.*",
            "entity_patterns": [],
            "confidence": 0.92,
        })
        await proc.approve_fp_pattern("fp-1", "analyst-bob")
        redis.set_fp_pattern.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_approve_publishes_to_kafka(self):
        proc, db, kafka, redis = _processor()
        db.fetch_one = AsyncMock(return_value={
            "pattern_id": "fp-1",
            "alert_name_regex": "Test.*",
            "entity_patterns": [],
            "confidence": 0.92,
        })
        await proc.approve_fp_pattern("fp-1", "analyst-bob")
        produce_calls = [c for c in kafka.produce.call_args_list
                         if c[0][0] == FP_APPROVED_TOPIC]
        assert len(produce_calls) == 1

    @pytest.mark.asyncio
    async def test_approve_no_redis(self):
        proc, db, kafka, _ = _processor(redis=False)
        db.fetch_one = AsyncMock(return_value={
            "pattern_id": "fp-1",
            "alert_name_regex": "Test.*",
        })
        await proc.approve_fp_pattern("fp-1", "analyst")
        # Should not raise


# ── audit publishing ──────────────────────────────────────────────

class TestAuditPublishing:
    @pytest.mark.asyncio
    async def test_publishes_audit_event(self):
        proc, _, kafka, _ = _processor()
        job = BatchJob(
            status=BatchJobStatus.COMPLETED,
            tasks=[_fp_task()],
            results=[{"request_id": "t-1", "content": _fp_result(), "valid": True, "status": "success"}],
        )
        await proc.process_job(job)
        audit_calls = [c for c in kafka.produce.call_args_list
                       if c[0][0] == AUDIT_TOPIC]
        assert len(audit_calls) == 1
