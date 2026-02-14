"""Tests for batch_scheduler.scheduler — Story 10.2."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from batch_scheduler.client import AluskortBatchClient
from batch_scheduler.models import BatchJob, BatchJobStatus, BatchTask
from batch_scheduler.scheduler import (
    BatchScheduler,
    DEFAULT_COUNT_THRESHOLD,
    DEFAULT_TIME_THRESHOLD_HOURS,
)


def _scheduler(count=50, hours=6):
    client = AsyncMock(spec=AluskortBatchClient)
    client.submit = AsyncMock(
        return_value=BatchJob(batch_api_id="b-1", status=BatchJobStatus.SUBMITTED)
    )
    client.poll_status = AsyncMock(
        side_effect=lambda j: j
    )
    return BatchScheduler(client, count_threshold=count, time_threshold_hours=hours), client


def _task(task_id="t-1"):
    return BatchTask(task_id=task_id, task_type="test")


# ── Construction ──────────────────────────────────────────────────

class TestConstruction:
    def test_defaults(self):
        s, _ = _scheduler()
        assert s.count_threshold == DEFAULT_COUNT_THRESHOLD
        assert s.time_threshold == timedelta(hours=DEFAULT_TIME_THRESHOLD_HOURS)
        assert s.queue_size == 0
        assert s.submitted_jobs == []

    def test_custom_thresholds(self):
        s, _ = _scheduler(count=10, hours=2)
        assert s.count_threshold == 10
        assert s.time_threshold == timedelta(hours=2)


# ── enqueue ───────────────────────────────────────────────────────

class TestEnqueue:
    def test_enqueue_single(self):
        s, _ = _scheduler()
        triggered = s.enqueue(_task())
        assert s.queue_size == 1
        assert triggered is False

    def test_enqueue_reaches_threshold(self):
        s, _ = _scheduler(count=3)
        s.enqueue(_task("t-1"))
        s.enqueue(_task("t-2"))
        triggered = s.enqueue(_task("t-3"))
        assert triggered is True
        assert s.queue_size == 3

    def test_enqueue_many(self):
        s, _ = _scheduler(count=5)
        triggered = s.enqueue_many([_task(f"t-{i}") for i in range(5)])
        assert triggered is True
        assert s.queue_size == 5

    def test_enqueue_many_below_threshold(self):
        s, _ = _scheduler(count=10)
        triggered = s.enqueue_many([_task(f"t-{i}") for i in range(3)])
        assert triggered is False
        assert s.queue_size == 3


# ── should_flush ──────────────────────────────────────────────────

class TestShouldFlush:
    def test_empty_queue_never_flushes(self):
        s, _ = _scheduler()
        assert s.should_flush() is False

    def test_count_trigger(self):
        s, _ = _scheduler(count=2)
        s.enqueue_many([_task("t-1"), _task("t-2")])
        assert s.should_flush() is True

    def test_time_trigger(self):
        s, _ = _scheduler(hours=1)
        s.enqueue(_task())
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        assert s.should_flush(future) is True

    def test_not_yet_time(self):
        s, _ = _scheduler(hours=6)
        s.enqueue(_task())
        now = datetime.now(timezone.utc)
        assert s.should_flush(now) is False

    def test_time_trigger_method(self):
        s, _ = _scheduler(hours=1)
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        assert s.should_flush_by_time(future) is True


# ── flush ─────────────────────────────────────────────────────────

class TestFlush:
    @pytest.mark.asyncio
    async def test_flush_submits_and_clears(self):
        s, client = _scheduler()
        s.enqueue_many([_task(f"t-{i}") for i in range(3)])
        job = await s.flush()
        assert job is not None
        assert job.status == BatchJobStatus.SUBMITTED
        assert s.queue_size == 0
        client.submit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_flush_empty_returns_none(self):
        s, _ = _scheduler()
        job = await s.flush()
        assert job is None

    @pytest.mark.asyncio
    async def test_flush_tracks_submitted_jobs(self):
        s, _ = _scheduler()
        s.enqueue(_task())
        await s.flush()
        assert len(s.submitted_jobs) == 1

    @pytest.mark.asyncio
    async def test_flush_multiple_batches(self):
        s, _ = _scheduler()
        s.enqueue(_task("t-1"))
        await s.flush()
        s.enqueue(_task("t-2"))
        await s.flush()
        assert len(s.submitted_jobs) == 2


# ── tick ──────────────────────────────────────────────────────────

class TestTick:
    @pytest.mark.asyncio
    async def test_tick_flushes_on_count(self):
        s, _ = _scheduler(count=2)
        s.enqueue_many([_task("t-1"), _task("t-2")])
        job = await s.tick()
        assert job is not None
        assert s.queue_size == 0

    @pytest.mark.asyncio
    async def test_tick_flushes_on_time(self):
        s, _ = _scheduler(hours=1)
        s.enqueue(_task())
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        job = await s.tick(future)
        assert job is not None

    @pytest.mark.asyncio
    async def test_tick_no_flush(self):
        s, _ = _scheduler(count=100, hours=24)
        s.enqueue(_task())
        job = await s.tick()
        assert job is None
        assert s.queue_size == 1

    @pytest.mark.asyncio
    async def test_tick_empty_no_flush(self):
        s, _ = _scheduler()
        job = await s.tick()
        assert job is None


# ── poll_active_jobs ──────────────────────────────────────────────

class TestPollActiveJobs:
    @pytest.mark.asyncio
    async def test_polls_submitted_jobs(self):
        s, client = _scheduler()
        s.enqueue(_task())
        await s.flush()
        updated = await s.poll_active_jobs()
        assert len(updated) == 1
        client.poll_status.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_skips_completed_jobs(self):
        s, client = _scheduler()
        s._submitted_jobs.append(
            BatchJob(status=BatchJobStatus.COMPLETED)
        )
        updated = await s.poll_active_jobs()
        assert len(updated) == 0

    @pytest.mark.asyncio
    async def test_poll_error_handled(self):
        s, client = _scheduler()
        client.poll_status = AsyncMock(side_effect=RuntimeError("fail"))
        s.enqueue(_task())
        await s.flush()
        updated = await s.poll_active_jobs()
        assert len(updated) == 0


# ── get_completed_jobs ────────────────────────────────────────────

class TestGetCompletedJobs:
    def test_returns_completed_without_results(self):
        s, _ = _scheduler()
        s._submitted_jobs.append(
            BatchJob(status=BatchJobStatus.COMPLETED)
        )
        completed = s.get_completed_jobs()
        assert len(completed) == 1

    def test_excludes_completed_with_results(self):
        s, _ = _scheduler()
        j = BatchJob(status=BatchJobStatus.COMPLETED)
        j.results = [{"status": "success"}]
        s._submitted_jobs.append(j)
        completed = s.get_completed_jobs()
        assert len(completed) == 0

    def test_excludes_non_completed(self):
        s, _ = _scheduler()
        s._submitted_jobs.append(BatchJob(status=BatchJobStatus.IN_PROGRESS))
        completed = s.get_completed_jobs()
        assert len(completed) == 0
