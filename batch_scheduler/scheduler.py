"""Batch Scheduler — Story 10.2.

Accumulates batch tasks and submits them when either the count
trigger (50 items) or time trigger (6 hours) fires first.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from batch_scheduler.client import AluskortBatchClient
from batch_scheduler.models import BatchJob, BatchJobStatus, BatchTask

logger = logging.getLogger(__name__)

DEFAULT_COUNT_THRESHOLD = 50
DEFAULT_TIME_THRESHOLD_HOURS = 6


class BatchScheduler:
    """Dual-trigger batch scheduler: time-based or count-based submission."""

    def __init__(
        self,
        client: AluskortBatchClient,
        count_threshold: int = DEFAULT_COUNT_THRESHOLD,
        time_threshold_hours: int = DEFAULT_TIME_THRESHOLD_HOURS,
    ) -> None:
        self._client = client
        self._count_threshold = count_threshold
        self._time_threshold = timedelta(hours=time_threshold_hours)
        self._queue: list[BatchTask] = []
        self._last_flush: datetime = datetime.now(timezone.utc)
        self._submitted_jobs: list[BatchJob] = []

    @property
    def queue_size(self) -> int:
        return len(self._queue)

    @property
    def submitted_jobs(self) -> list[BatchJob]:
        return list(self._submitted_jobs)

    @property
    def count_threshold(self) -> int:
        return self._count_threshold

    @property
    def time_threshold(self) -> timedelta:
        return self._time_threshold

    def enqueue(self, task: BatchTask) -> bool:
        """Add a task to the queue. Returns True if count trigger fires."""
        self._queue.append(task)
        return len(self._queue) >= self._count_threshold

    def enqueue_many(self, tasks: list[BatchTask]) -> bool:
        """Add multiple tasks. Returns True if count trigger fires."""
        self._queue.extend(tasks)
        return len(self._queue) >= self._count_threshold

    def should_flush_by_time(self, now: datetime | None = None) -> bool:
        """Check whether the time trigger has fired."""
        now = now or datetime.now(timezone.utc)
        return (now - self._last_flush) >= self._time_threshold

    def should_flush(self, now: datetime | None = None) -> bool:
        """Check whether any trigger condition is met."""
        if len(self._queue) == 0:
            return False
        if len(self._queue) >= self._count_threshold:
            return True
        return self.should_flush_by_time(now)

    async def flush(self) -> BatchJob | None:
        """Submit all queued tasks as a batch.

        Returns None if the queue is empty.
        """
        if not self._queue:
            return None

        tasks = list(self._queue)
        self._queue.clear()
        self._last_flush = datetime.now(timezone.utc)

        job = await self._client.submit(tasks)
        self._submitted_jobs.append(job)

        logger.info(
            "Flushed %d tasks → batch %s (status=%s)",
            len(tasks), job.job_id, job.status.value,
        )
        return job

    async def tick(self, now: datetime | None = None) -> BatchJob | None:
        """Called periodically — flushes if any trigger condition is met.

        This is the main entry point for the scheduler loop.
        """
        if self.should_flush(now):
            return await self.flush()
        return None

    async def poll_active_jobs(self) -> list[BatchJob]:
        """Poll all active (non-terminal) jobs for status updates."""
        updated: list[BatchJob] = []
        for job in self._submitted_jobs:
            if job.status in (
                BatchJobStatus.SUBMITTED,
                BatchJobStatus.IN_PROGRESS,
            ):
                try:
                    job = await self._client.poll_status(job)
                    updated.append(job)
                except Exception as exc:
                    logger.error("Poll failed for job %s: %s", job.job_id, exc)
        return updated

    def get_completed_jobs(self) -> list[BatchJob]:
        """Return all jobs that have completed and need result processing."""
        return [
            j for j in self._submitted_jobs
            if j.status == BatchJobStatus.COMPLETED and not j.results
        ]
