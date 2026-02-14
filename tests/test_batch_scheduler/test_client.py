"""Tests for batch_scheduler.client — Story 10.1."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from batch_scheduler.client import (
    AluskortBatchClient,
    BatchSLAExceeded,
    DEFAULT_POLL_INTERVAL_SECONDS,
)
from batch_scheduler.models import BatchJob, BatchJobStatus, BatchTask


def _client(*, poll_interval=300, validator=None):
    """Build an AluskortBatchClient with mocked Anthropic client."""
    anthropic = AsyncMock()
    anthropic.batches = AsyncMock()
    return AluskortBatchClient(
        anthropic_client=anthropic,
        output_validator=validator,
        poll_interval_seconds=poll_interval,
    ), anthropic


def _tasks(n=3):
    return [BatchTask(task_id=f"t-{i}", task_type="test") for i in range(n)]


# ── Construction ──────────────────────────────────────────────────

class TestConstruction:
    def test_default_poll_interval(self):
        client, _ = _client()
        assert client.poll_interval == DEFAULT_POLL_INTERVAL_SECONDS

    def test_custom_poll_interval(self):
        client, _ = _client(poll_interval=60)
        assert client.poll_interval == 60


# ── submit ────────────────────────────────────────────────────────

class TestSubmit:
    @pytest.mark.asyncio
    async def test_submit_success(self):
        client, anthropic = _client()
        anthropic.batches.create = AsyncMock(return_value={"id": "batch-abc"})
        job = await client.submit(_tasks(3))
        assert job.status == BatchJobStatus.SUBMITTED
        assert job.batch_api_id == "batch-abc"
        assert len(job.tasks) == 3
        assert job.submitted_at != ""

    @pytest.mark.asyncio
    async def test_submit_empty_raises(self):
        client, _ = _client()
        with pytest.raises(ValueError, match="empty"):
            await client.submit([])

    @pytest.mark.asyncio
    async def test_submit_exceeds_max_raises(self):
        client, _ = _client()
        tasks = _tasks(10_001)
        with pytest.raises(ValueError, match="exceeds maximum"):
            await client.submit(tasks)

    @pytest.mark.asyncio
    async def test_submit_api_failure(self):
        client, anthropic = _client()
        anthropic.batches.create = AsyncMock(side_effect=RuntimeError("api down"))
        job = await client.submit(_tasks(2))
        assert job.status == BatchJobStatus.FAILED

    @pytest.mark.asyncio
    async def test_task_to_request_format(self):
        client, anthropic = _client()
        anthropic.batches.create = AsyncMock(return_value={"id": "b-1"})
        tasks = [BatchTask(
            task_id="t-1",
            system_prompt="sys",
            user_content="usr",
            model_id="claude-sonnet-4-5-20250929",
            max_tokens=4096,
        )]
        await client.submit(tasks)
        call_args = anthropic.batches.create.call_args
        requests = call_args[1]["requests"]
        assert requests[0]["custom_id"] == "t-1"
        assert requests[0]["params"]["model"] == "claude-sonnet-4-5-20250929"
        assert requests[0]["params"]["max_tokens"] == 4096


# ── poll_status ───────────────────────────────────────────────────

class TestPollStatus:
    @pytest.mark.asyncio
    async def test_poll_completed(self):
        client, anthropic = _client()
        anthropic.batches.retrieve = AsyncMock(
            return_value={"processing_status": "ended"}
        )
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.SUBMITTED,
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
        job = await client.poll_status(job)
        assert job.status == BatchJobStatus.COMPLETED
        assert job.completed_at != ""

    @pytest.mark.asyncio
    async def test_poll_in_progress(self):
        client, anthropic = _client()
        anthropic.batches.retrieve = AsyncMock(
            return_value={"processing_status": "in_progress"}
        )
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.SUBMITTED,
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
        job = await client.poll_status(job)
        assert job.status == BatchJobStatus.IN_PROGRESS

    @pytest.mark.asyncio
    async def test_poll_failed(self):
        client, anthropic = _client()
        anthropic.batches.retrieve = AsyncMock(
            return_value={"processing_status": "failed"}
        )
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.SUBMITTED,
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
        job = await client.poll_status(job)
        assert job.status == BatchJobStatus.FAILED

    @pytest.mark.asyncio
    async def test_poll_sla_exceeded(self):
        client, _ = _client()
        expired_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.SUBMITTED,
            submitted_at=expired_time,
        )
        with pytest.raises(BatchSLAExceeded):
            await client.poll_status(job)
        assert job.status == BatchJobStatus.EXPIRED

    @pytest.mark.asyncio
    async def test_poll_no_api_id(self):
        client, _ = _client()
        job = BatchJob(status=BatchJobStatus.PENDING)
        result = await client.poll_status(job)
        assert result.status == BatchJobStatus.PENDING

    @pytest.mark.asyncio
    async def test_poll_api_error(self):
        client, anthropic = _client()
        anthropic.batches.retrieve = AsyncMock(side_effect=RuntimeError("timeout"))
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.SUBMITTED,
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
        result = await client.poll_status(job)
        assert result.status == BatchJobStatus.SUBMITTED


# ── retrieve_results ──────────────────────────────────────────────

class TestRetrieveResults:
    @pytest.mark.asyncio
    async def test_retrieve_success(self):
        client, anthropic = _client()
        anthropic.batches.results = AsyncMock(return_value=[
            {
                "custom_id": "t-1",
                "result": {
                    "type": "succeeded",
                    "message": {"content": [{"type": "text", "text": '{"key": "val"}'}]},
                },
            },
        ])
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.COMPLETED,
            tasks=[BatchTask(task_id="t-1")],
        )
        job = await client.retrieve_results(job)
        assert job.success_count == 1
        assert job.error_count == 0
        assert len(job.results) == 1
        assert job.results[0]["status"] == "success"
        assert job.results[0]["content"] == '{"key": "val"}'

    @pytest.mark.asyncio
    async def test_retrieve_with_error(self):
        client, anthropic = _client()
        anthropic.batches.results = AsyncMock(return_value=[
            {
                "custom_id": "t-1",
                "result": {
                    "type": "errored",
                    "error": {"message": "rate limited"},
                },
            },
        ])
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.COMPLETED,
            tasks=[BatchTask(task_id="t-1")],
        )
        job = await client.retrieve_results(job)
        assert job.success_count == 0
        assert job.error_count == 1
        assert job.results[0]["status"] == "error"

    @pytest.mark.asyncio
    async def test_retrieve_with_validator(self):
        validator = MagicMock(return_value=(True, [], []))
        client, anthropic = _client(validator=validator)
        anthropic.batches.results = AsyncMock(return_value=[
            {
                "custom_id": "t-1",
                "result": {
                    "type": "succeeded",
                    "message": {"content": [{"type": "text", "text": "output"}]},
                },
            },
        ])
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.COMPLETED,
            tasks=[BatchTask(task_id="t-1")],
        )
        job = await client.retrieve_results(job)
        validator.assert_called_once_with("output")
        assert job.results[0]["valid"] is True

    @pytest.mark.asyncio
    async def test_retrieve_validator_fails(self):
        validator = MagicMock(return_value=(False, ["bad output"], []))
        client, anthropic = _client(validator=validator)
        anthropic.batches.results = AsyncMock(return_value=[
            {
                "custom_id": "t-1",
                "result": {
                    "type": "succeeded",
                    "message": {"content": [{"type": "text", "text": "bad"}]},
                },
            },
        ])
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.COMPLETED,
            tasks=[BatchTask(task_id="t-1")],
        )
        job = await client.retrieve_results(job)
        assert job.results[0]["valid"] is False
        assert "bad output" in job.results[0]["validation_errors"]

    @pytest.mark.asyncio
    async def test_retrieve_not_completed_noop(self):
        client, _ = _client()
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.IN_PROGRESS,
        )
        result = await client.retrieve_results(job)
        assert result.results == []

    @pytest.mark.asyncio
    async def test_retrieve_api_failure(self):
        client, anthropic = _client()
        anthropic.batches.results = AsyncMock(side_effect=RuntimeError("fail"))
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.COMPLETED,
        )
        job = await client.retrieve_results(job)
        assert job.status == BatchJobStatus.FAILED

    @pytest.mark.asyncio
    async def test_retrieve_mixed_results(self):
        client, anthropic = _client()
        anthropic.batches.results = AsyncMock(return_value=[
            {
                "custom_id": "t-1",
                "result": {
                    "type": "succeeded",
                    "message": {"content": [{"type": "text", "text": "ok"}]},
                },
            },
            {
                "custom_id": "t-2",
                "result": {
                    "type": "errored",
                    "error": {"message": "fail"},
                },
            },
            {
                "custom_id": "t-3",
                "result": {
                    "type": "succeeded",
                    "message": {"content": [{"type": "text", "text": "ok2"}]},
                },
            },
        ])
        job = BatchJob(
            batch_api_id="b-1",
            status=BatchJobStatus.COMPLETED,
            tasks=[BatchTask(task_id=f"t-{i}") for i in range(1, 4)],
        )
        job = await client.retrieve_results(job)
        assert job.success_count == 2
        assert job.error_count == 1
