"""Anthropic Batch API client — Story 10.1.

Submits batch requests, polls for completion, and processes results.
Uses the Anthropic Batch API for 50% cost discount on Tier 2 tasks.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from batch_scheduler.models import (
    BATCH_SLA_HOURS,
    MAX_BATCH_SIZE,
    BatchJob,
    BatchJobStatus,
    BatchTask,
)

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL_SECONDS = 300  # 5 minutes


class BatchSLAExceeded(Exception):
    """Raised when a batch exceeds the 24-hour SLA."""


class AluskortBatchClient:
    """Wrapper around the Anthropic Batch API.

    Submits batch tasks, polls for completion, and returns parsed results.
    Each result is validated through the output validator.
    """

    def __init__(
        self,
        anthropic_client: Any,
        output_validator: Any | None = None,
        poll_interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS,
    ) -> None:
        self._client = anthropic_client
        self._validator = output_validator
        self._poll_interval = poll_interval_seconds

    @property
    def poll_interval(self) -> int:
        return self._poll_interval

    async def submit(self, tasks: list[BatchTask]) -> BatchJob:
        """Submit a list of tasks as a batch to the Anthropic Batch API.

        Raises ValueError if tasks exceed MAX_BATCH_SIZE.
        """
        if not tasks:
            raise ValueError("Cannot submit empty batch")
        if len(tasks) > MAX_BATCH_SIZE:
            raise ValueError(
                f"Batch size {len(tasks)} exceeds maximum {MAX_BATCH_SIZE}"
            )

        requests = [self._task_to_request(t) for t in tasks]

        try:
            response = await self._client.batches.create(requests=requests)
        except Exception as exc:
            logger.error("Batch submission failed: %s", exc)
            job = BatchJob(tasks=tasks, status=BatchJobStatus.FAILED)
            return job

        job = BatchJob(
            batch_api_id=response.get("id", ""),
            tasks=tasks,
            status=BatchJobStatus.SUBMITTED,
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
        logger.info(
            "Batch %s submitted with %d tasks (api_id=%s)",
            job.job_id, len(tasks), job.batch_api_id,
        )
        return job

    async def poll_status(self, job: BatchJob) -> BatchJob:
        """Check the current status of a submitted batch job.

        Updates the job status and returns it. Raises BatchSLAExceeded
        if the 24-hour SLA has been breached.
        """
        if not job.batch_api_id:
            return job

        # SLA check
        if job.submitted_at:
            submitted = datetime.fromisoformat(job.submitted_at)
            elapsed = datetime.now(timezone.utc) - submitted
            if elapsed > timedelta(hours=BATCH_SLA_HOURS):
                job.status = BatchJobStatus.EXPIRED
                raise BatchSLAExceeded(
                    f"Batch {job.job_id} exceeded {BATCH_SLA_HOURS}h SLA "
                    f"(elapsed: {elapsed})"
                )

        try:
            status_response = await self._client.batches.retrieve(job.batch_api_id)
        except Exception as exc:
            logger.error("Failed to poll batch %s: %s", job.batch_api_id, exc)
            return job

        api_status = status_response.get("processing_status", "")
        if api_status == "ended":
            job.status = BatchJobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc).isoformat()
        elif api_status == "in_progress":
            job.status = BatchJobStatus.IN_PROGRESS
        elif api_status == "failed":
            job.status = BatchJobStatus.FAILED

        return job

    async def retrieve_results(self, job: BatchJob) -> BatchJob:
        """Retrieve and validate results from a completed batch.

        Each result is parsed and optionally validated through the
        output validator. Returns the job with results populated.
        """
        if job.status != BatchJobStatus.COMPLETED:
            return job
        if not job.batch_api_id:
            return job

        try:
            raw_results = await self._client.batches.results(job.batch_api_id)
        except Exception as exc:
            logger.error("Failed to retrieve results for %s: %s", job.job_id, exc)
            job.status = BatchJobStatus.FAILED
            return job

        results_list = raw_results if isinstance(raw_results, list) else []
        processed: list[dict[str, Any]] = []
        success = 0
        errors = 0

        for item in results_list:
            request_id = item.get("custom_id", "")
            result_body = item.get("result", {})
            result_type = result_body.get("type", "")

            if result_type == "succeeded":
                content = self._extract_content(result_body)
                valid = True
                validation_errors: list[str] = []

                if self._validator and content:
                    valid, validation_errors, _ = self._validator(content)

                processed.append({
                    "request_id": request_id,
                    "content": content,
                    "valid": valid,
                    "validation_errors": validation_errors,
                    "status": "success",
                })
                success += 1
            else:
                error_msg = result_body.get("error", {}).get("message", "unknown")
                processed.append({
                    "request_id": request_id,
                    "content": "",
                    "valid": False,
                    "validation_errors": [error_msg],
                    "status": "error",
                })
                errors += 1
                logger.warning(
                    "Batch item %s failed: %s", request_id, error_msg,
                )

        job.results = processed
        job.success_count = success
        job.error_count = errors
        return job

    def _task_to_request(self, task: BatchTask) -> dict[str, Any]:
        """Convert a BatchTask to an Anthropic Batch API request."""
        return {
            "custom_id": task.task_id,
            "params": {
                "model": task.model_id,
                "max_tokens": task.max_tokens,
                "system": task.system_prompt,
                "messages": [{"role": "user", "content": task.user_content}],
            },
        }

    def _extract_content(self, result_body: dict[str, Any]) -> str:
        """Extract text content from a batch result."""
        message = result_body.get("message", {})
        content_blocks = message.get("content", [])
        parts: list[str] = []
        for block in content_blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
