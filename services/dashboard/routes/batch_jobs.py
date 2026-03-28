"""Batch Job Monitor routes — visibility into async Tier-2 batch processing.

Provides a dashboard for monitoring batch jobs with filtering, progress
tracking, cancel actions, and cost visibility.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Demo / fallback data
# ---------------------------------------------------------------------------

DEMO_BATCH_JOBS: list[dict[str, Any]] = [
    {
        "job_id": "BJ-001",
        "job_type": "fp_pattern_training",
        "job_type_label": "FP Pattern Training",
        "status": "completed",
        "submitted_at": "2026-03-29T06:00:00Z",
        "started_at": "2026-03-29T06:02:14Z",
        "completed_at": "2026-03-29T06:48:31Z",
        "duration": "46m 17s",
        "model_tier": "Tier 2",
        "tokens_input": 284_500,
        "tokens_output": 42_300,
        "cost_usd": 0.74,
        "items_processed": 150,
        "total_items": 150,
        "error_message": None,
        "submitted_by": "system",
    },
    {
        "job_id": "BJ-002",
        "job_type": "playbook_generation",
        "job_type_label": "Playbook Generation",
        "status": "completed",
        "submitted_at": "2026-03-29T06:00:00Z",
        "started_at": "2026-03-29T06:01:48Z",
        "completed_at": "2026-03-29T06:35:12Z",
        "duration": "33m 24s",
        "model_tier": "Tier 2",
        "tokens_input": 198_200,
        "tokens_output": 67_800,
        "cost_usd": 0.81,
        "items_processed": 25,
        "total_items": 25,
        "error_message": None,
        "submitted_by": "system",
    },
    {
        "job_id": "BJ-003",
        "job_type": "embedding_migration",
        "job_type_label": "Embedding Migration",
        "status": "running",
        "submitted_at": "2026-03-29T08:30:00Z",
        "started_at": "2026-03-29T08:31:05Z",
        "completed_at": None,
        "duration": "1h 12m (elapsed)",
        "model_tier": "Tier 1",
        "tokens_input": 512_000,
        "tokens_output": 15_200,
        "cost_usd": 1.76,
        "items_processed": 3_420,
        "total_items": 5_000,
        "error_message": None,
        "submitted_by": "system",
    },
    {
        "job_id": "BJ-004",
        "job_type": "incident_indexing",
        "job_type_label": "Incident Memory Indexing",
        "status": "running",
        "submitted_at": "2026-03-29T09:00:00Z",
        "started_at": "2026-03-29T09:00:42Z",
        "completed_at": None,
        "duration": "42m (elapsed)",
        "model_tier": "Tier 1",
        "tokens_input": 345_600,
        "tokens_output": 28_400,
        "cost_usd": 1.46,
        "items_processed": 780,
        "total_items": 1_200,
        "error_message": None,
        "submitted_by": "system",
    },
    {
        "job_id": "BJ-005",
        "job_type": "ioc_refresh",
        "job_type_label": "IOC Feed Refresh",
        "status": "completed",
        "submitted_at": "2026-03-29T04:00:00Z",
        "started_at": "2026-03-29T04:00:22Z",
        "completed_at": "2026-03-29T04:12:45Z",
        "duration": "12m 23s",
        "model_tier": "Tier 0",
        "tokens_input": 95_300,
        "tokens_output": 12_100,
        "cost_usd": 0.12,
        "items_processed": 4_800,
        "total_items": 4_800,
        "error_message": None,
        "submitted_by": "system",
    },
    {
        "job_id": "BJ-006",
        "job_type": "atlas_evaluation",
        "job_type_label": "ATLAS Rule Evaluation",
        "status": "queued",
        "submitted_at": "2026-03-29T09:45:00Z",
        "started_at": None,
        "completed_at": None,
        "duration": None,
        "model_tier": "Tier 2",
        "tokens_input": 0,
        "tokens_output": 0,
        "cost_usd": 0.00,
        "items_processed": 0,
        "total_items": 320,
        "error_message": None,
        "submitted_by": "analyst@corp.local",
    },
    {
        "job_id": "BJ-007",
        "job_type": "fp_pattern_training",
        "job_type_label": "FP Pattern Training",
        "status": "failed",
        "submitted_at": "2026-03-28T22:00:00Z",
        "started_at": "2026-03-28T22:01:15Z",
        "completed_at": "2026-03-28T22:14:03Z",
        "duration": "12m 48s",
        "model_tier": "Tier 2",
        "tokens_input": 78_200,
        "tokens_output": 5_100,
        "cost_usd": 0.16,
        "items_processed": 32,
        "total_items": 150,
        "error_message": "Batch API returned HTTP 529: Overloaded. 118 tasks did not complete. Retry scheduled for next window.",
        "submitted_by": "system",
    },
    {
        "job_id": "BJ-008",
        "job_type": "playbook_generation",
        "job_type_label": "Playbook Generation",
        "status": "queued",
        "submitted_at": "2026-03-29T09:50:00Z",
        "started_at": None,
        "completed_at": None,
        "duration": None,
        "model_tier": "Tier 2",
        "tokens_input": 0,
        "tokens_output": 0,
        "cost_usd": 0.00,
        "items_processed": 0,
        "total_items": 18,
        "error_message": None,
        "submitted_by": "system",
    },
    {
        "job_id": "BJ-009",
        "job_type": "ioc_refresh",
        "job_type_label": "IOC Feed Refresh",
        "status": "cancelled",
        "submitted_at": "2026-03-28T16:00:00Z",
        "started_at": "2026-03-28T16:00:30Z",
        "completed_at": "2026-03-28T16:03:12Z",
        "duration": "2m 42s",
        "model_tier": "Tier 0",
        "tokens_input": 22_100,
        "tokens_output": 3_400,
        "cost_usd": 0.03,
        "items_processed": 1_100,
        "total_items": 4_800,
        "error_message": None,
        "submitted_by": "analyst@corp.local",
    },
    {
        "job_id": "BJ-010",
        "job_type": "embedding_migration",
        "job_type_label": "Embedding Migration",
        "status": "completed",
        "submitted_at": "2026-03-28T02:00:00Z",
        "started_at": "2026-03-28T02:01:10Z",
        "completed_at": "2026-03-28T03:42:55Z",
        "duration": "1h 41m 45s",
        "model_tier": "Tier 1",
        "tokens_input": 1_024_000,
        "tokens_output": 31_200,
        "cost_usd": 3.54,
        "items_processed": 10_000,
        "total_items": 10_000,
        "error_message": None,
        "submitted_by": "system",
    },
    {
        "job_id": "BJ-011",
        "job_type": "atlas_evaluation",
        "job_type_label": "ATLAS Rule Evaluation",
        "status": "completed",
        "submitted_at": "2026-03-28T12:00:00Z",
        "started_at": "2026-03-28T12:02:00Z",
        "completed_at": "2026-03-28T12:38:22Z",
        "duration": "36m 22s",
        "model_tier": "Tier 2",
        "tokens_input": 256_800,
        "tokens_output": 89_400,
        "cost_usd": 1.05,
        "items_processed": 320,
        "total_items": 320,
        "error_message": None,
        "submitted_by": "system",
    },
    {
        "job_id": "BJ-012",
        "job_type": "incident_indexing",
        "job_type_label": "Incident Memory Indexing",
        "status": "failed",
        "submitted_at": "2026-03-27T20:00:00Z",
        "started_at": "2026-03-27T20:00:55Z",
        "completed_at": "2026-03-27T20:22:10Z",
        "duration": "21m 15s",
        "model_tier": "Tier 1",
        "tokens_input": 189_400,
        "tokens_output": 14_600,
        "cost_usd": 0.79,
        "items_processed": 410,
        "total_items": 600,
        "error_message": "Qdrant connection timeout after 3 retries. 190 incidents could not be indexed. Vector store may be under maintenance.",
        "submitted_by": "system",
    },
]


def _compute_stats(jobs: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute summary statistics from job list."""
    running = [j for j in jobs if j["status"] == "running"]
    queued = [j for j in jobs if j["status"] == "queued"]
    completed_today = [
        j for j in jobs
        if j["status"] == "completed"
        and j.get("completed_at", "")
        and j["completed_at"].startswith("2026-03-29")
    ]
    total_cost = round(sum(j.get("cost_usd", 0) for j in jobs), 2)
    cost_today = round(
        sum(
            j.get("cost_usd", 0)
            for j in jobs
            if j.get("submitted_at", "").startswith("2026-03-29")
        ),
        2,
    )
    return {
        "total": len(jobs),
        "running": len(running),
        "queued": len(queued),
        "completed_today": len(completed_today),
        "total_cost": total_cost,
        "cost_today": cost_today,
    }


def _filter_jobs(
    jobs: list[dict[str, Any]],
    status: str | None = None,
    job_type: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    """Apply filters to job list."""
    result = jobs
    if status:
        result = [j for j in result if j["status"] == status]
    if job_type:
        result = [j for j in result if j["job_type"] == job_type]
    if date_from:
        result = [j for j in result if j.get("submitted_at", "") >= date_from]
    if date_to:
        result = [j for j in result if j.get("submitted_at", "") <= date_to]
    return result


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------


@router.get("/batch-jobs", response_class=HTMLResponse)
async def batch_jobs_page(request: Request) -> HTMLResponse:
    """Render the batch job monitor page."""
    jobs = DEMO_BATCH_JOBS
    stats = _compute_stats(jobs)

    return templates.TemplateResponse(
        request,
        "batch_jobs/index.html",
        {
            "jobs": jobs,
            "stats": stats,
        },
    )


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------


@router.get("/api/batch-jobs/list")
async def api_batch_jobs_list(
    status: str | None = None,
    job_type: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict[str, Any]:
    """List batch jobs with optional filtering."""
    filtered = _filter_jobs(DEMO_BATCH_JOBS, status, job_type, date_from, date_to)
    return {
        "jobs": filtered,
        "count": len(filtered),
        "stats": _compute_stats(filtered),
    }


@router.post("/api/batch-jobs/cancel/{job_id}")
async def api_cancel_job(job_id: str) -> dict[str, Any]:
    """Cancel a queued or running batch job (demo: toggles status)."""
    for job in DEMO_BATCH_JOBS:
        if job["job_id"] == job_id:
            if job["status"] in ("queued", "running"):
                job["status"] = "cancelled"
                logger.info("Cancelled batch job %s", job_id)
                return {"status": "cancelled", "job_id": job_id}
            return {
                "error": f"Cannot cancel job in '{job['status']}' state",
                "job_id": job_id,
            }
    return {"error": "Job not found", "job_id": job_id}
