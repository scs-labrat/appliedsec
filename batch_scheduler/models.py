"""Batch Scheduler data models — Story 10.1.

Defines BatchTask, BatchJob, FPPattern, and PlaybookDraft.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid


class BatchJobStatus(str, Enum):
    """Lifecycle states for a batch job."""

    PENDING = "pending"
    SUBMITTED = "submitted"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class BatchTaskType(str, Enum):
    """Types of tasks that can be batched."""

    FP_PATTERN_GENERATION = "fp_pattern_generation"
    PLAYBOOK_GENERATION = "playbook_generation"


class FPPatternStatus(str, Enum):
    """Lifecycle states for an FP pattern."""

    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    ACTIVE = "active"
    SHADOW = "shadow"
    DEPRECATED = "deprecated"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class BatchTask:
    """A single task within a batch job."""

    task_id: str = ""
    task_type: str = ""
    system_prompt: str = ""
    user_content: str = ""
    model_id: str = "claude-sonnet-4-5-20250929"
    max_tokens: int = 16384
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.task_id:
            self.task_id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


MAX_BATCH_SIZE = 10_000
BATCH_SLA_HOURS = 24


@dataclass
class BatchJob:
    """A submitted batch of tasks."""

    job_id: str = ""
    batch_api_id: str = ""
    status: BatchJobStatus = BatchJobStatus.PENDING
    tasks: list[BatchTask] = field(default_factory=list)
    submitted_at: str = ""
    completed_at: str = ""
    results: list[dict[str, Any]] = field(default_factory=list)
    error_count: int = 0
    success_count: int = 0
    total_cost_usd: float = 0.0
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.job_id:
            self.job_id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    @property
    def task_count(self) -> int:
        return len(self.tasks)


@dataclass
class FPPattern:
    """A false-positive pattern candidate or approved pattern."""

    pattern_id: str = ""
    alert_name: str = ""
    alert_name_regex: str = ""
    entity_patterns: list[dict[str, Any]] = field(default_factory=list)
    severity: str = ""
    confidence: float = 0.0
    status: str = FPPatternStatus.PENDING_REVIEW.value
    approved_by: str = ""
    approved_by_1: str = ""
    approved_by_2: str = ""
    approval_date: str = ""
    expiry_date: str = ""
    reaffirmed_date: str = ""
    reaffirmed_by: str = ""
    reason: str = ""
    false_positive_count: int = 0
    scope_rule_family: str = ""
    scope_tenant_id: str = ""
    scope_asset_class: str = ""
    source_investigations: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not self.pattern_id:
            self.pattern_id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at


@dataclass
class PlaybookDraft:
    """An auto-generated playbook draft for analyst review."""

    playbook_id: str = ""
    name: str = ""
    description: str = ""
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)
    confidence: float = 0.0
    source_investigations: list[str] = field(default_factory=list)
    status: str = "draft"
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.playbook_id:
            self.playbook_id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
