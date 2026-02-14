"""Tests for batch_scheduler.models — Story 10.1 data models."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from batch_scheduler.models import (
    MAX_BATCH_SIZE,
    BATCH_SLA_HOURS,
    BatchJob,
    BatchJobStatus,
    BatchTask,
    BatchTaskType,
    FPPattern,
    FPPatternStatus,
    PlaybookDraft,
)


# ── BatchTask ─────────────────────────────────────────────────────

class TestBatchTask:
    def test_auto_id(self):
        t = BatchTask()
        assert t.task_id != ""
        assert len(t.task_id) == 36  # UUID

    def test_auto_timestamp(self):
        t = BatchTask()
        ts = datetime.fromisoformat(t.created_at)
        assert ts.tzinfo is not None

    def test_explicit_fields(self):
        t = BatchTask(
            task_id="t-1",
            task_type="fp_pattern_generation",
            system_prompt="sys",
            user_content="user",
            model_id="claude-sonnet-4-5-20250929",
            max_tokens=8192,
            metadata={"key": "val"},
        )
        assert t.task_id == "t-1"
        assert t.task_type == "fp_pattern_generation"
        assert t.max_tokens == 8192
        assert t.metadata["key"] == "val"

    def test_default_model(self):
        t = BatchTask()
        assert t.model_id == "claude-sonnet-4-5-20250929"

    def test_default_max_tokens(self):
        t = BatchTask()
        assert t.max_tokens == 16384


# ── BatchJob ──────────────────────────────────────────────────────

class TestBatchJob:
    def test_auto_id(self):
        j = BatchJob()
        assert j.job_id != ""
        assert len(j.job_id) == 36

    def test_auto_timestamp(self):
        j = BatchJob()
        ts = datetime.fromisoformat(j.created_at)
        assert ts.tzinfo is not None

    def test_defaults(self):
        j = BatchJob()
        assert j.status == BatchJobStatus.PENDING
        assert j.tasks == []
        assert j.results == []
        assert j.error_count == 0
        assert j.success_count == 0
        assert j.total_cost_usd == 0.0

    def test_task_count_property(self):
        j = BatchJob(tasks=[BatchTask(), BatchTask()])
        assert j.task_count == 2

    def test_empty_task_count(self):
        j = BatchJob()
        assert j.task_count == 0


# ── BatchJobStatus ────────────────────────────────────────────────

class TestBatchJobStatus:
    def test_all_statuses(self):
        assert BatchJobStatus.PENDING.value == "pending"
        assert BatchJobStatus.SUBMITTED.value == "submitted"
        assert BatchJobStatus.IN_PROGRESS.value == "in_progress"
        assert BatchJobStatus.COMPLETED.value == "completed"
        assert BatchJobStatus.FAILED.value == "failed"
        assert BatchJobStatus.EXPIRED.value == "expired"

    def test_count(self):
        assert len(BatchJobStatus) == 6


# ── BatchTaskType ─────────────────────────────────────────────────

class TestBatchTaskType:
    def test_types(self):
        assert BatchTaskType.FP_PATTERN_GENERATION.value == "fp_pattern_generation"
        assert BatchTaskType.PLAYBOOK_GENERATION.value == "playbook_generation"


# ── FPPattern ─────────────────────────────────────────────────────

class TestFPPattern:
    def test_auto_id(self):
        p = FPPattern()
        assert p.pattern_id != ""
        assert len(p.pattern_id) == 36

    def test_defaults(self):
        p = FPPattern()
        assert p.status == FPPatternStatus.PENDING_REVIEW.value
        assert p.confidence == 0.0
        assert p.entity_patterns == []
        assert p.source_investigations == []
        assert p.approved_by == ""
        assert p.false_positive_count == 0

    def test_explicit_fields(self):
        p = FPPattern(
            pattern_id="fp-1",
            alert_name="Test Alert",
            alert_name_regex="Test.*",
            entity_patterns=[{"type": "ip", "value_regex": "10\\..*"}],
            severity="low",
            confidence=0.95,
            reason="Known test pattern",
        )
        assert p.pattern_id == "fp-1"
        assert p.alert_name == "Test Alert"
        assert len(p.entity_patterns) == 1
        assert p.confidence == 0.95

    def test_updated_at_matches_created_at(self):
        p = FPPattern()
        assert p.updated_at == p.created_at


# ── FPPatternStatus ───────────────────────────────────────────────

class TestFPPatternStatus:
    def test_all_statuses(self):
        assert FPPatternStatus.PENDING_REVIEW.value == "pending_review"
        assert FPPatternStatus.APPROVED.value == "approved"
        assert FPPatternStatus.ACTIVE.value == "active"
        assert FPPatternStatus.DEPRECATED.value == "deprecated"


# ── PlaybookDraft ─────────────────────────────────────────────────

class TestPlaybookDraft:
    def test_auto_id(self):
        d = PlaybookDraft()
        assert d.playbook_id != ""
        assert len(d.playbook_id) == 36

    def test_defaults(self):
        d = PlaybookDraft()
        assert d.status == "draft"
        assert d.tactics == []
        assert d.techniques == []
        assert d.remediation_steps == []
        assert d.source_investigations == []

    def test_explicit_fields(self):
        d = PlaybookDraft(
            name="Phishing Response",
            description="Respond to phishing attempts",
            tactics=["Initial Access"],
            techniques=["T1566"],
            remediation_steps=["Block sender", "Reset credentials"],
            confidence=0.88,
            source_investigations=["inv-1", "inv-2"],
        )
        assert d.name == "Phishing Response"
        assert len(d.remediation_steps) == 2
        assert d.confidence == 0.88


# ── Constants ─────────────────────────────────────────────────────

class TestConstants:
    def test_max_batch_size(self):
        assert MAX_BATCH_SIZE == 10_000

    def test_batch_sla_hours(self):
        assert BATCH_SLA_HOURS == 24
