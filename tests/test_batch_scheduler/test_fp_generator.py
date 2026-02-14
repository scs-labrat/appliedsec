"""Tests for batch_scheduler.fp_generator — Story 10.4."""

from __future__ import annotations

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock

from batch_scheduler.fp_generator import (
    FP_GENERATION_SYSTEM_PROMPT,
    FPPatternGenerator,
    MIN_INVESTIGATIONS_FOR_FP,
    MIN_INVESTIGATIONS_FOR_PLAYBOOK,
    PLAYBOOK_GENERATION_SYSTEM_PROMPT,
)
from batch_scheduler.models import BatchTaskType

NOW = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def _fp_investigation(inv_id, alert_title="Known FP Alert"):
    """Create a mock closed FP investigation row."""
    return {
        "investigation_id": inv_id,
        "alert_id": f"alert-{inv_id}",
        "graphstate_json": {
            "classification": "false_positive",
            "alert_title": alert_title,
            "entities": {"ips": [{"primary_value": "10.0.0.1"}]},
        },
        "decision_chain": [{"agent": "reasoning", "action": "classify"}],
    }


def _resolved_investigation(inv_id, technique="AML.T0020"):
    """Create a mock closed non-FP investigation row."""
    return {
        "investigation_id": inv_id,
        "alert_id": f"alert-{inv_id}",
        "graphstate_json": {
            "classification": "true_positive",
            "alert_title": "Real Attack",
            "atlas_techniques": [technique],
            "entities": {},
        },
        "decision_chain": [{"agent": "reasoning", "action": "classify"}],
    }


# ── generate_fp_tasks ─────────────────────────────────────────────

class TestGenerateFPTasks:
    @pytest.mark.asyncio
    async def test_generates_tasks_for_fp_group(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[
            _fp_investigation("inv-1"),
            _fp_investigation("inv-2"),
            _fp_investigation("inv-3"),
        ])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_fp_tasks(NOW)
        assert len(tasks) == 1
        assert tasks[0].task_type == BatchTaskType.FP_PATTERN_GENERATION.value
        assert tasks[0].system_prompt == FP_GENERATION_SYSTEM_PROMPT

    @pytest.mark.asyncio
    async def test_skips_below_minimum(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[
            _fp_investigation("inv-1"),
            _fp_investigation("inv-2"),
        ])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_fp_tasks(NOW)
        assert len(tasks) == 0

    @pytest.mark.asyncio
    async def test_groups_by_alert_title(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[
            _fp_investigation("inv-1", "Alert A"),
            _fp_investigation("inv-2", "Alert A"),
            _fp_investigation("inv-3", "Alert A"),
            _fp_investigation("inv-4", "Alert B"),
            _fp_investigation("inv-5", "Alert B"),
            _fp_investigation("inv-6", "Alert B"),
        ])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_fp_tasks(NOW)
        assert len(tasks) == 2

    @pytest.mark.asyncio
    async def test_excludes_non_fp(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[
            _resolved_investigation("inv-1"),
            _resolved_investigation("inv-2"),
            _resolved_investigation("inv-3"),
        ])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_fp_tasks(NOW)
        assert len(tasks) == 0

    @pytest.mark.asyncio
    async def test_metadata_includes_investigation_ids(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[
            _fp_investigation("inv-1"),
            _fp_investigation("inv-2"),
            _fp_investigation("inv-3"),
        ])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_fp_tasks(NOW)
        ids = tasks[0].metadata["source_investigations"]
        assert "inv-1" in ids
        assert "inv-2" in ids
        assert "inv-3" in ids

    @pytest.mark.asyncio
    async def test_empty_database(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_fp_tasks(NOW)
        assert tasks == []

    @pytest.mark.asyncio
    async def test_handles_string_graphstate(self):
        db = AsyncMock()
        row = _fp_investigation("inv-1")
        row["graphstate_json"] = json.dumps(row["graphstate_json"])
        row2 = _fp_investigation("inv-2")
        row2["graphstate_json"] = json.dumps(row2["graphstate_json"])
        row3 = _fp_investigation("inv-3")
        row3["graphstate_json"] = json.dumps(row3["graphstate_json"])
        db.fetch_many = AsyncMock(return_value=[row, row2, row3])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_fp_tasks(NOW)
        assert len(tasks) == 1


# ── generate_playbook_tasks ───────────────────────────────────────

class TestGeneratePlaybookTasks:
    @pytest.mark.asyncio
    async def test_generates_playbook_tasks(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[
            _resolved_investigation("inv-1", "AML.T0020"),
            _resolved_investigation("inv-2", "AML.T0020"),
        ])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_playbook_tasks(NOW)
        assert len(tasks) == 1
        assert tasks[0].task_type == BatchTaskType.PLAYBOOK_GENERATION.value
        assert tasks[0].system_prompt == PLAYBOOK_GENERATION_SYSTEM_PROMPT

    @pytest.mark.asyncio
    async def test_skips_fp_investigations(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[
            _fp_investigation("inv-1"),
            _fp_investigation("inv-2"),
            _fp_investigation("inv-3"),
        ])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_playbook_tasks(NOW)
        assert len(tasks) == 0

    @pytest.mark.asyncio
    async def test_groups_by_technique(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[
            _resolved_investigation("inv-1", "AML.T0020"),
            _resolved_investigation("inv-2", "AML.T0020"),
            _resolved_investigation("inv-3", "AML.T0015"),
            _resolved_investigation("inv-4", "AML.T0015"),
        ])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_playbook_tasks(NOW)
        assert len(tasks) == 2

    @pytest.mark.asyncio
    async def test_skips_no_techniques(self):
        db = AsyncMock()
        inv = _resolved_investigation("inv-1")
        inv["graphstate_json"]["atlas_techniques"] = []
        inv2 = _resolved_investigation("inv-2")
        inv2["graphstate_json"]["atlas_techniques"] = []
        db.fetch_many = AsyncMock(return_value=[inv, inv2])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_playbook_tasks(NOW)
        assert len(tasks) == 0

    @pytest.mark.asyncio
    async def test_below_minimum(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[
            _resolved_investigation("inv-1", "AML.T0099"),
        ])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_playbook_tasks(NOW)
        assert len(tasks) == 0


# ── generate_all_tasks ────────────────────────────────────────────

class TestGenerateAllTasks:
    @pytest.mark.asyncio
    async def test_combines_fp_and_playbook(self):
        db = AsyncMock()
        # Called twice: once for FP, once for playbook
        db.fetch_many = AsyncMock(side_effect=[
            [_fp_investigation(f"fp-{i}") for i in range(3)],
            [_resolved_investigation(f"pb-{i}", "AML.T0020") for i in range(2)],
        ])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_all_tasks(NOW)
        fp_tasks = [t for t in tasks if t.task_type == BatchTaskType.FP_PATTERN_GENERATION.value]
        pb_tasks = [t for t in tasks if t.task_type == BatchTaskType.PLAYBOOK_GENERATION.value]
        assert len(fp_tasks) == 1
        assert len(pb_tasks) == 1

    @pytest.mark.asyncio
    async def test_empty_returns_empty(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[])
        gen = FPPatternGenerator(db)
        tasks = await gen.generate_all_tasks(NOW)
        assert tasks == []


# ── Constants ─────────────────────────────────────────────────────

class TestConstants:
    def test_min_fp_investigations(self):
        assert MIN_INVESTIGATIONS_FOR_FP == 3

    def test_min_playbook_investigations(self):
        assert MIN_INVESTIGATIONS_FOR_PLAYBOOK == 2

    def test_system_prompts_non_empty(self):
        assert len(FP_GENERATION_SYSTEM_PROMPT) > 50
        assert len(PLAYBOOK_GENERATION_SYSTEM_PROMPT) > 50
