"""Tests for CanaryScheduler — REM-H05."""

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from orchestrator.canary import (
    CanaryConfig,
    CanaryEvaluator,
    CanaryScheduler,
    CanarySlice,
    CANARY_ACTIVE,
)


@pytest.fixture
def mock_evaluator():
    evaluator = AsyncMock(spec=CanaryEvaluator)
    evaluator.evaluate_all_slices = AsyncMock(return_value=[
        {"slice_id": "s1", "action": "continue", "precision": 0.99, "missed_tps": 0},
    ])
    return evaluator


@pytest.fixture
def config():
    return CanaryConfig(
        slices=[
            CanarySlice(slice_id="s1", dimension="tenant", value="tenant-A"),
        ],
        promotion_days=7,
    )


@pytest.fixture
def mock_audit():
    audit = MagicMock()
    audit.emit = MagicMock()
    return audit


class TestCanaryScheduler:
    @pytest.mark.asyncio
    async def test_start_creates_task(self, mock_evaluator, config):
        scheduler = CanaryScheduler(mock_evaluator, config, interval_seconds=1)
        task = scheduler.start()
        assert isinstance(task, asyncio.Task)
        assert scheduler.is_running
        scheduler.stop()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_stop_signals_shutdown(self, mock_evaluator, config):
        scheduler = CanaryScheduler(mock_evaluator, config, interval_seconds=1)
        task = scheduler.start()
        scheduler.stop()
        assert scheduler._running is False
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_runs_evaluation_cycle(self, mock_evaluator, config):
        scheduler = CanaryScheduler(mock_evaluator, config, interval_seconds=1)
        task = scheduler.start()

        # Let it run one cycle
        await asyncio.sleep(0.1)
        scheduler.stop()

        # Wait for task to finish
        try:
            await asyncio.wait_for(task, timeout=3)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            task.cancel()

        mock_evaluator.evaluate_all_slices.assert_called()

    @pytest.mark.asyncio
    async def test_emits_audit_event(self, mock_evaluator, config, mock_audit):
        scheduler = CanaryScheduler(
            mock_evaluator, config,
            interval_seconds=1, audit_producer=mock_audit,
        )
        task = scheduler.start()
        await asyncio.sleep(0.1)
        scheduler.stop()
        try:
            await asyncio.wait_for(task, timeout=3)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            task.cancel()

        mock_audit.emit.assert_called()
        call_kwargs = mock_audit.emit.call_args
        assert call_kwargs.kwargs["event_type"] == "canary.evaluation_cycle"

    @pytest.mark.asyncio
    async def test_handles_evaluation_error(self, mock_evaluator, config):
        mock_evaluator.evaluate_all_slices.side_effect = RuntimeError("boom")
        scheduler = CanaryScheduler(mock_evaluator, config, interval_seconds=1)
        task = scheduler.start()
        await asyncio.sleep(0.1)
        scheduler.stop()
        try:
            await asyncio.wait_for(task, timeout=3)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            task.cancel()
        # Should not crash — error is logged

    @pytest.mark.asyncio
    async def test_double_start_returns_existing(self, mock_evaluator, config):
        scheduler = CanaryScheduler(mock_evaluator, config, interval_seconds=1)
        task1 = scheduler.start()
        task2 = scheduler.start()
        assert task1 is task2
        scheduler.stop()
        task1.cancel()
        try:
            await task1
        except asyncio.CancelledError:
            pass
