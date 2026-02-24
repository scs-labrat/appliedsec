"""Tests for chain verification and scheduled integrity checks — Story 13.7."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from services.audit_service.chain import (
    chain_event,
    compute_record_hash,
    create_genesis_record,
)
from services.audit_service.verification import (
    VerificationScheduler,
    verify_recent,
    verify_tenant_chain,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_chain(tenant_id: str = "t1", count: int = 5) -> list[dict]:
    """Build a valid chain of *count* records (excluding genesis)."""
    genesis = create_genesis_record(tenant_id)
    state = {"last_sequence": 0, "last_hash": genesis["record_hash"]}
    records = [genesis]
    for i in range(count):
        event = {
            "audit_id": f"evt-{i}",
            "tenant_id": tenant_id,
            "timestamp": "2026-02-21T12:00:00.000Z",
            "event_type": "alert.classified",
            "event_category": "decision",
            "severity": "info",
            "actor_type": "agent",
            "actor_id": "test",
            "investigation_id": "inv-1",
            "context": {},
            "decision": {},
            "outcome": {},
        }
        record = chain_event(event, state)
        records.append(record)
        state = {"last_sequence": record["sequence_number"], "last_hash": record["record_hash"]}
    return records


def _mock_db(records: list[dict] | None = None, tenants: list[str] | None = None):
    """Create a mocked Postgres client."""
    db = AsyncMock()
    if records is None:
        records = _make_chain()
    db.fetch_many = AsyncMock(side_effect=_fetch_many_side_effect(records, tenants or ["t1"]))
    db.fetch_one = AsyncMock(return_value={"max_seq": len(records)})
    db.execute = AsyncMock()
    return db


def _fetch_many_side_effect(records, tenants):
    """Return appropriate rows depending on the query."""
    def side_effect(query, *args):
        if "audit_chain_state" in query:
            return [{"tenant_id": t} for t in tenants]
        if "RANDOM()" in query:
            return records[:min(100, len(records))]
        if "DESC LIMIT" in query:
            return list(reversed(records[-100:]))
        return records
    return side_effect


# ---------------------------------------------------------------------------
# TestVerifyTenantChain
# ---------------------------------------------------------------------------

class TestVerifyTenantChain:
    """AC-4: verify_tenant_chain detects tampered and valid chains."""

    @pytest.mark.asyncio
    async def test_valid_chain_passes(self):
        records = _make_chain(count=3)
        db = _mock_db(records)
        valid, errors = await verify_tenant_chain(db, "t1")
        assert valid is True
        assert errors == []

    @pytest.mark.asyncio
    async def test_tampered_record_detected(self):
        records = _make_chain(count=3)
        records[2]["record_hash"] = "tampered_hash_value"
        db = _mock_db(records)
        valid, errors = await verify_tenant_chain(db, "t1")
        assert valid is False
        assert any("hash mismatch" in e for e in errors)

    @pytest.mark.asyncio
    async def test_sequence_gap_detected(self):
        records = _make_chain(count=3)
        records[2]["sequence_number"] = 99
        records[2]["record_hash"] = compute_record_hash(records[2])
        db = _mock_db(records)
        valid, errors = await verify_tenant_chain(db, "t1")
        assert valid is False
        assert any("gap" in e.lower() or "previous_hash" in e for e in errors)

    @pytest.mark.asyncio
    async def test_broken_previous_hash_detected(self):
        records = _make_chain(count=3)
        records[2]["previous_hash"] = "wrong_hash"
        records[2]["record_hash"] = compute_record_hash(records[2])
        db = _mock_db(records)
        valid, errors = await verify_tenant_chain(db, "t1")
        assert valid is False
        assert any("previous_hash" in e for e in errors)

    @pytest.mark.asyncio
    async def test_empty_chain_returns_true(self):
        db = _mock_db([])
        valid, errors = await verify_tenant_chain(db, "t1")
        assert valid is True
        assert errors == []

    @pytest.mark.asyncio
    async def test_with_sequence_range(self):
        records = _make_chain(count=5)
        db = _mock_db(records)
        valid, errors = await verify_tenant_chain(db, "t1", from_sequence=1, to_sequence=3)
        assert valid is True


# ---------------------------------------------------------------------------
# TestVerifyRecent
# ---------------------------------------------------------------------------

class TestVerifyRecent:
    """verify_recent: last N records."""

    @pytest.mark.asyncio
    async def test_recent_valid(self):
        records = _make_chain(count=5)
        db = _mock_db(records)
        valid, errors = await verify_recent(db, "t1", count=3)
        assert valid is True

    @pytest.mark.asyncio
    async def test_recent_tampered(self):
        records = _make_chain(count=5)
        records[-1]["record_hash"] = "tampered"
        db = _mock_db(records)
        valid, errors = await verify_recent(db, "t1", count=3)
        assert valid is False


# ---------------------------------------------------------------------------
# TestVerificationScheduler
# ---------------------------------------------------------------------------

class TestVerificationScheduler:
    """AC-1,2,3: Scheduled verification runs and results persisted."""

    @pytest.fixture()
    def scheduler(self):
        records = _make_chain(count=5)
        db = _mock_db(records, tenants=["t1"])
        metrics = MagicMock()
        return VerificationScheduler(db, metrics_callback=metrics), db, metrics

    @pytest.mark.asyncio
    async def test_continuous_check_runs(self, scheduler):
        sched, db, metrics = scheduler
        results = await sched.run_continuous_check()
        assert len(results) == 1
        assert results[0]["verification_type"] == "continuous"
        assert results[0]["chain_valid"] is True

    @pytest.mark.asyncio
    async def test_daily_full_check_runs(self, scheduler):
        sched, db, metrics = scheduler
        results = await sched.run_daily_full_check()
        assert len(results) == 1
        assert results[0]["verification_type"] == "daily_full"
        assert results[0]["chain_valid"] is True

    @pytest.mark.asyncio
    async def test_hourly_lag_check_runs(self, scheduler):
        sched, db, metrics = scheduler
        results = await sched.run_hourly_lag_check()
        assert len(results) == 1
        assert results[0]["verification_type"] == "hourly_lag"

    @pytest.mark.asyncio
    async def test_weekly_cold_check_runs(self, scheduler):
        sched, db, metrics = scheduler
        results = await sched.run_weekly_cold_check()
        assert len(results) == 1
        assert results[0]["verification_type"] == "weekly_cold"
        assert results[0]["chain_valid"] is True

    @pytest.mark.asyncio
    async def test_results_written_to_verification_log(self, scheduler):
        sched, db, metrics = scheduler
        await sched.run_continuous_check()
        db.execute.assert_called()
        call_args = db.execute.call_args
        assert "audit_verification_log" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_lag_high_detected(self):
        records = _make_chain(count=5)
        db = _mock_db(records, tenants=["t1"])
        db.fetch_one = AsyncMock(return_value={"max_seq": 100})
        kafka_admin = AsyncMock()
        kafka_admin.get_latest_offset = AsyncMock(return_value=5000)
        metrics = MagicMock()
        sched = VerificationScheduler(db, kafka_admin=kafka_admin, metrics_callback=metrics)
        results = await sched.run_hourly_lag_check()
        assert results[0]["chain_valid"] is False
        assert any("lag" in e.lower() for e in results[0]["errors"])


# ---------------------------------------------------------------------------
# TestVerificationMetrics
# ---------------------------------------------------------------------------

class TestVerificationMetrics:
    """AC-1,2: Prometheus metrics emitted correctly."""

    @pytest.mark.asyncio
    async def test_valid_chain_sets_gauge_to_1(self):
        records = _make_chain(count=3)
        db = _mock_db(records, tenants=["t1"])
        metrics = MagicMock()
        sched = VerificationScheduler(db, metrics_callback=metrics)
        await sched.run_continuous_check()
        calls = [c for c in metrics.call_args_list if c[0][0] == "aluskort_audit_chain_valid"]
        assert len(calls) > 0
        assert calls[0][0][2] == 1  # value = 1

    @pytest.mark.asyncio
    async def test_broken_chain_sets_gauge_to_0(self):
        records = _make_chain(count=3)
        records[-1]["record_hash"] = "tampered"
        db = _mock_db(records, tenants=["t1"])
        metrics = MagicMock()
        sched = VerificationScheduler(db, metrics_callback=metrics)
        await sched.run_continuous_check()
        calls = [c for c in metrics.call_args_list if c[0][0] == "aluskort_audit_chain_valid"]
        assert len(calls) > 0
        assert calls[0][0][2] == 0  # value = 0

    @pytest.mark.asyncio
    async def test_lag_metric_exported(self):
        records = _make_chain(count=3)
        db = _mock_db(records, tenants=["t1"])
        db.fetch_one = AsyncMock(return_value={"max_seq": 50})
        metrics = MagicMock()
        sched = VerificationScheduler(db, metrics_callback=metrics)
        await sched.run_hourly_lag_check()
        calls = [c for c in metrics.call_args_list if c[0][0] == "aluskort_audit_kafka_lag"]
        assert len(calls) > 0

    @pytest.mark.asyncio
    async def test_duration_metric_exported(self):
        records = _make_chain(count=3)
        db = _mock_db(records, tenants=["t1"])
        metrics = MagicMock()
        sched = VerificationScheduler(db, metrics_callback=metrics)
        await sched.run_continuous_check()
        calls = [c for c in metrics.call_args_list if c[0][0] == "aluskort_audit_verification_duration_seconds"]
        assert len(calls) > 0
