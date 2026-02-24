"""Tests for retention lifecycle — warm-to-cold export — Story 13.9."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from services.audit_service.retention import (
    RetentionLifecycle,
    _add_months,
    _next_month,
    _partition_name,
    _parse_partition_date,
    _records_to_parquet,
    _subtract_months,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_records(count: int = 5, tenant_id: str = "t1") -> list[dict]:
    """Create sample audit records."""
    records = []
    for i in range(count):
        records.append({
            "audit_id": f"aud-{i}",
            "tenant_id": tenant_id,
            "sequence_number": i,
            "previous_hash": "0" * 64,
            "timestamp": "2025-12-15T12:00:00+00:00",
            "ingested_at": "2025-12-15T12:00:01+00:00",
            "event_type": "alert.classified",
            "event_category": "decision",
            "severity": "info",
            "actor_type": "agent",
            "actor_id": "test",
            "actor_permissions": [],
            "investigation_id": "inv-1",
            "alert_id": "alert-1",
            "entity_ids": [],
            "context": {"key": "value"},
            "decision": {},
            "outcome": {},
            "record_hash": "abc123",
            "record_version": "1.0",
        })
    return records


def _mock_s3(parquet_bytes: bytes | None = None):
    """Create a mock S3 client that returns uploaded content on get."""
    s3 = MagicMock()
    stored = {}

    def put_object(**kwargs):
        stored[kwargs["Key"]] = kwargs["Body"]

    def get_object(**kwargs):
        key = kwargs["Key"]
        body = MagicMock()
        body.read.return_value = stored.get(key, b"")
        return {"Body": body}

    s3.put_object = MagicMock(side_effect=put_object)
    s3.get_object = MagicMock(side_effect=get_object)
    s3._stored = stored
    return s3


def _mock_db(records: list[dict] | None = None):
    """Create a mock Postgres client."""
    db = AsyncMock()
    db.fetch_many = AsyncMock(return_value=records or [])
    db.fetch_one = AsyncMock(return_value={"cnt": 0})
    db.execute = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# TestRetentionLifecycle
# ---------------------------------------------------------------------------

class TestRetentionLifecycle:
    """AC-1,4: Export generates Parquet, hash verified, partition management."""

    @pytest.mark.asyncio
    async def test_export_generates_parquet_and_hash(self):
        """Monthly export produces Parquet file and SHA-256 sidecar."""
        records = _make_records(3)
        db = _mock_db(records)
        s3 = _mock_s3()

        lifecycle = RetentionLifecycle(db, s3)
        ref_date = datetime(2026, 2, 15, tzinfo=timezone.utc)
        result = await lifecycle.run_monthly_export(reference_date=ref_date)

        assert result["exported_count"] == 3
        assert result["verified"] is True
        assert result["partition_name"] == "audit_records_2025_12"
        assert "s3_path" in result

        # Verify both files were uploaded
        assert s3.put_object.call_count == 2

    @pytest.mark.asyncio
    async def test_export_hash_verification(self):
        """Uploaded file hash matches computed hash."""
        records = _make_records(2)
        db = _mock_db(records)
        s3 = _mock_s3()

        lifecycle = RetentionLifecycle(db, s3)
        ref_date = datetime(2026, 2, 15, tzinfo=timezone.utc)
        result = await lifecycle.run_monthly_export(reference_date=ref_date)

        assert result["verified"] is True
        assert len(result["file_hash"]) == 64  # SHA-256 hex

    @pytest.mark.asyncio
    async def test_export_empty_partition_skips(self):
        """Empty partition returns skipped status."""
        db = _mock_db([])
        s3 = _mock_s3()

        lifecycle = RetentionLifecycle(db, s3)
        ref_date = datetime(2026, 2, 15, tzinfo=timezone.utc)
        result = await lifecycle.run_monthly_export(reference_date=ref_date)

        assert result["exported_count"] == 0
        assert result["skipped"] == "no_records"
        s3.put_object.assert_not_called()

    @pytest.mark.asyncio
    async def test_partition_identified_correctly(self):
        """Export targets partition from 2 months ago."""
        db = _mock_db([])
        s3 = _mock_s3()

        lifecycle = RetentionLifecycle(db, s3)

        # Feb 2026 → export Dec 2025
        result = await lifecycle.run_monthly_export(
            reference_date=datetime(2026, 2, 15, tzinfo=timezone.utc)
        )
        assert result["partition_name"] == "audit_records_2025_12"

        # Mar 2026 → export Jan 2026
        result = await lifecycle.run_monthly_export(
            reference_date=datetime(2026, 3, 15, tzinfo=timezone.utc)
        )
        assert result["partition_name"] == "audit_records_2026_01"

    @pytest.mark.asyncio
    async def test_buffer_enforced_on_drop(self):
        """Cannot drop partition within 1-month buffer of current date."""
        db = _mock_db()
        s3 = _mock_s3()

        lifecycle = RetentionLifecycle(db, s3)

        # Try to drop current month's partition — should be refused
        now = datetime.now(timezone.utc)
        current_partition = _partition_name(now)
        result = await lifecycle.drop_old_partition(current_partition, verified=True)
        assert result is False

    @pytest.mark.asyncio
    async def test_unverified_export_blocks_drop(self):
        """Cannot drop partition if export was not verified."""
        db = _mock_db()
        s3 = _mock_s3()

        lifecycle = RetentionLifecycle(db, s3)
        result = await lifecycle.drop_old_partition("audit_records_2024_01", verified=False)
        assert result is False


# ---------------------------------------------------------------------------
# TestLegalHold
# ---------------------------------------------------------------------------

class TestLegalHold:
    """AC-2: Legal hold tenants' data is NOT dropped."""

    @pytest.mark.asyncio
    async def test_legal_hold_blocks_drop(self):
        """Partition with legal hold tenant data is NOT dropped."""
        db = _mock_db()
        db.fetch_one = AsyncMock(return_value={"cnt": 5})  # legal hold data found
        s3 = _mock_s3()

        lifecycle = RetentionLifecycle(db, s3, legal_hold_tenants={"tenant-legal"})

        result = await lifecycle.drop_old_partition(
            "audit_records_2024_06", verified=True,
        )
        assert result is False
        db.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_legal_hold_allows_drop(self):
        """Partition without legal hold data can be dropped."""
        db = _mock_db()
        db.fetch_one = AsyncMock(return_value={"cnt": 0})  # no legal hold data
        s3 = _mock_s3()

        lifecycle = RetentionLifecycle(db, s3, legal_hold_tenants={"tenant-legal"})

        result = await lifecycle.drop_old_partition(
            "audit_records_2024_06", verified=True,
        )
        assert result is True
        db.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_empty_legal_hold_set_allows_drop(self):
        """No legal hold tenants → drop proceeds normally."""
        db = _mock_db()
        s3 = _mock_s3()

        lifecycle = RetentionLifecycle(db, s3)

        result = await lifecycle.drop_old_partition(
            "audit_records_2024_06", verified=True,
        )
        assert result is True


# ---------------------------------------------------------------------------
# TestLifecycleConfig
# ---------------------------------------------------------------------------

class TestLifecycleConfig:
    """AC-3: S3 lifecycle rules are valid and correctly configured."""

    def test_lifecycle_json_is_valid(self):
        """Lifecycle JSON is valid and parseable."""
        import os
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "infra", "s3-lifecycle",
            "audit-cold-lifecycle.json",
        )
        with open(config_path) as f:
            config = json.load(f)

        assert "Rules" in config
        assert len(config["Rules"]) >= 1

    def test_transition_days_correct(self):
        """Glacier at 365d, Deep Archive at 730d, expire at 2555d (7yr)."""
        import os
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "infra", "s3-lifecycle",
            "audit-cold-lifecycle.json",
        )
        with open(config_path) as f:
            config = json.load(f)

        rule = config["Rules"][0]
        transitions = rule["Transitions"]

        glacier = next(t for t in transitions if t["StorageClass"] == "GLACIER")
        assert glacier["Days"] == 365

        deep = next(t for t in transitions if t["StorageClass"] == "DEEP_ARCHIVE")
        assert deep["Days"] == 730

        assert rule["Expiration"]["Days"] == 2555


# ---------------------------------------------------------------------------
# TestPartitionManagement
# ---------------------------------------------------------------------------

class TestPartitionManagement:
    """AC-1,4: Partition creation and listing."""

    @pytest.mark.asyncio
    async def test_create_next_partitions(self):
        """Creates correct number of future partitions."""
        db = _mock_db()
        s3 = _mock_s3()

        lifecycle = RetentionLifecycle(db, s3)
        created = await lifecycle.create_next_partitions(count=3)

        assert len(created) == 3
        assert db.execute.call_count == 3

    @pytest.mark.asyncio
    async def test_list_partitions(self):
        """Lists partitions with metadata."""
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[
            {"partition_name": "audit_records_2026_01"},
            {"partition_name": "audit_records_2026_02"},
        ])
        db.fetch_one = AsyncMock(return_value={"cnt": 42})
        s3 = _mock_s3()

        lifecycle = RetentionLifecycle(db, s3)
        partitions = await lifecycle.list_partitions()

        assert len(partitions) == 2
        assert partitions[0]["partition_name"] == "audit_records_2026_01"
        assert partitions[0]["row_count"] == 42

    @pytest.mark.asyncio
    async def test_partition_names_follow_convention(self):
        """Partition names match audit_records_YYYY_MM pattern."""
        created = await _create_and_check_partitions()
        for name in created:
            assert name.startswith("audit_records_")
            parts = name.replace("audit_records_", "").split("_")
            assert len(parts) == 2
            assert len(parts[0]) == 4  # YYYY
            assert len(parts[1]) == 2  # MM


async def _create_and_check_partitions():
    db = _mock_db()
    s3 = _mock_s3()
    lifecycle = RetentionLifecycle(db, s3)
    return await lifecycle.create_next_partitions(count=2)


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestHelperFunctions:
    """Unit tests for date arithmetic helpers."""

    def test_subtract_months_same_year(self):
        dt = datetime(2026, 5, 15, tzinfo=timezone.utc)
        result = _subtract_months(dt, 2)
        assert result.month == 3
        assert result.year == 2026

    def test_subtract_months_cross_year(self):
        dt = datetime(2026, 2, 15, tzinfo=timezone.utc)
        result = _subtract_months(dt, 3)
        assert result.month == 11
        assert result.year == 2025

    def test_add_months_cross_year(self):
        dt = datetime(2026, 11, 1, tzinfo=timezone.utc)
        result = _add_months(dt, 3)
        assert result.month == 2
        assert result.year == 2027

    def test_partition_name_format(self):
        dt = datetime(2026, 1, 15, tzinfo=timezone.utc)
        assert _partition_name(dt) == "audit_records_2026_01"

    def test_parse_partition_date(self):
        result = _parse_partition_date("audit_records_2025_12")
        assert result is not None
        assert result.year == 2025
        assert result.month == 12

    def test_records_to_parquet_returns_bytes(self):
        records = _make_records(2)
        result = _records_to_parquet(records)
        assert isinstance(result, bytes)
        assert len(result) > 0
