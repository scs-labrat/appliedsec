"""Tests for Postgres upsert logic — Story 8.5."""

import pytest
from unittest.mock import AsyncMock

from ctem_normaliser.models import CTEMExposure
from ctem_normaliser.upsert import CTEMRepository, _UPSERT_SQL


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.execute = AsyncMock()
    db.fetch_one = AsyncMock(return_value=None)
    db.fetch_many = AsyncMock(return_value=[])
    return db


@pytest.fixture
def repo(mock_db):
    return CTEMRepository(mock_db)


@pytest.fixture
def exposure():
    return CTEMExposure(
        exposure_key="abc123def456abcd",
        ts="2026-01-15T10:00:00Z",
        source_tool="wiz",
        title="S3 Public Access",
        description="Public S3 bucket",
        severity="HIGH",
        original_severity="HIGH",
        asset_id="arn:aws:s3:::bucket",
        asset_type="s3",
        asset_zone="Zone3_Enterprise",
        exploitability_score=0.9,
        physical_consequence="data_loss",
        ctem_score=2.7,
        atlas_technique="",
        attack_technique="",
        status="Open",
        sla_deadline="2026-01-18T10:00:00Z",
        tenant_id="tenant-A",
    )


class TestUpsert:
    @pytest.mark.asyncio
    async def test_upsert_calls_execute(self, repo, mock_db, exposure):
        await repo.upsert(exposure)
        mock_db.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_upsert_uses_parameterised_sql(self, repo, mock_db, exposure):
        await repo.upsert(exposure)
        sql = mock_db.execute.call_args[0][0]
        assert "$1" in sql
        assert "$22" in sql
        # No string interpolation
        assert "%" not in sql
        assert "format" not in sql.lower()

    @pytest.mark.asyncio
    async def test_upsert_passes_22_params(self, repo, mock_db, exposure):
        await repo.upsert(exposure)
        args = mock_db.execute.call_args[0]
        # SQL + 22 params
        assert len(args) == 23

    @pytest.mark.asyncio
    async def test_upsert_preserves_verified_status(self, repo, mock_db, exposure):
        await repo.upsert(exposure)
        sql = mock_db.execute.call_args[0][0]
        assert "Verified" in sql
        assert "Closed" in sql

    @pytest.mark.asyncio
    async def test_on_conflict_clause(self, repo, mock_db, exposure):
        await repo.upsert(exposure)
        sql = mock_db.execute.call_args[0][0]
        assert "ON CONFLICT (exposure_key)" in sql
        assert "DO UPDATE SET" in sql

    @pytest.mark.asyncio
    async def test_upsert_param_order(self, repo, mock_db, exposure):
        await repo.upsert(exposure)
        args = mock_db.execute.call_args[0]
        assert args[1] == "abc123def456abcd"  # exposure_key
        assert args[3] == "wiz"  # source_tool
        assert args[4] == "S3 Public Access"  # title


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_returns_none(self, repo, mock_db):
        result = await repo.fetch("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_fetch_returns_row(self, repo, mock_db):
        mock_db.fetch_one.return_value = {"exposure_key": "abc", "severity": "HIGH"}
        result = await repo.fetch("abc")
        assert result["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_fetch_by_asset(self, repo, mock_db):
        mock_db.fetch_many.return_value = [
            {"exposure_key": "a", "severity": "HIGH"},
            {"exposure_key": "b", "severity": "MEDIUM"},
        ]
        results = await repo.fetch_by_asset("asset-1")
        assert len(results) == 2


class TestSQLSafety:
    def test_no_string_formatting(self):
        assert "%" not in _UPSERT_SQL
        assert "{" not in _UPSERT_SQL

    def test_uses_dollar_params(self):
        for i in range(1, 23):
            assert f"${i}" in _UPSERT_SQL
