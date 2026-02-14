"""Tests for FP Short-Circuit — Story 7.9."""

import pytest
from unittest.mock import AsyncMock

from shared.schemas.investigation import GraphState, InvestigationState
from orchestrator.fp_shortcircuit import (
    FPMatchResult,
    FPShortCircuit,
    FP_CONFIDENCE_THRESHOLD,
    _safe_regex_match,
    _cidr_match,
)


@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    redis.list_fp_patterns = AsyncMock(return_value=[])
    redis.get_fp_pattern = AsyncMock(return_value=None)
    return redis


@pytest.fixture
def fp(mock_redis):
    return FPShortCircuit(redis_client=mock_redis)


@pytest.fixture
def state():
    return GraphState(
        investigation_id="inv-001",
        entities={
            "accounts": [{"primary_value": "service-account-01"}],
            "ips": [{"primary_value": "10.0.1.50"}],
        },
    )


class TestFPCheck:
    @pytest.mark.asyncio
    async def test_no_patterns_no_match(self, fp, state):
        result = await fp.check(state, "Some Alert Title")
        assert result.matched is False

    @pytest.mark.asyncio
    async def test_matching_pattern(self, fp, state, mock_redis):
        mock_redis.list_fp_patterns.return_value = ["fp:FP-001"]
        mock_redis.get_fp_pattern.return_value = {
            "pattern_id": "FP-001",
            "alert_name_regex": ".*Exchange.*Unusual Activity.*",
            "entity_patterns": [
                {"type": "account", "value_regex": ".*service-account.*"},
            ],
            "min_confidence": 0.90,
            "status": "approved",
        }
        result = await fp.check(
            state, "Exchange Unusual Activity Detected"
        )
        assert result.matched is True
        assert result.pattern_id == "FP-001"
        assert result.confidence >= FP_CONFIDENCE_THRESHOLD

    @pytest.mark.asyncio
    async def test_unapproved_pattern_skipped(self, fp, state, mock_redis):
        mock_redis.list_fp_patterns.return_value = ["fp:FP-002"]
        mock_redis.get_fp_pattern.return_value = {
            "pattern_id": "FP-002",
            "alert_name_regex": ".*",
            "entity_patterns": [],
            "status": "pending_review",
        }
        result = await fp.check(state, "Any Alert")
        assert result.matched is False

    @pytest.mark.asyncio
    async def test_low_confidence_no_match(self, fp, state, mock_redis):
        mock_redis.list_fp_patterns.return_value = ["fp:FP-003"]
        mock_redis.get_fp_pattern.return_value = {
            "pattern_id": "FP-003",
            "alert_name_regex": ".*Totally Different.*",
            "entity_patterns": [
                {"type": "account", "value_regex": ".*admin.*"},
            ],
            "status": "approved",
        }
        result = await fp.check(state, "Exchange Alert")
        assert result.matched is False

    @pytest.mark.asyncio
    async def test_cidr_entity_match(self, fp, state, mock_redis):
        mock_redis.list_fp_patterns.return_value = ["fp:FP-004"]
        mock_redis.get_fp_pattern.return_value = {
            "pattern_id": "FP-004",
            "alert_name_regex": ".*",
            "entity_patterns": [
                {"type": "ip", "value_cidr": "10.0.0.0/8"},
            ],
            "status": "approved",
        }
        result = await fp.check(state, "Any Alert Title")
        assert result.matched is True

    @pytest.mark.asyncio
    async def test_tracks_queries(self, fp, state, mock_redis):
        mock_redis.list_fp_patterns.return_value = ["fp:FP-001"]
        mock_redis.get_fp_pattern.return_value = {
            "status": "approved",
            "alert_name_regex": "nope",
            "entity_patterns": [],
        }
        result = await fp.check(state, "Alert")
        assert state.queries_executed >= 2  # list + get


class TestApplyShortCircuit:
    def test_closes_investigation(self, fp, state):
        match = FPMatchResult(matched=True, pattern_id="FP-001", confidence=0.95)
        result = fp.apply_shortcircuit(state, match)
        assert result.state == InvestigationState.CLOSED
        assert result.classification == "false_positive"
        assert result.confidence == 0.95

    def test_appends_decision_chain(self, fp, state):
        match = FPMatchResult(matched=True, pattern_id="FP-001", confidence=0.95)
        result = fp.apply_shortcircuit(state, match)
        assert len(result.decision_chain) == 1
        assert result.decision_chain[0]["agent"] == "fp_short_circuit"
        assert result.decision_chain[0]["pattern_id"] == "FP-001"


class TestFPMatchResult:
    def test_no_match(self):
        r = FPMatchResult(matched=False)
        assert r.matched is False
        assert r.pattern_id == ""
        assert r.confidence == 0.0

    def test_match(self):
        r = FPMatchResult(matched=True, pattern_id="FP-X", confidence=0.92)
        assert r.matched is True
        assert r.pattern_id == "FP-X"


class TestHelpers:
    def test_safe_regex_match(self):
        assert _safe_regex_match(".*test.*", "this is a test") is True
        assert _safe_regex_match("^exact$", "not exact") is False

    def test_safe_regex_invalid(self):
        assert _safe_regex_match("[invalid", "text") is False

    def test_cidr_match_v4(self):
        assert _cidr_match("10.0.0.0/8", "10.0.1.50") is True
        assert _cidr_match("192.168.0.0/16", "10.0.1.50") is False

    def test_cidr_match_invalid(self):
        assert _cidr_match("not_a_cidr", "10.0.0.1") is False
        assert _cidr_match("10.0.0.0/8", "not_an_ip") is False

    def test_threshold_constant(self):
        assert FP_CONFIDENCE_THRESHOLD == 0.90
