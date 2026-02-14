"""Tests for routing metrics and outcome tracking — Story 6.4."""

import pytest

from llm_router.metrics import RoutingMetrics, TierOutcome


# ---------- TierOutcome dataclass ---------------------------------------------

class TestTierOutcome:
    def test_defaults(self):
        o = TierOutcome()
        assert o.total == 0
        assert o.success == 0
        assert o.total_cost_usd == 0.0

    def test_success_rate(self):
        o = TierOutcome(total=10, success=7)
        assert o.success_rate == pytest.approx(0.7)

    def test_success_rate_zero_total(self):
        o = TierOutcome()
        assert o.success_rate == 0.0

    def test_avg_cost(self):
        o = TierOutcome(total=4, total_cost_usd=2.0)
        assert o.avg_cost == pytest.approx(0.5)

    def test_avg_cost_zero_total(self):
        o = TierOutcome()
        assert o.avg_cost == 0.0

    def test_avg_latency(self):
        o = TierOutcome(total=5, total_latency_ms=500.0)
        assert o.avg_latency_ms == pytest.approx(100.0)

    def test_avg_latency_zero_total(self):
        o = TierOutcome()
        assert o.avg_latency_ms == 0.0

    def test_avg_confidence(self):
        o = TierOutcome(total=4, confidence_sum=3.2)
        assert o.avg_confidence == pytest.approx(0.8)

    def test_avg_confidence_zero_total(self):
        o = TierOutcome()
        assert o.avg_confidence == 0.0


# ---------- RoutingMetrics core -----------------------------------------------

class TestRoutingMetrics:
    def test_empty_metrics(self):
        m = RoutingMetrics()
        assert m.get_all_outcomes() == {}

    def test_record_single_success(self):
        m = RoutingMetrics()
        m.record_outcome(
            "ioc_extraction", "tier_0",
            success=True, cost_usd=0.01, latency_ms=50, confidence=0.9,
        )
        o = m.get_outcome("ioc_extraction", "tier_0")
        assert o is not None
        assert o.total == 1
        assert o.success == 1
        assert o.total_cost_usd == pytest.approx(0.01)
        assert o.total_latency_ms == pytest.approx(50.0)
        assert o.confidence_sum == pytest.approx(0.9)

    def test_record_failure(self):
        m = RoutingMetrics()
        m.record_outcome("investigation", "tier_1", success=False)
        o = m.get_outcome("investigation", "tier_1")
        assert o.total == 1
        assert o.success == 0

    def test_multiple_records_accumulate(self):
        m = RoutingMetrics()
        m.record_outcome("ioc_extraction", "tier_0", success=True, cost_usd=0.01)
        m.record_outcome("ioc_extraction", "tier_0", success=True, cost_usd=0.02)
        m.record_outcome("ioc_extraction", "tier_0", success=False, cost_usd=0.01)
        o = m.get_outcome("ioc_extraction", "tier_0")
        assert o.total == 3
        assert o.success == 2
        assert o.total_cost_usd == pytest.approx(0.04)

    def test_separate_keys(self):
        m = RoutingMetrics()
        m.record_outcome("ioc_extraction", "tier_0", success=True)
        m.record_outcome("investigation", "tier_1", success=True)
        assert len(m.get_all_outcomes()) == 2

    def test_get_nonexistent(self):
        m = RoutingMetrics()
        assert m.get_outcome("nope", "tier_0") is None


# ---------- Summary -----------------------------------------------------------

class TestSummary:
    def test_empty_summary(self):
        m = RoutingMetrics()
        assert m.summary() == {}

    def test_summary_structure(self):
        m = RoutingMetrics()
        m.record_outcome(
            "ioc_extraction", "tier_0",
            success=True, cost_usd=0.02, latency_ms=100, confidence=0.85,
        )
        m.record_outcome(
            "ioc_extraction", "tier_0",
            success=False, cost_usd=0.01, latency_ms=200, confidence=0.4,
        )
        s = m.summary()
        entry = s["ioc_extraction:tier_0"]
        assert entry["total"] == 2
        assert entry["success_rate"] == pytest.approx(0.5)
        assert entry["avg_cost"] == pytest.approx(0.015)
        assert entry["avg_latency_ms"] == pytest.approx(150.0)
        assert entry["avg_confidence"] == pytest.approx(0.625)

    def test_summary_keys(self):
        m = RoutingMetrics()
        m.record_outcome("a", "t0", success=True)
        m.record_outcome("b", "t1", success=True)
        s = m.summary()
        assert set(s.keys()) == {"a:t0", "b:t1"}

    def test_summary_values_are_dicts(self):
        m = RoutingMetrics()
        m.record_outcome("x", "y", success=True)
        for v in m.summary().values():
            assert isinstance(v, dict)
            expected_keys = {"total", "success_rate", "avg_cost", "avg_latency_ms", "avg_confidence"}
            assert set(v.keys()) == expected_keys


# ---------- Integration scenario ----------------------------------------------

class TestMetricsIntegration:
    def test_realistic_scenario(self):
        """Simulate a realistic sequence of routing outcomes."""
        m = RoutingMetrics()

        # 10 IOC extractions via Haiku — 9 succeed
        for i in range(10):
            m.record_outcome(
                "ioc_extraction", "tier_0",
                success=i < 9,
                cost_usd=0.005,
                latency_ms=80 + i * 5,
                confidence=0.85 + i * 0.01,
            )

        # 5 investigations via Sonnet — 4 succeed
        for i in range(5):
            m.record_outcome(
                "investigation", "tier_1",
                success=i < 4,
                cost_usd=0.05,
                latency_ms=500 + i * 50,
                confidence=0.7 + i * 0.05,
            )

        ioc = m.get_outcome("ioc_extraction", "tier_0")
        assert ioc.success_rate == pytest.approx(0.9)
        assert ioc.total == 10

        inv = m.get_outcome("investigation", "tier_1")
        assert inv.success_rate == pytest.approx(0.8)
        assert inv.total == 5

        s = m.summary()
        assert len(s) == 2
        assert s["ioc_extraction:tier_0"]["total"] == 10
        assert s["investigation:tier_1"]["total"] == 5
