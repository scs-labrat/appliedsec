"""Tests for Anthropic API client wrapper — Story 5.5."""

from __future__ import annotations

from context_gateway.anthropic_client import (
    DEFAULT_PRICING,
    APICallMetrics,
    compute_cost,
)


class TestAPICallMetrics:
    def test_default_values(self):
        m = APICallMetrics()
        assert m.input_tokens == 0
        assert m.output_tokens == 0
        assert m.cache_read_tokens == 0
        assert m.cache_write_tokens == 0
        assert m.cost_usd == 0.0
        assert m.latency_ms == 0.0
        assert m.model_id == ""

    def test_custom_values(self):
        m = APICallMetrics(
            input_tokens=1000,
            output_tokens=500,
            cache_read_tokens=200,
            cache_write_tokens=50,
            cost_usd=0.005,
            latency_ms=1234.5,
            model_id="claude-sonnet-4-5-20250929",
        )
        assert m.input_tokens == 1000
        assert m.output_tokens == 500
        assert m.latency_ms == 1234.5


class TestComputeCost:
    def test_sonnet_pricing(self):
        m = APICallMetrics(
            input_tokens=1000,
            output_tokens=500,
            model_id="claude-sonnet-4-5-20250929",
        )
        cost = compute_cost(m)
        expected = 1000 * 3.0 / 1_000_000 + 500 * 15.0 / 1_000_000
        assert abs(cost - expected) < 1e-6

    def test_haiku_pricing(self):
        m = APICallMetrics(
            input_tokens=1000,
            output_tokens=500,
            model_id="claude-haiku-4-5-20251001",
        )
        cost = compute_cost(m)
        expected = 1000 * 0.80 / 1_000_000 + 500 * 4.0 / 1_000_000
        assert abs(cost - expected) < 1e-6

    def test_cache_tokens_counted(self):
        m = APICallMetrics(
            input_tokens=0,
            output_tokens=0,
            cache_read_tokens=1000,
            cache_write_tokens=100,
            model_id="claude-sonnet-4-5-20250929",
        )
        cost = compute_cost(m)
        assert cost > 0

    def test_custom_pricing(self):
        m = APICallMetrics(input_tokens=1000, output_tokens=500)
        pricing = {"input": 0.001, "output": 0.002}
        cost = compute_cost(m, pricing)
        assert abs(cost - (1.0 + 1.0)) < 1e-6

    def test_unknown_model_zero_cost(self):
        m = APICallMetrics(input_tokens=1000, model_id="unknown-model")
        cost = compute_cost(m)
        assert cost == 0.0

    def test_zero_tokens_zero_cost(self):
        m = APICallMetrics(model_id="claude-sonnet-4-5-20250929")
        cost = compute_cost(m)
        assert cost == 0.0


class TestDefaultPricing:
    def test_sonnet_pricing_defined(self):
        assert "claude-sonnet-4-5-20250929" in DEFAULT_PRICING
        p = DEFAULT_PRICING["claude-sonnet-4-5-20250929"]
        assert "input" in p
        assert "output" in p
        assert "cache_read" in p
        assert "cache_write" in p

    def test_haiku_pricing_defined(self):
        assert "claude-haiku-4-5-20251001" in DEFAULT_PRICING

    def test_haiku_cheaper_than_sonnet(self):
        h = DEFAULT_PRICING["claude-haiku-4-5-20251001"]
        s = DEFAULT_PRICING["claude-sonnet-4-5-20250929"]
        assert h["input"] < s["input"]
        assert h["output"] < s["output"]
