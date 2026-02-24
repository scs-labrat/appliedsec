"""Tests for AuditProducer integration in LLM Router — Story 13.8, Task 4."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from llm_router.router import LLMRouter
from llm_router.models import ModelTier, TaskContext


def _make_ctx(**overrides):
    defaults = {
        "task_type": "ioc_extraction",
        "alert_severity": "medium",
        "context_tokens": 1000,
        "time_budget_seconds": 10,
        "requires_reasoning": False,
    }
    defaults.update(overrides)
    return TaskContext(**defaults)


class TestRouterAudit:
    """AC-4: routing.provider_failover and circuit_breaker events emitted."""

    def test_provider_failover_emitted_on_fallback(self):
        """When primary is unavailable and fallback used, emit routing.provider_failover."""
        audit = MagicMock()
        health = MagicMock()
        health.is_available = MagicMock(side_effect=lambda p: p.value != "anthropic")
        health.compute_degradation_level = MagicMock(return_value=MagicMock(value="degraded"))

        router = LLMRouter(health_registry=health, audit_producer=audit)
        ctx = _make_ctx()
        decision = router.route(ctx)

        failover_calls = [c for c in audit.emit.call_args_list
                          if c[1].get("event_type") == "routing.provider_failover"]
        assert len(failover_calls) == 1
        assert failover_calls[0][1]["tenant_id"] == "unknown"
        assert "primary_provider" in failover_calls[0][1]["context"]

    def test_no_failover_event_when_primary_available(self):
        """No failover event when primary provider is healthy."""
        audit = MagicMock()
        health = MagicMock()
        health.is_available = MagicMock(return_value=True)
        health.compute_degradation_level = MagicMock(return_value=MagicMock(value="full_capability"))

        router = LLMRouter(health_registry=health, audit_producer=audit)
        ctx = _make_ctx()
        router.route(ctx)

        failover_calls = [c for c in audit.emit.call_args_list
                          if c[1].get("event_type") == "routing.provider_failover"]
        assert len(failover_calls) == 0

    def test_no_exception_when_audit_producer_is_none(self):
        """Backward compat: router works without audit_producer."""
        router = LLMRouter()
        ctx = _make_ctx()
        decision = router.route(ctx)
        assert decision.tier is not None

    def test_audit_emit_failure_does_not_block_routing(self):
        """Fire-and-forget: audit failures don't affect routing."""
        audit = MagicMock()
        audit.emit.side_effect = Exception("Kafka down")
        health = MagicMock()
        health.is_available = MagicMock(side_effect=lambda p: p.value != "anthropic")
        health.compute_degradation_level = MagicMock(return_value=MagicMock(value="degraded"))

        router = LLMRouter(health_registry=health, audit_producer=audit)
        ctx = _make_ctx()
        decision = router.route(ctx)
        assert decision.tier is not None
