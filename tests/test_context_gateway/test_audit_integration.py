"""Tests for AuditProducer integration in Context Gateway — Story 13.8, Task 3."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from context_gateway.gateway import ContextGateway, GatewayRequest
from context_gateway.anthropic_client import APICallMetrics


def _make_gateway(audit_producer=None):
    """Create ContextGateway with mocked client and optional AuditProducer."""
    client = AsyncMock()
    client.complete = AsyncMock(return_value=(
        '{"classification": "true_positive"}',
        APICallMetrics(
            model_id="claude-sonnet-4-6",
            input_tokens=100,
            output_tokens=50,
            cost_usd=0.001,
            latency_ms=500,
            cache_read_tokens=0,
            cache_write_tokens=0,
        ),
    ))
    gw = ContextGateway(client=client, audit_producer=audit_producer)
    return gw


class TestGatewayAudit:
    """AC-3: routing.tier_selected and technique.quarantined emitted via AuditProducer."""

    @pytest.mark.asyncio
    async def test_routing_tier_selected_emitted(self):
        """After LLM call, routing.tier_selected emitted with LLM context."""
        audit = MagicMock()
        gw = _make_gateway(audit_producer=audit)

        req = GatewayRequest(
            agent_id="reasoning",
            task_type="investigation",
            system_prompt="You are a SOC analyst",
            user_content="Analyze this alert",
            tenant_id="t1",
        )

        with patch("context_gateway.gateway.sanitise_input", return_value=("Analyze this alert", [])), \
             patch("context_gateway.gateway.redact_pii", return_value=("Analyze this alert", {})), \
             patch("context_gateway.gateway.build_cached_system_blocks", return_value=[]), \
             patch("context_gateway.gateway.validate_output", return_value=(True, [], [])), \
             patch("context_gateway.gateway.deanonymise_text", return_value='{"classification": "true_positive"}'):
            await gw.complete(req)

        tier_calls = [c for c in audit.emit.call_args_list
                      if c[1].get("event_type") == "routing.tier_selected"]
        assert len(tier_calls) == 1
        ctx = tier_calls[0][1]["context"]
        assert ctx["llm_model_id"] == "claude-sonnet-4-6"
        assert ctx["llm_input_tokens"] == 100
        assert ctx["llm_output_tokens"] == 50

    @pytest.mark.asyncio
    async def test_technique_quarantined_via_audit_producer(self):
        """Quarantine events use AuditProducer.emit instead of raw produce."""
        audit = MagicMock()
        gw = _make_gateway(audit_producer=audit)

        req = GatewayRequest(
            agent_id="reasoning",
            task_type="investigation",
            system_prompt="System",
            user_content="Content",
            tenant_id="t1",
        )

        with patch("context_gateway.gateway.sanitise_input", return_value=("Content", [])), \
             patch("context_gateway.gateway.redact_pii", return_value=("Content", {})), \
             patch("context_gateway.gateway.build_cached_system_blocks", return_value=[]), \
             patch("context_gateway.gateway.validate_output", return_value=(True, [], ["T1059.001"])), \
             patch("context_gateway.gateway.deanonymise_text", return_value="clean"):
            await gw.complete(req)

        quarantine_calls = [c for c in audit.emit.call_args_list
                            if c[1].get("event_type") == "technique.quarantined"]
        assert len(quarantine_calls) == 1
        assert quarantine_calls[0][1]["context"]["technique_id"] == "T1059.001"

    @pytest.mark.asyncio
    async def test_no_exception_when_audit_producer_is_none(self):
        """Backward compat: gateway works without audit_producer."""
        gw = _make_gateway(audit_producer=None)

        req = GatewayRequest(
            agent_id="reasoning",
            task_type="investigation",
            system_prompt="System",
            user_content="Content",
            tenant_id="t1",
        )

        with patch("context_gateway.gateway.sanitise_input", return_value=("Content", [])), \
             patch("context_gateway.gateway.redact_pii", return_value=("Content", {})), \
             patch("context_gateway.gateway.build_cached_system_blocks", return_value=[]), \
             patch("context_gateway.gateway.validate_output", return_value=(True, [], [])), \
             patch("context_gateway.gateway.deanonymise_text", return_value="clean"):
            resp = await gw.complete(req)
            assert resp.valid is True

    @pytest.mark.asyncio
    async def test_audit_emit_failure_does_not_block_gateway(self):
        """Fire-and-forget: audit failures don't affect gateway response."""
        audit = MagicMock()
        audit.emit.side_effect = Exception("Kafka down")
        gw = _make_gateway(audit_producer=audit)

        req = GatewayRequest(
            agent_id="reasoning",
            task_type="investigation",
            system_prompt="System",
            user_content="Content",
            tenant_id="t1",
        )

        with patch("context_gateway.gateway.sanitise_input", return_value=("Content", [])), \
             patch("context_gateway.gateway.redact_pii", return_value=("Content", {})), \
             patch("context_gateway.gateway.build_cached_system_blocks", return_value=[]), \
             patch("context_gateway.gateway.validate_output", return_value=(True, [], [])), \
             patch("context_gateway.gateway.deanonymise_text", return_value="clean"):
            resp = await gw.complete(req)
            assert resp.valid is True
