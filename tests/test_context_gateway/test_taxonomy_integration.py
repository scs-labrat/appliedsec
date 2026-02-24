"""Integration tests for taxonomy validation — Story 12.1.

Tests the full pipeline: Postgres lookup → validate_output → deny-by-default
stripping → Kafka quarantine event publishing.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from context_gateway.anthropic_client import APICallMetrics
from context_gateway.gateway import ContextGateway, GatewayRequest, GatewayResponse


# ---- helpers ----------------------------------------------------------------

def _make_mock_client(response_text: str = '{"verdict": "malicious"}') -> MagicMock:
    """Create a mocked AluskortAnthropicClient."""
    client = MagicMock()
    metrics = APICallMetrics(
        input_tokens=500,
        output_tokens=200,
        cost_usd=0.005,
        model_id="claude-sonnet-4-5-20250929",
        latency_ms=1500.0,
    )
    client.complete = AsyncMock(return_value=(response_text, metrics))
    return client


# ---- Task 3: taxonomy lookup wired at init ----------------------------------

class TestTaxonomyLoadedAtInit:
    """AC 1, 2: known_technique_ids loaded from Postgres at init."""

    def test_gateway_accepts_known_ids(self):
        gw = ContextGateway(
            client=_make_mock_client(),
            known_technique_ids={"T1059.001", "T1078"},
        )
        assert gw.known_technique_ids == {"T1059.001", "T1078"}

    def test_gateway_none_when_no_ids_provided(self):
        gw = ContextGateway(client=_make_mock_client())
        assert gw.known_technique_ids is None


# ---- Task 4: deny-by-default enforcement -----------------------------------

class TestDenyByDefault:
    """AC 3: Quarantined IDs stripped from automation fields, preserved in raw_output."""

    @pytest.mark.asyncio
    async def test_quarantined_ids_stripped_from_json_content(self):
        """When LLM returns JSON with hallucinated technique IDs in
        automation-driving fields, those IDs are stripped."""
        llm_response = json.dumps({
            "verdict": "malicious",
            "techniques": ["T1059.001", "T9999"],
            "classification": "T9999 lateral movement",
            "recommended_actions": ["Block T9999 activity"],
        })
        gw = ContextGateway(
            client=_make_mock_client(response_text=llm_response),
            known_technique_ids={"T1059.001"},
        )
        request = GatewayRequest(
            agent_id="test",
            task_type="reasoning",
            system_prompt="Analyze this alert.",
            user_content="Normal alert text.",
        )
        response = await gw.complete(request)
        # Quarantined IDs should be reported
        assert "T9999" in response.quarantined_ids
        # raw_output preserves original LLM response
        assert "T9999" in response.raw_output
        # Content should have T9999 stripped
        assert "T9999" not in response.content

    @pytest.mark.asyncio
    async def test_valid_ids_not_stripped(self):
        """Valid technique IDs in known_technique_ids are NOT stripped."""
        llm_response = json.dumps({
            "verdict": "malicious",
            "techniques": ["T1059.001"],
        })
        gw = ContextGateway(
            client=_make_mock_client(response_text=llm_response),
            known_technique_ids={"T1059.001"},
        )
        request = GatewayRequest(
            agent_id="test",
            task_type="reasoning",
            system_prompt="Analyze.",
            user_content="Alert.",
        )
        response = await gw.complete(request)
        assert "T1059.001" in response.content
        assert len(response.quarantined_ids) == 0

    @pytest.mark.asyncio
    async def test_raw_output_always_set(self):
        """raw_output is always populated with original LLM response."""
        llm_response = "Simple text with T1059.001"
        gw = ContextGateway(
            client=_make_mock_client(response_text=llm_response),
            known_technique_ids={"T1059.001"},
        )
        request = GatewayRequest(
            agent_id="test",
            task_type="triage",
            system_prompt="Triage.",
            user_content="Alert.",
        )
        response = await gw.complete(request)
        assert response.raw_output == llm_response


# ---- Task 5: Kafka quarantine event publishing ------------------------------

class TestKafkaQuarantineEvents:
    """AC 5: Events published to audit.events for quarantined IDs."""

    @pytest.mark.asyncio
    async def test_quarantine_event_published(self):
        """When a technique ID is quarantined, a Kafka event is produced."""
        llm_response = json.dumps({"techniques": ["T9999"]})
        mock_producer = MagicMock()
        gw = ContextGateway(
            client=_make_mock_client(response_text=llm_response),
            known_technique_ids={"T1059.001"},
            audit_producer=mock_producer,
        )
        request = GatewayRequest(
            agent_id="test",
            task_type="reasoning",
            system_prompt="Analyze.",
            user_content="Alert.",
        )
        await gw.complete(request)
        # AuditProducer.emit() should have been called for quarantine
        quarantine_calls = [c for c in mock_producer.emit.call_args_list
                            if c[1].get("event_type") == "technique.quarantined"]
        assert len(quarantine_calls) >= 1
        assert quarantine_calls[0][1]["context"]["technique_id"] == "T9999"

    @pytest.mark.asyncio
    async def test_no_event_when_no_quarantine(self):
        """No Kafka event when all IDs are valid."""
        llm_response = json.dumps({"techniques": ["T1059.001"]})
        mock_producer = MagicMock()
        gw = ContextGateway(
            client=_make_mock_client(response_text=llm_response),
            known_technique_ids={"T1059.001"},
            audit_producer=mock_producer,
        )
        request = GatewayRequest(
            agent_id="test",
            task_type="reasoning",
            system_prompt="Analyze.",
            user_content="Alert.",
        )
        await gw.complete(request)
        quarantine_calls = [c for c in mock_producer.emit.call_args_list
                            if c[1].get("event_type") == "technique.quarantined"]
        assert len(quarantine_calls) == 0

    @pytest.mark.asyncio
    async def test_no_crash_without_producer(self):
        """Gateway works fine without an audit producer (graceful degradation)."""
        llm_response = json.dumps({"techniques": ["T9999"]})
        gw = ContextGateway(
            client=_make_mock_client(response_text=llm_response),
            known_technique_ids={"T1059.001"},
        )
        request = GatewayRequest(
            agent_id="test",
            task_type="reasoning",
            system_prompt="Analyze.",
            user_content="Alert.",
        )
        response = await gw.complete(request)
        assert "T9999" in response.quarantined_ids
