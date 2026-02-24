"""Tests for context budget scaling — Story 15.1."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from context_gateway.prompt_builder import (
    CONTEXT_BUDGET_BY_TIER,
    DEFAULT_CONTEXT_BUDGET,
    SYSTEM_PREFIX,
    build_request_with_budget,
    get_context_budget,
    truncate_to_budget,
)
from orchestrator.agents.context_enricher import (
    CaseFacts,
    ContextEnricherAgent,
    extract_case_facts,
)
from shared.schemas.investigation import GraphState


# ---------------------------------------------------------------------------
# TestContextBudget (Task 1)
# ---------------------------------------------------------------------------

class TestContextBudget:
    """AC-1,2,3: Tier-based context budgets."""

    def test_tier_0_returns_4096(self):
        assert get_context_budget("tier_0") == 4_096

    def test_tier_1_returns_8192(self):
        assert get_context_budget("tier_1") == 8_192

    def test_tier_1_plus_returns_16384(self):
        assert get_context_budget("tier_1_plus") == 16_384

    def test_tier_2_returns_16384(self):
        assert get_context_budget("tier_2") == 16_384

    def test_unknown_tier_returns_default(self):
        assert get_context_budget("tier_unknown") == DEFAULT_CONTEXT_BUDGET

    def test_truncation_within_budget(self):
        """Text shorter than budget is returned unchanged."""
        text = "short text"
        result = truncate_to_budget(text, 1000)
        assert result == text

    def test_truncation_over_budget(self):
        """Text exceeding budget is truncated to budget * 4 chars."""
        text = "a" * 10_000
        result = truncate_to_budget(text, 100)
        # 100 tokens * 4 chars/token = 400 chars
        assert len(result) == 400

    def test_budget_dict_has_all_tiers(self):
        assert set(CONTEXT_BUDGET_BY_TIER.keys()) == {
            "tier_0", "tier_1", "tier_1_plus", "tier_2",
        }


# ---------------------------------------------------------------------------
# TestCaseFacts (Task 2)
# ---------------------------------------------------------------------------

class TestCaseFacts:
    """AC-4,5: Structured case facts extraction."""

    def test_extracts_entities(self):
        state = GraphState(
            investigation_id="inv-001",
            entities={
                "accounts": [{"primary_value": "jsmith@example.com"}],
                "hosts": [{"primary_value": "web-01"}],
                "ips": [],
            },
            ioc_matches=[],
        )
        facts = extract_case_facts(state)
        assert "jsmith@example.com" in facts.entities
        assert "web-01" in facts.entities

    def test_extracts_iocs(self):
        state = GraphState(
            investigation_id="inv-002",
            ioc_matches=[
                {"type": "ip", "value": "10.0.0.1"},
                {"type": "domain", "value": "evil.example"},
            ],
        )
        facts = extract_case_facts(state)
        assert len(facts.iocs) == 2
        assert facts.iocs[0]["value"] == "10.0.0.1"

    def test_extracts_techniques(self):
        state = GraphState(
            investigation_id="inv-003",
            entities={"techniques": ["T1566", "T1078"]},
        )
        facts = extract_case_facts(state)
        assert "T1566" in facts.techniques
        assert "T1078" in facts.techniques

    def test_token_estimate_nonzero(self):
        state = GraphState(
            investigation_id="inv-004",
            entities={"accounts": [{"primary_value": "user@example.com"}]},
            ioc_matches=[{"type": "ip", "value": "1.2.3.4"}],
        )
        facts = extract_case_facts(state)
        assert facts.token_estimate > 0

    def test_stored_in_graph_state(self):
        """case_facts field exists and defaults to empty dict."""
        gs = GraphState(investigation_id="inv-005")
        assert gs.case_facts == {}
        gs.case_facts = {"entities": ["host-1"], "token_estimate": 50}
        assert gs.case_facts["entities"] == ["host-1"]


# ---------------------------------------------------------------------------
# TestHierarchicalRetrieval (Task 3)
# ---------------------------------------------------------------------------

class TestHierarchicalRetrieval:
    """AC-4: Hierarchical two-pass retrieval."""

    @pytest.fixture
    def mock_redis(self):
        redis = AsyncMock()
        redis.get_ioc = AsyncMock(return_value=None)
        return redis

    @pytest.fixture
    def mock_postgres(self):
        pg = AsyncMock()
        pg.fetch_one = AsyncMock(return_value=None)
        return pg

    @pytest.fixture
    def mock_qdrant(self):
        qdrant = MagicMock()
        qdrant.search = MagicMock(return_value=[])
        return qdrant

    @pytest.fixture
    def agent(self, mock_redis, mock_postgres, mock_qdrant):
        return ContextEnricherAgent(mock_redis, mock_postgres, mock_qdrant)

    @pytest.fixture
    def state(self):
        return GraphState(
            investigation_id="inv-010",
            tenant_id="tenant-A",
            entities={
                "accounts": [{"primary_value": "jsmith@example.com"}],
                "hosts": [],
                "ips": [],
                "techniques": ["T1566"],
            },
            ioc_matches=[{"type": "ip", "value": "10.0.0.1"}],
        )

    @pytest.mark.asyncio
    async def test_tier_0_first_pass_only(self, agent, state, mock_postgres):
        """Tier 0: no deep retrieval, case_facts still populated."""
        result = await agent.execute(state, tier="tier_0")
        assert "entities" in result.case_facts
        assert "deep_context" not in result.case_facts
        # Postgres should NOT be called for technique intel
        calls = [c for c in mock_postgres.fetch_one.call_args_list
                 if "threat_intel" in str(c)]
        assert len(calls) == 0

    @pytest.mark.asyncio
    async def test_tier_1_plus_triggers_deep_retrieval(self, agent, state, mock_postgres):
        """Tier 1+: deep retrieval queries technique intel."""
        mock_postgres.fetch_one.return_value = None
        result = await agent.execute(state, tier="tier_1_plus")
        assert "deep_context" in result.case_facts
        # Should have queried for technique T1566
        calls = [c for c in mock_postgres.fetch_one.call_args_list
                 if "threat_intel" in str(c)]
        assert len(calls) >= 1

    @pytest.mark.asyncio
    async def test_default_tier_is_tier_0(self, agent, state):
        """Default tier parameter is tier_0 (backward compat)."""
        result = await agent.execute(state)
        assert "deep_context" not in result.case_facts

    @pytest.mark.asyncio
    async def test_case_facts_populated_after_first_pass(self, agent, state):
        """case_facts populated with entities, iocs, techniques."""
        result = await agent.execute(state, tier="tier_0")
        assert len(result.case_facts["iocs"]) >= 1
        assert "T1566" in result.case_facts["techniques"]
        assert result.case_facts["token_estimate"] > 0


# ---------------------------------------------------------------------------
# TestBudgetEnforcement (Task 4)
# ---------------------------------------------------------------------------

class TestBudgetEnforcement:
    """AC-1,2,3,5: Budget enforcement in prompt assembly."""

    def test_tier_0_prompt_within_budget(self):
        """Tier 0 prompt fits within 4096 tokens."""
        prompt = build_request_with_budget(
            system_instructions="Triage this alert.",
            evidence_block="<evidence>some data</evidence>",
            retrieval_context="A" * 20_000,
            tier="tier_0",
        )
        # 4096 tokens * 4 chars/token = 16384 chars max
        assert len(prompt) <= 4_096 * 4 + 500  # margin for prefix

    def test_tier_1_plus_allows_more(self):
        """Tier 1+ allows 16384 tokens."""
        context = "B" * 60_000
        prompt_t0 = build_request_with_budget(
            system_instructions="Triage.",
            evidence_block="<e>data</e>",
            retrieval_context=context,
            tier="tier_0",
        )
        prompt_t1 = build_request_with_budget(
            system_instructions="Triage.",
            evidence_block="<e>data</e>",
            retrieval_context=context,
            tier="tier_1_plus",
        )
        assert len(prompt_t1) > len(prompt_t0)

    def test_oversized_context_truncated(self):
        """Retrieval context exceeding budget is truncated."""
        context = "C" * 100_000  # Way over any budget
        prompt = build_request_with_budget(
            system_instructions="Classify.",
            evidence_block="<evidence></evidence>",
            retrieval_context=context,
            tier="tier_0",
        )
        # Should be significantly shorter than original context
        assert len(prompt) < 100_000

    def test_includes_safety_prefix(self):
        """Budget-enforced prompt still includes safety prefix."""
        prompt = build_request_with_budget(
            system_instructions="Task.",
            evidence_block="<evidence></evidence>",
            retrieval_context="context data",
            tier="tier_0",
        )
        assert SYSTEM_PREFIX in prompt

    def test_existing_build_system_prompt_unchanged(self):
        """Backward compat: build_system_prompt still works as before."""
        from context_gateway.prompt_builder import build_system_prompt
        result = build_system_prompt("Analyse this alert.")
        assert result.startswith(SYSTEM_PREFIX)
        assert "Analyse this alert." in result
