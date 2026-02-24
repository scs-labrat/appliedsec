"""Tests for executor hard constraints — Story 12.9."""

from __future__ import annotations

import pytest

from orchestrator.executor_constraints import (
    DEFAULT_CONSTRAINTS,
    ExecutorConstraints,
    PermissionDeniedError,
    ROLE_PERMISSIONS,
    RolePermissionEnforcer,
    validate_auto_close,
    validate_playbook,
)


# ---------- ExecutorConstraints — Task 1 --------------------------------------

class TestExecutorConstraints:
    """ExecutorConstraints dataclass and validation functions."""

    def test_default_constraints_values(self):
        c = DEFAULT_CONSTRAINTS
        assert c.min_confidence_for_auto_close == 0.85
        assert c.require_fp_match_for_auto_close is True
        assert c.can_modify_routing_policy is False
        assert c.can_disable_guardrails is False
        assert isinstance(c.allowlisted_playbooks, frozenset)

    def test_custom_allowlist(self):
        c = ExecutorConstraints(
            allowlisted_playbooks=frozenset({"PB-001", "PB-002"})
        )
        assert "PB-001" in c.allowlisted_playbooks
        assert "PB-002" in c.allowlisted_playbooks

    def test_validate_playbook_allowed(self):
        c = ExecutorConstraints(
            allowlisted_playbooks=frozenset({"PB-001", "PB-002"})
        )
        assert validate_playbook("PB-001", c) is True

    def test_validate_playbook_not_allowed(self):
        c = ExecutorConstraints(
            allowlisted_playbooks=frozenset({"PB-001"})
        )
        assert validate_playbook("PB-999", c) is False

    def test_validate_playbook_empty_allowlist(self):
        c = ExecutorConstraints(allowlisted_playbooks=frozenset())
        assert validate_playbook("PB-001", c) is False

    def test_auto_close_both_conditions_met(self):
        c = ExecutorConstraints(
            min_confidence_for_auto_close=0.85,
            require_fp_match_for_auto_close=True,
        )
        assert validate_auto_close(0.90, True, c) is True

    def test_auto_close_low_confidence(self):
        c = ExecutorConstraints(
            min_confidence_for_auto_close=0.85,
            require_fp_match_for_auto_close=True,
        )
        assert validate_auto_close(0.50, True, c) is False

    def test_auto_close_no_fp_match(self):
        c = ExecutorConstraints(
            min_confidence_for_auto_close=0.85,
            require_fp_match_for_auto_close=True,
        )
        assert validate_auto_close(0.90, False, c) is False

    def test_auto_close_fp_match_not_required(self):
        c = ExecutorConstraints(
            min_confidence_for_auto_close=0.85,
            require_fp_match_for_auto_close=False,
        )
        assert validate_auto_close(0.90, False, c) is True

    def test_cannot_modify_routing_policy(self):
        assert DEFAULT_CONSTRAINTS.can_modify_routing_policy is False

    def test_cannot_disable_guardrails(self):
        assert DEFAULT_CONSTRAINTS.can_disable_guardrails is False


# ---------- RolePermissionEnforcer — Task 2 -----------------------------------

class TestRolePermissions:
    """Role-based permission enforcement."""

    def setup_method(self):
        self.enforcer = RolePermissionEnforcer()

    def test_ioc_extractor_can_query_data(self):
        assert self.enforcer.check_permission("ioc_extractor", "query_data") is True

    def test_ioc_extractor_cannot_execute_playbook(self):
        assert self.enforcer.check_permission("ioc_extractor", "execute_playbook") is False

    def test_reasoning_agent_can_analyse(self):
        assert self.enforcer.check_permission("reasoning_agent", "analyse") is True

    def test_reasoning_agent_can_comment_incident(self):
        assert self.enforcer.check_permission("reasoning_agent", "comment_incident") is True

    def test_response_agent_can_execute_playbook(self):
        assert self.enforcer.check_permission("response_agent", "execute_playbook") is True

    def test_context_enricher_can_query_graph(self):
        assert self.enforcer.check_permission("context_enricher", "query_graph") is True

    def test_unknown_role_denied_all(self):
        assert self.enforcer.check_permission("unknown_role", "query_data") is False

    def test_enforce_permission_passes(self):
        # Should not raise
        self.enforcer.enforce_permission("response_agent", "execute_playbook")

    def test_enforce_permission_raises(self):
        with pytest.raises(PermissionDeniedError):
            self.enforcer.enforce_permission("ioc_extractor", "execute_playbook")

    def test_all_roles_can_call_llm(self):
        for role in ROLE_PERMISSIONS:
            assert self.enforcer.check_permission(role, "call_llm") is True
