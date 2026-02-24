"""Executor hard constraints — Story 12.9.

Code-enforced constraints that prevent LLM output from causing
unauthorized actions.  Even a fully compromised LLM cannot bypass
these guards — they are enforced by orchestrator code, not LLM
compliance.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------- constraint data model --------------------------------------------

@dataclass(frozen=True)
class ExecutorConstraints:
    """Hard constraints enforced at the executor level."""

    allowlisted_playbooks: frozenset[str] = field(default_factory=frozenset)
    min_confidence_for_auto_close: float = 0.85
    require_fp_match_for_auto_close: bool = True
    can_modify_routing_policy: bool = False
    can_disable_guardrails: bool = False


DEFAULT_CONSTRAINTS = ExecutorConstraints()


# ---------- validation functions ---------------------------------------------

def validate_playbook(
    playbook_id: str,
    constraints: ExecutorConstraints,
) -> bool:
    """Check whether a playbook is in the allowlist."""
    return playbook_id in constraints.allowlisted_playbooks


def validate_auto_close(
    confidence: float,
    fp_matched: bool,
    constraints: ExecutorConstraints,
) -> bool:
    """Check whether auto-close criteria are met.

    Requires BOTH confidence > threshold AND fp_match (when configured).
    """
    if confidence < constraints.min_confidence_for_auto_close:
        return False
    if constraints.require_fp_match_for_auto_close and not fp_matched:
        return False
    return True


# ---------- role permission enforcement --------------------------------------

class PermissionDeniedError(Exception):
    """Raised when an agent attempts an action outside its allowed set."""


ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "ioc_extractor": frozenset({"query_data", "call_llm"}),
    "context_enricher": frozenset({"query_data", "query_graph", "call_llm"}),
    "reasoning_agent": frozenset({
        "query_data", "query_graph", "analyse",
        "comment_incident", "call_llm",
    }),
    "response_agent": frozenset({
        "query_data", "analyse", "update_incident",
        "execute_playbook", "call_llm",
    }),
}


class RolePermissionEnforcer:
    """Enforces the ROLE_PERMISSIONS matrix at the code level."""

    def check_permission(self, agent_role: str, action: str) -> bool:
        """Check whether *agent_role* is permitted to perform *action*."""
        allowed = ROLE_PERMISSIONS.get(agent_role, frozenset())
        return action in allowed

    def enforce_permission(self, agent_role: str, action: str) -> None:
        """Raise ``PermissionDeniedError`` if *action* is not permitted."""
        if not self.check_permission(agent_role, action):
            raise PermissionDeniedError(
                f"Agent '{agent_role}' is not permitted to '{action}'"
            )
