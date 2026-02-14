"""Base agent protocol — Story 7.1."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from shared.schemas.investigation import GraphState


@runtime_checkable
class AgentNode(Protocol):
    """Interface for all orchestrator agent nodes."""

    async def execute(self, state: GraphState) -> GraphState:
        """Execute this agent's logic, returning the updated state."""
        ...
