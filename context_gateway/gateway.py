"""Context Gateway — ties together all sub-components.

Provides :class:`GatewayRequest` / :class:`GatewayResponse` data models
and the :class:`ContextGateway` orchestrator that runs the full pipeline:

    sanitise → redact → build prompt → call LLM → validate → deanonymise
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from context_gateway.anthropic_client import APICallMetrics, AluskortAnthropicClient
from context_gateway.injection_detector import sanitise_input
from context_gateway.output_validator import validate_output
from context_gateway.pii_redactor import RedactionMap, deanonymise_text, redact_pii
from context_gateway.prompt_builder import build_cached_system_blocks
from context_gateway.spend_guard import SpendGuard


@dataclass
class GatewayRequest:
    """Incoming request to the Context Gateway."""

    agent_id: str
    task_type: str
    system_prompt: str
    user_content: str
    output_schema: Optional[dict[str, Any]] = None
    tenant_id: str = "default"


@dataclass
class GatewayResponse:
    """Response returned by the Context Gateway."""

    content: str
    model_id: str
    tokens_used: int
    valid: bool
    validation_errors: list[str] = field(default_factory=list)
    quarantined_ids: list[str] = field(default_factory=list)
    metrics: Optional[APICallMetrics] = None
    injection_detections: list[str] = field(default_factory=list)


class ContextGateway:
    """Centralised LLM sanitisation + output validation service."""

    def __init__(
        self,
        client: AluskortAnthropicClient,
        spend_guard: SpendGuard | None = None,
        known_technique_ids: set[str] | None = None,
    ) -> None:
        self.client = client
        self.spend_guard = spend_guard or SpendGuard()
        self.known_technique_ids = known_technique_ids

    async def complete(self, request: GatewayRequest) -> GatewayResponse:
        """Run the full gateway pipeline.

        1. Check spend budget.
        2. Sanitise input (injection detection).
        3. Redact PII.
        4. Build cached system prompt.
        5. Call Anthropic API.
        6. Validate output.
        7. Deanonymise response.
        """
        # 1 — spend guard
        self.spend_guard.check_budget()

        # 2 — injection detection
        sanitised_content, detections = sanitise_input(request.user_content)

        # 3 — PII redaction
        redacted_content, redaction_map = redact_pii(sanitised_content)

        # 4 — system prompt with cache control
        system_blocks = build_cached_system_blocks(request.system_prompt)

        # 5 — LLM call
        messages = [{"role": "user", "content": redacted_content}]
        response_text, metrics = await self.client.complete(
            system=system_blocks,
            messages=messages,
        )

        # 6 — output validation
        valid, errors, quarantined = validate_output(
            response_text,
            known_technique_ids=self.known_technique_ids,
            output_schema=request.output_schema,
        )

        # 7 — deanonymise
        final_text = deanonymise_text(response_text, redaction_map)

        # record cost
        self.spend_guard.record(
            cost_usd=metrics.cost_usd,
            model_id=metrics.model_id,
            task_type=request.task_type,
            tenant_id=request.tenant_id,
        )

        return GatewayResponse(
            content=final_text,
            model_id=metrics.model_id,
            tokens_used=metrics.input_tokens + metrics.output_tokens,
            valid=valid,
            validation_errors=errors,
            quarantined_ids=quarantined,
            metrics=metrics,
            injection_detections=detections,
        )
