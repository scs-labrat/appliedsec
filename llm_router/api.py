"""LLM Router FastAPI service — routes tasks to appropriate model tiers.

Exposes the LLMRouter as an HTTP API. Other services POST a TaskContext
and receive a RoutingDecision with the selected model, tier, and parameters.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from llm_router.models import (
    MODEL_REGISTRY,
    FALLBACK_REGISTRY,
    TIER_DEFAULTS,
    ModelTier,
    TaskContext,
)
from llm_router.router import LLMRouter

logger = logging.getLogger(__name__)

# ---- request / response schemas -------------------------------------------

class RouteRequest(BaseModel):
    task_type: str
    context_tokens: int = 0
    time_budget_seconds: int = 30
    alert_severity: str = "medium"
    tenant_tier: str = "standard"
    requires_reasoning: bool = False
    previous_confidence: float | None = None


class RouteResponse(BaseModel):
    tier: str
    model_id: str
    provider: str
    max_tokens: int
    temperature: float
    use_extended_thinking: bool = False
    use_prompt_caching: bool = True
    reason: str = ""
    degradation_level: str = "full_capability"
    fallback_model_ids: list[str] = Field(default_factory=list)


class RegistryResponse(BaseModel):
    tiers: dict[str, dict[str, Any]]
    fallbacks: dict[str, list[str]]


# ---- app ------------------------------------------------------------------

app = FastAPI(
    title="ALUSKORT LLM Router",
    version="1.0.0",
)

_router: LLMRouter | None = None


@app.on_event("startup")
async def startup() -> None:
    global _router
    _router = LLMRouter()
    logger.info("LLM Router initialized")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "llm-router"}


@app.post("/v1/route", response_model=RouteResponse)
async def route_task(req: RouteRequest) -> RouteResponse:
    """Route a task to the appropriate model tier."""
    if _router is None:
        raise HTTPException(503, "Router not initialized")

    ctx = TaskContext(
        task_type=req.task_type,
        context_tokens=req.context_tokens,
        time_budget_seconds=req.time_budget_seconds,
        alert_severity=req.alert_severity,
        tenant_tier=req.tenant_tier,
        requires_reasoning=req.requires_reasoning,
        previous_confidence=req.previous_confidence,
    )

    decision = _router.route(ctx)

    return RouteResponse(
        tier=decision.tier.value,
        model_id=decision.model_config.model_id,
        provider=decision.model_config.provider.value,
        max_tokens=decision.max_tokens,
        temperature=decision.temperature,
        use_extended_thinking=decision.use_extended_thinking,
        use_prompt_caching=decision.use_prompt_caching,
        reason=decision.reason,
        degradation_level=decision.degradation_level,
        fallback_model_ids=[fc.model_id for fc in decision.fallback_configs],
    )


@app.get("/v1/registry", response_model=RegistryResponse)
async def get_registry() -> RegistryResponse:
    """Return the current model registry and fallback configuration."""
    tiers = {}
    for tier, config in MODEL_REGISTRY.items():
        defaults = TIER_DEFAULTS.get(tier, {})
        tiers[tier.value] = {
            "model_id": config.model_id,
            "provider": config.provider.value,
            "max_context_tokens": config.max_context_tokens,
            "cost_per_mtok_input": config.cost_per_mtok_input,
            "cost_per_mtok_output": config.cost_per_mtok_output,
            "default_max_tokens": defaults.get("max_tokens", 4096),
            "default_temperature": defaults.get("temperature", 0.2),
        }

    fallbacks = {}
    for tier, configs in FALLBACK_REGISTRY.items():
        fallbacks[tier.value] = [c.model_id for c in configs]

    return RegistryResponse(tiers=tiers, fallbacks=fallbacks)
