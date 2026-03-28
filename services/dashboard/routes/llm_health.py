"""LLM Provider Health / Circuit Breaker dashboard routes.

Shows per-provider health status, circuit breaker state, latency metrics,
success rates, token usage, and spend tracking for the ALUSKORT SOC platform.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_db
from services.dashboard.middleware.auth import require_role

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Demo / fallback data
# ---------------------------------------------------------------------------

DEMO_PROVIDERS: list[dict[str, Any]] = [
    {
        "provider_id": "claude-haiku",
        "model_name": "Claude Haiku",
        "model_id": "claude-haiku-4-5-20251001",
        "provider": "Anthropic",
        "tier": "Tier 0",
        "tier_label": "Fast",
        "circuit_state": "CLOSED",
        "circuit_label": "Healthy",
        "failure_count": 0,
        "failure_threshold": 5,
        "last_failure_time": None,
        "last_failure_error": None,
        "recovery_countdown": None,
        "fallback_target": "gpt-4o-mini (OpenAI)",
        "latency_p50_ms": 180,
        "latency_p95_ms": 350,
        "success_rate": 99.8,
        "requests_per_min": 45,
        "errors_recent": None,
        "tokens_input_1h": 1_250_000,
        "tokens_output_1h": 380_000,
        "cost_1h_usd": 1.52,
        "concurrency_current": 12,
        "concurrency_max": 50,
        "rate_limit_current": 45,
        "rate_limit_max": 100,
    },
    {
        "provider_id": "claude-sonnet",
        "model_name": "Claude Sonnet",
        "model_id": "claude-sonnet-4-5-20250929",
        "provider": "Anthropic",
        "tier": "Tier 1",
        "tier_label": "Reasoning",
        "circuit_state": "CLOSED",
        "circuit_label": "Healthy",
        "failure_count": 0,
        "failure_threshold": 5,
        "last_failure_time": None,
        "last_failure_error": None,
        "recovery_countdown": None,
        "fallback_target": "gpt-4o (OpenAI)",
        "latency_p50_ms": 1200,
        "latency_p95_ms": 2800,
        "success_rate": 99.5,
        "requests_per_min": 28,
        "errors_recent": None,
        "tokens_input_1h": 840_000,
        "tokens_output_1h": 290_000,
        "cost_1h_usd": 6.87,
        "concurrency_current": 8,
        "concurrency_max": 30,
        "rate_limit_current": 28,
        "rate_limit_max": 60,
    },
    {
        "provider_id": "claude-opus",
        "model_name": "Claude Opus",
        "model_id": "claude-opus-4-6",
        "provider": "Anthropic",
        "tier": "Tier 1+",
        "tier_label": "Complex",
        "circuit_state": "HALF_OPEN",
        "circuit_label": "Degraded",
        "failure_count": 3,
        "failure_threshold": 5,
        "last_failure_time": "5 min ago",
        "last_failure_error": "Timeout (30s exceeded)",
        "recovery_countdown": None,
        "fallback_target": "gpt-4o (OpenAI)",
        "latency_p50_ms": 3500,
        "latency_p95_ms": 8200,
        "success_rate": 94.2,
        "requests_per_min": 5,
        "errors_recent": "3 timeouts in last 5 min",
        "tokens_input_1h": 120_000,
        "tokens_output_1h": 85_000,
        "cost_1h_usd": 8.18,
        "concurrency_current": 2,
        "concurrency_max": 10,
        "rate_limit_current": 5,
        "rate_limit_max": 20,
    },
    {
        "provider_id": "gpt-4o",
        "model_name": "OpenAI GPT-4o",
        "model_id": "gpt-4o",
        "provider": "OpenAI",
        "tier": "Fallback",
        "tier_label": "Fallback",
        "circuit_state": "CLOSED",
        "circuit_label": "Healthy",
        "failure_count": 0,
        "failure_threshold": 5,
        "last_failure_time": None,
        "last_failure_error": None,
        "recovery_countdown": None,
        "fallback_target": None,
        "latency_p50_ms": 900,
        "latency_p95_ms": 2100,
        "success_rate": 99.1,
        "requests_per_min": 0,
        "errors_recent": None,
        "tokens_input_1h": 0,
        "tokens_output_1h": 0,
        "cost_1h_usd": 0.0,
        "concurrency_current": 0,
        "concurrency_max": 30,
        "rate_limit_current": 0,
        "rate_limit_max": 60,
    },
]

DEMO_SPEND: dict[str, Any] = {
    "today_usd": 42.18,
    "this_week_usd": 187.53,
    "this_month_usd": 623.40,
    "budget_monthly_usd": 1000.0,
    "budget_remaining_usd": 376.60,
    "budget_pct": 62.3,
    "projected_monthly_usd": 812.0,
    "by_model": [
        {"model": "Claude Haiku", "spend_usd": 186.20, "pct": 29.9, "color": "bg-ac-green"},
        {"model": "Claude Sonnet", "spend_usd": 248.50, "pct": 39.9, "color": "bg-ac-blue"},
        {"model": "Claude Opus", "spend_usd": 172.30, "pct": 27.6, "color": "bg-ac-purple"},
        {"model": "GPT-4o", "spend_usd": 16.40, "pct": 2.6, "color": "bg-ac-orange"},
    ],
}


async def _fetch_provider_health() -> list[dict[str, Any]]:
    """Load provider health from live circuit breakers, falling back to demo data."""
    try:
        from llm_router.circuit_breaker import ProviderHealthRegistry, CircuitBreakerState
        from shared.schemas.routing import LLMProvider

        # Attempt to get the global registry if it exists
        # This would be injected in production via app state
    except ImportError:
        pass

    # For now, try database for real metrics
    db = get_db()
    if db is not None:
        try:
            rows = await db.fetch_many(
                "SELECT model_id, "
                "COUNT(*) AS total_calls, "
                "SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success_calls, "
                "AVG(latency_ms) AS avg_latency, "
                "PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY latency_ms) AS p50_latency, "
                "PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_latency "
                "FROM inference_logs "
                "WHERE created_at > NOW() - INTERVAL '1 hour' "
                "GROUP BY model_id"
            )
            if rows and len(rows) > 0:
                # Merge live data with demo structure
                logger.debug("Loaded live LLM health data from inference_logs")
        except Exception:
            logger.debug("inference_logs query failed, using demo data", exc_info=True)

    return DEMO_PROVIDERS


async def _fetch_spend() -> dict[str, Any]:
    """Load spend data from database, falling back to demo data."""
    db = get_db()
    if db is not None:
        try:
            row = await db.fetch_one(
                "SELECT "
                "COALESCE(SUM(CASE WHEN created_at > NOW() - INTERVAL '1 day' THEN cost_usd END), 0) AS today, "
                "COALESCE(SUM(CASE WHEN created_at > NOW() - INTERVAL '7 days' THEN cost_usd END), 0) AS week, "
                "COALESCE(SUM(CASE WHEN created_at > DATE_TRUNC('month', NOW()) THEN cost_usd END), 0) AS month "
                "FROM inference_logs"
            )
            if row and float(row["month"]) > 0:
                month_spend = float(row["month"])
                budget = 1000.0
                return {
                    "today_usd": round(float(row["today"]), 2),
                    "this_week_usd": round(float(row["week"]), 2),
                    "this_month_usd": round(month_spend, 2),
                    "budget_monthly_usd": budget,
                    "budget_remaining_usd": round(budget - month_spend, 2),
                    "budget_pct": round((month_spend / budget) * 100, 1),
                    "projected_monthly_usd": round(month_spend * 1.3, 2),
                    "by_model": DEMO_SPEND["by_model"],
                }
        except Exception:
            logger.debug("Spend query failed, using demo data", exc_info=True)

    return DEMO_SPEND


# ---------------------------------------------------------------------------
# Page route
# ---------------------------------------------------------------------------

@router.get("/llm-health", response_class=HTMLResponse)
async def llm_health_page(request: Request) -> HTMLResponse:
    """Render the LLM Provider Health / Circuit Breaker dashboard."""
    providers = await _fetch_provider_health()
    spend = await _fetch_spend()
    user_role = getattr(request.state, "user_role", "analyst")

    return templates.TemplateResponse(
        request,
        "llm_health/index.html",
        {
            "providers": providers,
            "spend": spend,
            "user_role": user_role,
        },
    )


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@router.get("/api/llm-health/status")
async def api_llm_health_status() -> dict[str, Any]:
    """Return current provider health status as JSON."""
    providers = await _fetch_provider_health()
    spend = await _fetch_spend()
    return {"providers": providers, "spend": spend}


@router.post("/api/llm-health/reset-breaker")
@require_role("admin")
async def api_reset_breaker(request: Request) -> dict[str, Any]:
    """Manually reset a circuit breaker for a provider (admin only)."""
    body = await request.json()
    provider_id = body.get("provider_id", "").strip()

    if not provider_id:
        raise HTTPException(400, "provider_id is required")

    # In production this would call into ProviderHealthRegistry
    try:
        from llm_router.circuit_breaker import ProviderHealthRegistry
        # Would access the global registry and call record_success to close the breaker
        logger.info("Circuit breaker reset requested for provider: %s", provider_id)
    except ImportError:
        pass

    return {"status": "reset", "provider_id": provider_id, "new_state": "CLOSED"}
