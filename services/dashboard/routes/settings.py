"""System settings routes — asset discovery, threat modeling, CTI, infrastructure.

Provides a dashboard for system initialisation status, infrastructure health
with remediation actions, zone mappings, SLA policies, and pipeline config.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from services.dashboard.app import templates
from services.dashboard.deps import get_db, get_redis

logger = logging.getLogger(__name__)

router = APIRouter()


# -- Zone / consequence model (from ctem_normaliser.models) ----------------

ZONE_GROUPS = [
    {
        "group": "Purdue Model (OT)",
        "zones": [
            {"zone": "Zone0_PhysicalProcess", "consequence": "safety_life", "severity": "CRITICAL"},
            {"zone": "Zone0_Safety", "consequence": "safety_life", "severity": "CRITICAL"},
            {"zone": "Zone0_FieldDevices", "consequence": "safety_life", "severity": "CRITICAL"},
            {"zone": "Zone1_EdgeInference", "consequence": "equipment", "severity": "HIGH"},
            {"zone": "Zone1_BasicControl", "consequence": "equipment", "severity": "HIGH"},
            {"zone": "Zone1_PLCNetwork", "consequence": "equipment", "severity": "HIGH"},
            {"zone": "Zone2_Operations", "consequence": "downtime", "severity": "MEDIUM"},
            {"zone": "Zone2_SCADA", "consequence": "downtime", "severity": "MEDIUM"},
            {"zone": "Zone2_HMI", "consequence": "downtime", "severity": "MEDIUM"},
            {"zone": "Zone3_Enterprise", "consequence": "data_loss", "severity": "LOW"},
            {"zone": "Zone3_5_DMZ", "consequence": "data_loss", "severity": "LOW"},
            {"zone": "Zone4_External", "consequence": "data_loss", "severity": "LOW"},
        ],
    },
    {
        "group": "Cloud & IT",
        "zones": [
            {"zone": "Cloud_Production", "consequence": "downtime", "severity": "MEDIUM"},
            {"zone": "Cloud_Staging", "consequence": "data_loss", "severity": "LOW"},
            {"zone": "Cloud_Development", "consequence": "data_loss", "severity": "LOW"},
            {"zone": "Cloud_Management", "consequence": "downtime", "severity": "MEDIUM"},
            {"zone": "IT_DataCenter", "consequence": "downtime", "severity": "MEDIUM"},
            {"zone": "IT_NetworkInfra", "consequence": "downtime", "severity": "MEDIUM"},
        ],
    },
    {
        "group": "OT-Specific",
        "zones": [
            {"zone": "OT_FieldBus", "consequence": "equipment", "severity": "HIGH"},
            {"zone": "OT_ControlNetwork", "consequence": "equipment", "severity": "HIGH"},
            {"zone": "OT_ProcessNetwork", "consequence": "safety_life", "severity": "CRITICAL"},
            {"zone": "OT_SafetyInstrumentedSystem", "consequence": "safety_life", "severity": "CRITICAL"},
        ],
    },
]

SEVERITY_MATRIX = [
    {"exploitability": "high", "consequence": "safety_life", "severity": "CRITICAL"},
    {"exploitability": "high", "consequence": "equipment", "severity": "CRITICAL"},
    {"exploitability": "high", "consequence": "downtime", "severity": "HIGH"},
    {"exploitability": "high", "consequence": "data_loss", "severity": "MEDIUM"},
    {"exploitability": "medium", "consequence": "safety_life", "severity": "CRITICAL"},
    {"exploitability": "medium", "consequence": "equipment", "severity": "HIGH"},
    {"exploitability": "medium", "consequence": "downtime", "severity": "MEDIUM"},
    {"exploitability": "medium", "consequence": "data_loss", "severity": "LOW"},
    {"exploitability": "low", "consequence": "safety_life", "severity": "HIGH"},
    {"exploitability": "low", "consequence": "equipment", "severity": "MEDIUM"},
    {"exploitability": "low", "consequence": "downtime", "severity": "LOW"},
    {"exploitability": "low", "consequence": "data_loss", "severity": "LOW"},
]

SLA_POLICIES = [
    {"severity": "CRITICAL", "hours": 24, "display": "24 hours"},
    {"severity": "HIGH", "hours": 72, "display": "3 days"},
    {"severity": "MEDIUM", "hours": 336, "display": "14 days"},
    {"severity": "LOW", "hours": 720, "display": "30 days"},
]

LLM_CONFIG = {
    "tiers": [
        {
            "id": "tier_0", "name": "Tier 0 — Fast", "model": "claude-haiku-4-5-20251001",
            "provider": "Anthropic", "max_context": "200K", "max_tokens": 2048,
            "temperature": 0.1, "cost_input": 0.80, "cost_output": 4.0,
            "tasks": ["ioc_extraction", "log_summarisation", "entity_normalisation", "fp_suggestion", "alert_classification", "severity_assessment"],
            "fallback_model": "gpt-4o-mini", "fallback_provider": "OpenAI",
            "latency_slo": "3s",
        },
        {
            "id": "tier_1", "name": "Tier 1 — Reasoning", "model": "claude-sonnet-4-5-20250929",
            "provider": "Anthropic", "max_context": "200K", "max_tokens": 8192,
            "temperature": 0.2, "cost_input": 3.0, "cost_output": 15.0,
            "tasks": ["investigation", "ctem_correlation", "atlas_reasoning", "attack_path_analysis", "incident_report", "playbook_selection"],
            "fallback_model": "gpt-4o", "fallback_provider": "OpenAI",
            "latency_slo": "30s",
        },
        {
            "id": "tier_1_plus", "name": "Tier 1+ — Complex", "model": "claude-opus-4-6",
            "provider": "Anthropic", "max_context": "200K", "max_tokens": 16384,
            "temperature": 0.2, "cost_input": 15.0, "cost_output": 75.0,
            "tasks": ["complex_reasoning", "escalation_analysis", "multi_step_planning"],
            "fallback_model": "gpt-4o", "fallback_provider": "OpenAI",
            "extended_thinking": True,
            "latency_slo": "60s",
        },
        {
            "id": "tier_2", "name": "Tier 2 — Batch", "model": "claude-sonnet-4-5-20250929",
            "provider": "Anthropic (Batch)", "max_context": "200K", "max_tokens": 16384,
            "temperature": 0.3, "cost_input": 1.5, "cost_output": 7.5,
            "tasks": ["fp_pattern_training", "playbook_generation", "agent_red_team", "detection_rule_generation", "retrospective_analysis", "threat_landscape_summary"],
            "fallback_model": None, "fallback_provider": None,
            "latency_slo": "async",
        },
    ],
    "spend_guard": {
        "monthly_hard_cap": 1000.0,
        "monthly_soft_alert": 500.0,
        "currency": "USD",
    },
    "gateway": {
        "prompt_caching": True,
        "pii_redaction": True,
        "injection_detection": True,
        "output_validation": True,
        "max_retries": 3,
        "base_delay": 1.0,
    },
}

KAFKA_TOPICS = [
    {"topic": "alerts.raw", "description": "Raw SIEM alerts from connectors", "category": "siem"},
    {"topic": "alerts.normalized", "description": "Entity-parsed alerts", "category": "siem"},
    {"topic": "alerts.raw.dlq", "description": "Failed raw alert parsing", "category": "siem"},
    {"topic": "alerts.normalized.dlq", "description": "Failed normalized alerts", "category": "siem"},
    {"topic": "investigations.completed", "description": "Completed investigation results", "category": "orchestrator"},
    {"topic": "ctem.raw.wiz", "description": "Wiz CSPM findings", "category": "ctem"},
    {"topic": "ctem.raw.snyk", "description": "Snyk SCA vulnerabilities", "category": "ctem"},
    {"topic": "ctem.raw.garak", "description": "Garak LLM security probes", "category": "ctem"},
    {"topic": "ctem.raw.art", "description": "MITRE ART test results", "category": "ctem"},
    {"topic": "ctem.raw.burp", "description": "Burp Suite scan results", "category": "ctem"},
    {"topic": "ctem.raw.custom", "description": "Custom CTEM tool findings", "category": "ctem"},
    {"topic": "ctem.normalized", "description": "Normalised CTEM exposures", "category": "ctem"},
    {"topic": "ctem.normalized.dlq", "description": "Failed CTEM normalisation", "category": "ctem"},
    {"topic": "audit.events", "description": "Audit trail events", "category": "audit"},
]


# -- Infrastructure service definitions ------------------------------------

INFRA_SERVICES = [
    {
        "id": "postgres",
        "label": "PostgreSQL",
        "description": "Primary data store for investigations, CTEM exposures, IOCs, audit records",
        "env_var": "POSTGRES_DSN",
        "default": "postgresql://aluskort:localdev@postgres:5432/aluskort",
        "port": 5432,
        "docs": "Holds all persistent state. Without Postgres: no investigations, no connector configs, no audit trail.",
        "remediation": [
            "Verify POSTGRES_DSN environment variable is set",
            "Check that the Postgres container is running: docker compose up -d postgres",
            "Run migrations: docker exec -i soc-postgres-1 psql -U aluskort -d aluskort < infra/migrations/001_core_tables.sql",
            "Test connectivity: docker exec soc-postgres-1 pg_isready",
        ],
    },
    {
        "id": "redis",
        "label": "Redis",
        "description": "IOC cache, FP pattern store, session data",
        "env_var": "REDIS_HOST",
        "default": "redis",
        "port": 6379,
        "docs": "Caches threat intel IOCs and FP patterns for sub-millisecond lookup. Fail-open: pipeline continues without Redis, but enrichment is degraded.",
        "remediation": [
            "Verify REDIS_HOST environment variable is set",
            "Check that the Redis container is running: docker compose up -d redis",
            "Test connectivity: docker exec soc-redis-1 redis-cli ping",
        ],
    },
    {
        "id": "kafka",
        "label": "Kafka (Redpanda)",
        "description": "Event bus for alert ingestion, CTEM findings, audit events",
        "env_var": "KAFKA_BOOTSTRAP_SERVERS",
        "default": "kafka:9092",
        "port": 9092,
        "docs": "Central event backbone. All connectors publish to Kafka topics; orchestrator and CTEM normaliser consume. Without Kafka: no event flow.",
        "remediation": [
            "Verify KAFKA_BOOTSTRAP_SERVERS environment variable is set",
            "Check Redpanda is running: docker compose up -d kafka",
            "Verify topics exist: docker exec soc-kafka-1 rpk topic list",
            "Create missing topics: python -m infra.scripts.create_kafka_topics",
        ],
    },
    {
        "id": "neo4j",
        "label": "Neo4j",
        "description": "Asset graph database — zones, assets, models, findings, and their relationships",
        "env_var": "NEO4J_URI",
        "default": "bolt://neo4j:7687",
        "port": 7687,
        "docs": "Stores Purdue model asset graph for consequence reasoning. Graceful degradation: falls back to static zone-consequence mapping when unavailable.",
        "remediation": [
            "Verify NEO4J_URI environment variable is set",
            "Check Neo4j is running: docker compose up -d neo4j",
            "Initialize schema: python -m infra.scripts.init_neo4j",
            "Default credentials: neo4j / localdev",
        ],
    },
    {
        "id": "qdrant",
        "label": "Qdrant",
        "description": "Vector database for semantic search — ATLAS technique matching, incident memory",
        "env_var": "QDRANT_HOST",
        "default": "qdrant",
        "port": 6333,
        "docs": "Stores embeddings for MITRE ATLAS technique descriptions and past incident summaries. Used by ATLAS Mapper and Context Enricher agents.",
        "remediation": [
            "Verify QDRANT_HOST environment variable is set",
            "Check Qdrant is running: docker compose up -d qdrant",
            "Verify collections: curl http://localhost:6333/collections",
            "Run embedding migration: python -m shared.db.embedding_migration",
        ],
    },
    {
        "id": "minio",
        "label": "MinIO (S3)",
        "description": "Object storage for raw alert payloads, evidence artifacts, report exports",
        "env_var": "MINIO_ENDPOINT",
        "default": "minio:9000",
        "port": 9000,
        "docs": "Stores large binary evidence (PCAPs, screenshots, memory dumps). Non-critical for core pipeline — investigations proceed without it.",
        "remediation": [
            "Check MinIO is running: docker compose up -d minio",
            "Access console: http://localhost:9001 (minioadmin / minioadmin)",
            "Create required buckets: evidence, reports, raw-alerts",
        ],
    },
    {
        "id": "context_gateway",
        "label": "Context Gateway",
        "description": "LLM gateway — sanitise, redact, call, validate pipeline",
        "env_var": "CONTEXT_GATEWAY_URL",
        "default": "http://context-gateway:8030",
        "port": 8030,
        "docs": "All LLM calls go through this service. Enforces spend limits, redacts PII, validates structured output. Without it: no AI-powered reasoning.",
        "remediation": [
            "Verify ANTHROPIC_API_KEY is set for the gateway container",
            "Check service: docker compose up -d context-gateway",
            "Test health: curl http://localhost:8030/health",
            "Check spend: curl http://localhost:8030/v1/spend",
        ],
    },
]


async def _check_infra_health() -> list[dict[str, Any]]:
    """Probe each infrastructure service and return status with remediation info."""
    results: list[dict[str, Any]] = []

    for svc in INFRA_SERVICES:
        entry: dict[str, Any] = {**svc, "status": "unknown", "detail": "", "env_value": ""}

        # Show the current env var value (masked for secrets)
        env_val = os.environ.get(svc["env_var"], "")
        if env_val:
            entry["env_value"] = env_val if "KEY" not in svc["env_var"] else env_val[:8] + "..."
        else:
            entry["env_value"] = "(not set)"

        # Probe based on service type
        try:
            if svc["id"] == "postgres":
                db = get_db()
                if db is not None:
                    row = await db.fetch_one("SELECT 1 AS ok")
                    if row:
                        entry["status"] = "healthy"
                        entry["detail"] = "Connected — pool active"
                    else:
                        entry["status"] = "unhealthy"
                        entry["detail"] = "Query returned no result"
                else:
                    entry["status"] = "disconnected"
                    entry["detail"] = f"POSTGRES_DSN={'set' if env_val else 'NOT SET'} — client not initialized"

            elif svc["id"] == "redis":
                redis = get_redis()
                if redis is not None:
                    pong = await redis._client.ping()  # type: ignore[union-attr]
                    entry["status"] = "healthy"
                    entry["detail"] = "Connected — PONG received"
                else:
                    entry["status"] = "disconnected"
                    entry["detail"] = f"REDIS_HOST={'set' if env_val else 'NOT SET'} — client not initialized"

            elif svc["id"] in ("kafka", "neo4j", "qdrant", "minio", "context_gateway"):
                # HTTP health probe for services with health endpoints
                probe_urls = {
                    "kafka": None,  # No HTTP health — TCP only
                    "neo4j": None,  # Bolt protocol — no HTTP health
                    "qdrant": f"http://{os.environ.get('QDRANT_HOST', 'qdrant')}:6333/healthz",
                    "minio": f"http://{os.environ.get('MINIO_ENDPOINT', 'minio:9000').split(':')[0]}:9000/minio/health/live",
                    "context_gateway": f"{os.environ.get('CONTEXT_GATEWAY_URL', 'http://context-gateway:8030')}/health",
                }
                url = probe_urls.get(svc["id"])

                if url:
                    async with httpx.AsyncClient(timeout=3.0) as client:
                        resp = await client.get(url)
                        if resp.status_code < 400:
                            entry["status"] = "healthy"
                            entry["detail"] = f"HTTP {resp.status_code} — {url}"
                        else:
                            entry["status"] = "unhealthy"
                            entry["detail"] = f"HTTP {resp.status_code} from {url}"
                else:
                    # TCP probe for Kafka and Neo4j
                    import asyncio
                    host = env_val.split("://")[-1].split(":")[0].split("/")[0] if env_val else svc["default"].split("://")[-1].split(":")[0]
                    port = svc["port"]
                    try:
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(host, port), timeout=3.0,
                        )
                        writer.close()
                        await writer.wait_closed()
                        entry["status"] = "healthy"
                        entry["detail"] = f"TCP connect to {host}:{port} succeeded"
                    except (asyncio.TimeoutError, OSError) as tcp_exc:
                        entry["status"] = "unreachable"
                        entry["detail"] = f"TCP connect to {host}:{port} failed: {tcp_exc}"

        except Exception as exc:
            entry["status"] = "error"
            entry["detail"] = str(exc)[:200]

        results.append(entry)

    return results


async def _get_db_stats() -> dict[str, Any]:
    """Fetch row counts from key tables."""
    db = get_db()
    if db is None:
        return {}

    stats: dict[str, Any] = {}
    tables = [
        ("investigation_state", "Investigations"),
        ("connectors", "Connectors"),
        ("ctem_exposures", "CTEM Exposures"),
        ("threat_intel_iocs", "Threat Intel IOCs"),
        ("mitre_techniques", "MITRE Techniques"),
        ("audit_records", "Audit Records"),
    ]
    for table, label in tables:
        try:
            row = await db.fetch_one(f"SELECT count(*) AS cnt FROM {table}")
            stats[label] = row["cnt"] if row else 0
        except Exception:
            stats[label] = "N/A"
    return stats


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    """Render the system settings / initialization page."""
    infra_health = await _check_infra_health()
    db_stats = await _get_db_stats()

    # LLM spend statistics from inference_logs
    llm_stats: dict[str, Any] = {}
    db = get_db()
    if db:
        try:
            # Total spend
            row = await db.fetch_one(
                "SELECT COALESCE(SUM(cost_usd), 0) AS total_spend, COUNT(*) AS total_calls FROM inference_logs",
            )
            if row:
                llm_stats["total_spend"] = float(row["total_spend"])
                llm_stats["total_calls"] = row["total_calls"]
            # By model
            rows = await db.fetch_many(
                "SELECT model_id, COUNT(*) AS calls, COALESCE(SUM(cost_usd), 0) AS spend "
                "FROM inference_logs GROUP BY model_id ORDER BY spend DESC",
            )
            llm_stats["by_model"] = [dict(r) for r in rows]
        except Exception:
            pass

    # LLM providers and models from DB or demo
    providers = await _get_providers()
    models = await _get_models()

    return templates.TemplateResponse(
        request,
        "settings/index.html",
        {
            "zone_groups": ZONE_GROUPS,
            "severity_matrix": SEVERITY_MATRIX,
            "sla_policies": SLA_POLICIES,
            "kafka_topics": KAFKA_TOPICS,
            "infra_services": infra_health,
            "db_stats": db_stats,
            "llm_config": LLM_CONFIG,
            "llm_stats": llm_stats,
            "llm_providers": providers,
            "llm_models": models,
        },
    )


@router.get("/api/settings/health")
async def api_health() -> list[dict[str, Any]]:
    """JSON endpoint for infrastructure health."""
    return await _check_infra_health()


@router.get("/api/settings/stats")
async def api_stats() -> dict[str, Any]:
    """JSON endpoint for database stats."""
    return await _get_db_stats()


@router.post("/api/settings/reconnect/{service_id}")
async def api_reconnect(service_id: str) -> dict[str, Any]:
    """Attempt to reconnect a disconnected infrastructure service."""
    from services.dashboard.deps import init_deps

    if service_id == "postgres":
        dsn = os.environ.get("POSTGRES_DSN", "")
        if not dsn:
            raise HTTPException(400, "POSTGRES_DSN not set in environment")
        try:
            from shared.db.postgres import PostgresClient
            db = PostgresClient(dsn=dsn)
            await db.connect()
            # Re-init deps with new client
            init_deps(db, get_redis())
            return {"status": "connected", "detail": "Postgres pool created"}
        except Exception as exc:
            raise HTTPException(502, f"Connection failed: {exc}")

    elif service_id == "redis":
        host = os.environ.get("REDIS_HOST", "")
        if not host:
            raise HTTPException(400, "REDIS_HOST not set in environment")
        try:
            from shared.db.redis_cache import RedisClient
            rc = RedisClient(host=host)
            await rc.connect()
            init_deps(get_db(), rc)
            return {"status": "connected", "detail": "Redis connected"}
        except Exception as exc:
            raise HTTPException(502, f"Connection failed: {exc}")

    else:
        raise HTTPException(400, f"Reconnect not supported for {service_id}")


# -- LLM Provider / Model CRUD -----------------------------------------------

# Demo fallback data when DB not available
DEMO_PROVIDERS = [
    {
        "provider_id": "anthropic", "display_name": "Anthropic",
        "api_base_url": "https://api.anthropic.com", "api_key_enc": "sk-ant-...****",
        "enabled": True, "created_at": "2026-01-15T00:00:00Z", "updated_at": "2026-03-20T00:00:00Z",
    },
    {
        "provider_id": "openai", "display_name": "OpenAI (Fallback)",
        "api_base_url": "https://api.openai.com/v1", "api_key_enc": "sk-proj-...****",
        "enabled": True, "created_at": "2026-01-15T00:00:00Z", "updated_at": "2026-03-20T00:00:00Z",
    },
]

DEMO_MODELS = [
    {
        "model_id": "haiku", "provider_id": "anthropic", "display_name": "Claude Haiku (Tier 0)",
        "model_name": "claude-haiku-4-5-20251001", "tier": "tier_0",
        "max_context": 200000, "max_tokens": 2048, "temperature": 0.1,
        "cost_input": 0.80, "cost_output": 4.0, "latency_slo": "3s",
        "tasks": ["ioc_extraction", "log_summarisation", "entity_normalisation", "fp_suggestion", "alert_classification", "severity_assessment"],
        "fallback_model": "gpt-4o-mini", "enabled": True, "extended_thinking": False,
    },
    {
        "model_id": "sonnet", "provider_id": "anthropic", "display_name": "Claude Sonnet (Tier 1)",
        "model_name": "claude-sonnet-4-5-20250929", "tier": "tier_1",
        "max_context": 200000, "max_tokens": 8192, "temperature": 0.2,
        "cost_input": 3.0, "cost_output": 15.0, "latency_slo": "30s",
        "tasks": ["investigation", "ctem_correlation", "atlas_reasoning", "attack_path_analysis", "incident_report", "playbook_selection"],
        "fallback_model": "gpt-4o", "enabled": True, "extended_thinking": False,
    },
    {
        "model_id": "opus", "provider_id": "anthropic", "display_name": "Claude Opus (Tier 1+)",
        "model_name": "claude-opus-4-6", "tier": "tier_1_plus",
        "max_context": 200000, "max_tokens": 16384, "temperature": 0.2,
        "cost_input": 15.0, "cost_output": 75.0, "latency_slo": "60s",
        "tasks": ["complex_reasoning", "escalation_analysis", "multi_step_planning"],
        "fallback_model": "gpt-4o", "enabled": True, "extended_thinking": True,
    },
    {
        "model_id": "sonnet-batch", "provider_id": "anthropic", "display_name": "Claude Sonnet Batch (Tier 2)",
        "model_name": "claude-sonnet-4-5-20250929", "tier": "tier_2",
        "max_context": 200000, "max_tokens": 16384, "temperature": 0.3,
        "cost_input": 1.5, "cost_output": 7.5, "latency_slo": "async",
        "tasks": ["fp_pattern_training", "playbook_generation", "agent_red_team", "detection_rule_generation", "retrospective_analysis", "threat_landscape_summary"],
        "fallback_model": None, "enabled": True, "extended_thinking": False,
    },
    {
        "model_id": "gpt-4o-mini", "provider_id": "openai", "display_name": "GPT-4o Mini (Fallback T0)",
        "model_name": "gpt-4o-mini", "tier": "tier_0",
        "max_context": 128000, "max_tokens": 4096, "temperature": 0.1,
        "cost_input": 0.15, "cost_output": 0.60, "latency_slo": "5s",
        "tasks": [], "fallback_model": None, "enabled": True, "extended_thinking": False,
    },
    {
        "model_id": "gpt-4o", "provider_id": "openai", "display_name": "GPT-4o (Fallback T1/T1+)",
        "model_name": "gpt-4o", "tier": "tier_1",
        "max_context": 128000, "max_tokens": 16384, "temperature": 0.2,
        "cost_input": 2.5, "cost_output": 10.0, "latency_slo": "30s",
        "tasks": [], "fallback_model": None, "enabled": True, "extended_thinking": False,
    },
]


async def _get_providers() -> list[dict[str, Any]]:
    db = get_db()
    if db:
        try:
            rows = await db.fetch_many(
                "SELECT * FROM llm_providers ORDER BY display_name",
            )
            if rows:
                return [dict(r) for r in rows]
        except Exception:
            pass
    return DEMO_PROVIDERS


async def _get_models() -> list[dict[str, Any]]:
    db = get_db()
    if db:
        try:
            rows = await db.fetch_many(
                "SELECT * FROM llm_models ORDER BY tier, display_name",
            )
            if rows:
                return [dict(r) for r in rows]
        except Exception:
            pass
    return DEMO_MODELS


@router.get("/api/settings/providers")
async def api_list_providers() -> list[dict[str, Any]]:
    return await _get_providers()


@router.get("/api/settings/models")
async def api_list_models() -> list[dict[str, Any]]:
    return await _get_models()


class ProviderCreate(BaseModel):
    provider_id: str
    display_name: str
    api_base_url: str = ""
    api_key: str = ""


async def _ensure_llm_tables(db: Any) -> None:
    """Create llm_providers/llm_models tables if they don't exist."""
    await db.execute("""
        CREATE TABLE IF NOT EXISTS llm_providers (
            provider_id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
            api_base_url TEXT NOT NULL DEFAULT '', api_key_enc TEXT NOT NULL DEFAULT '',
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    await db.execute("""
        CREATE TABLE IF NOT EXISTS llm_models (
            model_id TEXT PRIMARY KEY,
            provider_id TEXT NOT NULL REFERENCES llm_providers(provider_id) ON DELETE CASCADE,
            display_name TEXT NOT NULL, model_name TEXT NOT NULL,
            tier TEXT NOT NULL DEFAULT 'tier_1', max_context INTEGER NOT NULL DEFAULT 200000,
            max_tokens INTEGER NOT NULL DEFAULT 8192, temperature REAL NOT NULL DEFAULT 0.2,
            cost_input REAL NOT NULL DEFAULT 0.0, cost_output REAL NOT NULL DEFAULT 0.0,
            latency_slo TEXT NOT NULL DEFAULT '30s', tasks TEXT[] NOT NULL DEFAULT '{}',
            fallback_model TEXT, enabled BOOLEAN NOT NULL DEFAULT TRUE,
            extended_thinking BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)


@router.post("/api/settings/providers")
async def api_create_provider(body: ProviderCreate) -> dict[str, Any]:
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not connected — run migrations first")
    try:
        await _ensure_llm_tables(db)
        masked = body.api_key[:8] + "...****" if len(body.api_key) > 8 else "****"
        await db.execute(
            "INSERT INTO llm_providers (provider_id, display_name, api_base_url, api_key_enc) "
            "VALUES ($1, $2, $3, $4) ON CONFLICT (provider_id) DO UPDATE SET "
            "display_name = EXCLUDED.display_name, api_base_url = EXCLUDED.api_base_url, "
            "api_key_enc = EXCLUDED.api_key_enc, updated_at = NOW()",
            body.provider_id, body.display_name, body.api_base_url, masked,
        )
        return {"status": "ok", "provider_id": body.provider_id}
    except Exception as exc:
        raise HTTPException(500, f"Database error: {exc}")


class ProviderUpdate(BaseModel):
    display_name: str | None = None
    api_base_url: str | None = None
    api_key: str | None = None
    enabled: bool | None = None


@router.put("/api/settings/providers/{provider_id}")
async def api_update_provider(provider_id: str, body: ProviderUpdate) -> dict[str, Any]:
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not connected — run migrations first")
    try:
        await _ensure_llm_tables(db)
        sets: list[str] = []
        vals: list[Any] = []
        idx = 1
        if body.display_name is not None:
            sets.append(f"display_name = ${idx}")
            vals.append(body.display_name)
            idx += 1
        if body.api_base_url is not None:
            sets.append(f"api_base_url = ${idx}")
            vals.append(body.api_base_url)
            idx += 1
        if body.api_key is not None:
            masked = body.api_key[:8] + "...****" if len(body.api_key) > 8 else "****"
            sets.append(f"api_key_enc = ${idx}")
            vals.append(masked)
            idx += 1
        if body.enabled is not None:
            sets.append(f"enabled = ${idx}")
            vals.append(body.enabled)
            idx += 1
        if not sets:
            raise HTTPException(400, "No fields to update")
        sets.append("updated_at = NOW()")
        vals.append(provider_id)
        await db.execute(
            f"UPDATE llm_providers SET {', '.join(sets)} WHERE provider_id = ${idx}",
            *vals,
        )
        return {"status": "ok", "provider_id": provider_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Database error: {exc}")


@router.delete("/api/settings/providers/{provider_id}")
async def api_delete_provider(provider_id: str) -> dict[str, Any]:
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not connected — run migrations first")
    try:
        await db.execute("DELETE FROM llm_providers WHERE provider_id = $1", provider_id)
        return {"status": "ok", "provider_id": provider_id}
    except Exception as exc:
        raise HTTPException(500, f"Database error: {exc}")


class ModelCreate(BaseModel):
    model_id: str
    provider_id: str
    display_name: str
    model_name: str
    tier: str = "tier_1"
    max_context: int = 200000
    max_tokens: int = 8192
    temperature: float = 0.2
    cost_input: float = 0.0
    cost_output: float = 0.0
    latency_slo: str = "30s"
    tasks: list[str] = []
    fallback_model: str | None = None
    extended_thinking: bool = False


@router.post("/api/settings/models")
async def api_create_model(body: ModelCreate) -> dict[str, Any]:
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not connected — run migrations first")
    try:
        await _ensure_llm_tables(db)
        await db.execute(
            "INSERT INTO llm_models (model_id, provider_id, display_name, model_name, tier, "
            "max_context, max_tokens, temperature, cost_input, cost_output, latency_slo, "
            "tasks, fallback_model, extended_thinking) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) "
            "ON CONFLICT (model_id) DO UPDATE SET "
            "provider_id=EXCLUDED.provider_id, display_name=EXCLUDED.display_name, "
            "model_name=EXCLUDED.model_name, tier=EXCLUDED.tier, max_context=EXCLUDED.max_context, "
            "max_tokens=EXCLUDED.max_tokens, temperature=EXCLUDED.temperature, "
            "cost_input=EXCLUDED.cost_input, cost_output=EXCLUDED.cost_output, "
            "latency_slo=EXCLUDED.latency_slo, tasks=EXCLUDED.tasks, "
            "fallback_model=EXCLUDED.fallback_model, extended_thinking=EXCLUDED.extended_thinking, "
            "updated_at=NOW()",
            body.model_id, body.provider_id, body.display_name, body.model_name,
            body.tier, body.max_context, body.max_tokens, body.temperature,
            body.cost_input, body.cost_output, body.latency_slo,
            body.tasks, body.fallback_model, body.extended_thinking,
        )
        return {"status": "ok", "model_id": body.model_id}
    except Exception as exc:
        raise HTTPException(500, f"Database error: {exc}")


class ModelUpdate(BaseModel):
    provider_id: str | None = None
    display_name: str | None = None
    model_name: str | None = None
    tier: str | None = None
    max_context: int | None = None
    max_tokens: int | None = None
    temperature: float | None = None
    cost_input: float | None = None
    cost_output: float | None = None
    latency_slo: str | None = None
    tasks: list[str] | None = None
    fallback_model: str | None = None
    extended_thinking: bool | None = None
    enabled: bool | None = None


@router.put("/api/settings/models/{model_id}")
async def api_update_model(model_id: str, body: ModelUpdate) -> dict[str, Any]:
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not connected — run migrations first")
    try:
        await _ensure_llm_tables(db)
        sets: list[str] = []
        vals: list[Any] = []
        idx = 1
        for field_name, value in body.model_dump(exclude_none=True).items():
            sets.append(f"{field_name} = ${idx}")
            vals.append(value)
            idx += 1
        if not sets:
            raise HTTPException(400, "No fields to update")
        sets.append("updated_at = NOW()")
        vals.append(model_id)
        await db.execute(
            f"UPDATE llm_models SET {', '.join(sets)} WHERE model_id = ${idx}",
            *vals,
        )
        return {"status": "ok", "model_id": model_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Database error: {exc}")


@router.delete("/api/settings/models/{model_id}")
async def api_delete_model(model_id: str) -> dict[str, Any]:
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not connected — run migrations first")
    try:
        await db.execute("DELETE FROM llm_models WHERE model_id = $1", model_id)
        return {"status": "ok", "model_id": model_id}
    except Exception as exc:
        raise HTTPException(500, f"Database error: {exc}")


@router.post("/api/settings/providers/demo/load")
async def api_load_demo_providers() -> dict[str, Any]:
    """Insert all demo providers and models into the database."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not connected")
    try:
        await _ensure_llm_tables(db)
        prov_count = 0
        for p in DEMO_PROVIDERS:
            await db.execute(
                "INSERT INTO llm_providers (provider_id, display_name, api_base_url, api_key_enc) "
                "VALUES ($1, $2, $3, $4) ON CONFLICT (provider_id) DO UPDATE SET "
                "display_name = EXCLUDED.display_name, api_base_url = EXCLUDED.api_base_url, "
                "api_key_enc = EXCLUDED.api_key_enc, updated_at = NOW()",
                p["provider_id"], p["display_name"], p["api_base_url"], p["api_key_enc"],
            )
            prov_count += 1
        mdl_count = 0
        for m in DEMO_MODELS:
            await db.execute(
                "INSERT INTO llm_models (model_id, provider_id, display_name, model_name, tier, "
                "max_context, max_tokens, temperature, cost_input, cost_output, latency_slo, "
                "tasks, fallback_model, extended_thinking) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) "
                "ON CONFLICT (model_id) DO UPDATE SET "
                "provider_id=EXCLUDED.provider_id, display_name=EXCLUDED.display_name, "
                "model_name=EXCLUDED.model_name, tier=EXCLUDED.tier, max_context=EXCLUDED.max_context, "
                "max_tokens=EXCLUDED.max_tokens, temperature=EXCLUDED.temperature, "
                "cost_input=EXCLUDED.cost_input, cost_output=EXCLUDED.cost_output, "
                "latency_slo=EXCLUDED.latency_slo, tasks=EXCLUDED.tasks, "
                "fallback_model=EXCLUDED.fallback_model, extended_thinking=EXCLUDED.extended_thinking, "
                "updated_at=NOW()",
                m["model_id"], m["provider_id"], m["display_name"], m["model_name"],
                m["tier"], m["max_context"], m["max_tokens"], m["temperature"],
                m["cost_input"], m["cost_output"], m["latency_slo"],
                m["tasks"], m.get("fallback_model"), m["extended_thinking"],
            )
            mdl_count += 1
        return {"status": "ok", "providers": prov_count, "models": mdl_count}
    except Exception as exc:
        raise HTTPException(500, f"Database error: {exc}")


@router.post("/api/settings/providers/demo/clear")
async def api_clear_demo_providers() -> dict[str, Any]:
    """Remove all providers and models from the database."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not connected")
    try:
        await _ensure_llm_tables(db)
        mdl = await db.fetch_one("SELECT count(*) AS cnt FROM llm_models")
        prov = await db.fetch_one("SELECT count(*) AS cnt FROM llm_providers")
        await db.execute("DELETE FROM llm_models")
        await db.execute("DELETE FROM llm_providers")
        return {
            "status": "ok",
            "deleted_models": mdl["cnt"] if mdl else 0,
            "deleted_providers": prov["cnt"] if prov else 0,
        }
    except Exception as exc:
        raise HTTPException(500, f"Database error: {exc}")


@router.post("/api/settings/demo/load-all")
async def api_load_all_demo() -> dict[str, Any]:
    """Load demo data into all in-memory stores and DB tables."""
    results: dict[str, str] = {}

    # LLM providers/models → DB
    db = get_db()
    if db:
        try:
            await _ensure_llm_tables(db)
            for p in DEMO_PROVIDERS:
                await db.execute(
                    "INSERT INTO llm_providers (provider_id, display_name, api_base_url, api_key_enc) "
                    "VALUES ($1,$2,$3,$4) ON CONFLICT (provider_id) DO UPDATE SET "
                    "display_name=EXCLUDED.display_name, api_base_url=EXCLUDED.api_base_url, "
                    "api_key_enc=EXCLUDED.api_key_enc, updated_at=NOW()",
                    p["provider_id"], p["display_name"], p["api_base_url"], p["api_key_enc"],
                )
            for m in DEMO_MODELS:
                await db.execute(
                    "INSERT INTO llm_models (model_id, provider_id, display_name, model_name, tier, "
                    "max_context, max_tokens, temperature, cost_input, cost_output, latency_slo, "
                    "tasks, fallback_model, extended_thinking) "
                    "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) "
                    "ON CONFLICT (model_id) DO UPDATE SET "
                    "provider_id=EXCLUDED.provider_id, display_name=EXCLUDED.display_name, "
                    "model_name=EXCLUDED.model_name, tier=EXCLUDED.tier, updated_at=NOW()",
                    m["model_id"], m["provider_id"], m["display_name"], m["model_name"],
                    m["tier"], m["max_context"], m["max_tokens"], m["temperature"],
                    m["cost_input"], m["cost_output"], m["latency_slo"],
                    m["tasks"], m.get("fallback_model"), m["extended_thinking"],
                )
            results["llm_providers"] = f"{len(DEMO_PROVIDERS)} providers, {len(DEMO_MODELS)} models"
        except Exception as exc:
            results["llm_providers"] = f"error: {exc}"
    else:
        results["llm_providers"] = "skipped (no DB)"

    # In-memory demo data — reimport originals
    try:
        from services.dashboard.routes.canary import DEMO_CANARY_SLICES, DEMO_PROMOTION_HISTORY
        # Reset canary slices to original state
        _orig_slices = [
            {"slice_id": "canary-001", "slice_name": "FP Auto-Close (Severity: Low)", "rule_family": "fp_auto_close", "dimension": "severity", "value": "LOW", "current_phase": "50%", "traffic_pct": 50, "success_rate": 98.7, "error_rate": 1.3, "start_date": "2026-02-01T09:00:00Z", "last_promotion_date": "2026-03-15T10:00:00Z", "auto_rollback_threshold": 95.0, "status": "active"},
            {"slice_id": "canary-002", "slice_name": "Enrichment Routing (All Tenants)", "rule_family": "enrichment_routing", "dimension": "tenant", "value": "all", "current_phase": "25%", "traffic_pct": 25, "success_rate": 96.2, "error_rate": 3.8, "start_date": "2026-02-15T11:00:00Z", "last_promotion_date": "2026-03-08T14:00:00Z", "auto_rollback_threshold": 95.0, "status": "active"},
            {"slice_id": "canary-003", "slice_name": "Alert Dedup (Production)", "rule_family": "alert_dedup", "dimension": "tenant", "value": "production", "current_phase": "100%", "traffic_pct": 100, "success_rate": 99.4, "error_rate": 0.6, "start_date": "2025-12-15T09:00:00Z", "last_promotion_date": "2026-02-28T16:00:00Z", "auto_rollback_threshold": 95.0, "status": "promoted"},
            {"slice_id": "canary-004", "slice_name": "Containment Actions (Critical)", "rule_family": "containment_actions", "dimension": "severity", "value": "CRITICAL", "current_phase": "shadow", "traffic_pct": 0, "success_rate": 89.1, "error_rate": 10.9, "start_date": "2026-03-20T08:00:00Z", "last_promotion_date": None, "auto_rollback_threshold": 95.0, "status": "active"},
            {"slice_id": "canary-005", "slice_name": "Severity Override (Medium)", "rule_family": "severity_override", "dimension": "severity", "value": "MEDIUM", "current_phase": "10%", "traffic_pct": 10, "success_rate": 91.8, "error_rate": 8.2, "start_date": "2026-03-10T10:00:00Z", "last_promotion_date": "2026-03-22T09:00:00Z", "auto_rollback_threshold": 95.0, "status": "active"},
        ]
        DEMO_CANARY_SLICES.clear()
        DEMO_CANARY_SLICES.extend(_orig_slices)
        results["canary_slices"] = f"{len(_orig_slices)} slices"
    except Exception as exc:
        results["canary_slices"] = f"error: {exc}"

    try:
        from services.dashboard.routes.shadow_mode import DEMO_SHADOW_ENTRIES
        results["shadow_mode"] = f"{len(DEMO_SHADOW_ENTRIES)} entries (in-memory, already loaded)"
    except Exception as exc:
        results["shadow_mode"] = f"error: {exc}"

    return {"status": "ok", "results": results}


@router.post("/api/settings/demo/clear-all")
async def api_clear_all_demo() -> dict[str, Any]:
    """Remove ALL demo data from DB tables and in-memory stores."""
    results: dict[str, str] = {}

    # DB tables
    db = get_db()
    if db:
        tables_to_clear = [
            ("llm_models", "LLM Models"),
            ("llm_providers", "LLM Providers"),
            ("investigation_state", "Investigations"),
            ("connectors", "Connectors"),
        ]
        for table, label in tables_to_clear:
            try:
                row = await db.fetch_one(f"SELECT count(*) AS cnt FROM {table}")
                cnt = row["cnt"] if row else 0
                await db.execute(f"DELETE FROM {table}")
                results[label] = f"{cnt} rows deleted"
            except Exception as exc:
                results[label] = f"skipped ({exc})"
    else:
        results["database"] = "not connected"

    # In-memory: canary slices
    try:
        from services.dashboard.routes.canary import DEMO_CANARY_SLICES, DEMO_PROMOTION_HISTORY
        cnt = len(DEMO_CANARY_SLICES)
        DEMO_CANARY_SLICES.clear()
        DEMO_PROMOTION_HISTORY.clear()
        results["Canary Slices"] = f"{cnt} cleared"
    except Exception as exc:
        results["Canary Slices"] = f"error: {exc}"

    # In-memory: shadow mode
    try:
        from services.dashboard.routes.shadow_mode import DEMO_SHADOW_ENTRIES
        cnt = len(DEMO_SHADOW_ENTRIES)
        DEMO_SHADOW_ENTRIES.clear()
        results["Shadow Mode"] = f"{cnt} cleared"
    except Exception as exc:
        results["Shadow Mode"] = f"error: {exc}"

    # In-memory: users
    try:
        from services.dashboard.routes.users import DEMO_USERS
        cnt = len(DEMO_USERS)
        DEMO_USERS.clear()
        results["Users"] = f"{cnt} cleared"
    except Exception as exc:
        results["Users"] = f"error: {exc}"

    # In-memory: playbooks
    try:
        from services.dashboard.routes.playbooks import DEMO_PLAYBOOKS
        cnt = len(DEMO_PLAYBOOKS)
        DEMO_PLAYBOOKS.clear()
        results["Playbooks"] = f"{cnt} cleared"
    except Exception as exc:
        results["Playbooks"] = f"error: {exc}"

    # In-memory: batch jobs
    try:
        from services.dashboard.routes.batch_jobs import DEMO_BATCH_JOBS
        cnt = len(DEMO_BATCH_JOBS)
        DEMO_BATCH_JOBS.clear()
        results["Batch Jobs"] = f"{cnt} cleared"
    except Exception as exc:
        results["Batch Jobs"] = f"error: {exc}"

    # In-memory: LLM health
    try:
        from services.dashboard.routes.llm_health import DEMO_PROVIDERS as LLM_HEALTH_PROVIDERS
        cnt = len(LLM_HEALTH_PROVIDERS)
        LLM_HEALTH_PROVIDERS.clear()
        results["LLM Health"] = f"{cnt} cleared"
    except Exception as exc:
        results["LLM Health"] = f"error: {exc}"

    return {"status": "ok", "results": results}


@router.post("/api/settings/run-migrations")
async def api_run_migrations() -> dict[str, Any]:
    """Run all pending SQL migrations against Postgres."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not connected")

    import glob
    migration_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "infra", "migrations",
    )
    migration_dir = os.path.normpath(migration_dir)
    files = sorted(glob.glob(os.path.join(migration_dir, "*.sql")))

    results: list[dict[str, str]] = []
    for f in files:
        name = os.path.basename(f)
        try:
            with open(f) as fh:
                sql = fh.read()
            await db.execute(sql)
            results.append({"file": name, "status": "ok"})
        except Exception as exc:
            results.append({"file": name, "status": f"error: {exc}"})

    return {"migrations": results, "count": len(results)}
