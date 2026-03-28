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
