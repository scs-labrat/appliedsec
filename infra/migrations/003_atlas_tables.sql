-- ============================================================
-- ALUSKORT ATLAS Telemetry DDL Migration 003
-- Orbital inference logs, edge telemetry, audit tables.
-- ============================================================

CREATE TABLE IF NOT EXISTS orbital_inference_logs (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    edge_node_id    TEXT NOT NULL,
    model_version   TEXT NOT NULL,
    input_hash      TEXT NOT NULL,
    output_hash     TEXT NOT NULL,
    physics_check_result TEXT NOT NULL,
    confidence_score     REAL NOT NULL,
    inference_latency_ms INTEGER NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS edge_node_telemetry (
    id                  BIGSERIAL PRIMARY KEY,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    edge_node_id        TEXT NOT NULL,
    model_weight_hash   TEXT NOT NULL,
    disk_integrity      TEXT,
    boot_attestation    TEXT,
    active_connections  INTEGER NOT NULL DEFAULT 0,
    cpu_utilisation     REAL NOT NULL DEFAULT 0.0,
    memory_utilisation  REAL NOT NULL DEFAULT 0.0,
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    ingested_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS databricks_audit (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id         TEXT NOT NULL,
    action          TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    source_ip       INET,
    workspace_id    TEXT,
    cluster_name    TEXT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS model_registry (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id         TEXT NOT NULL,
    action          TEXT NOT NULL,
    model_name      TEXT NOT NULL,
    model_version   TEXT,
    model_hash      TEXT,
    stage           TEXT,
    approved_by     TEXT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Investigation state table (for GraphState persistence)
-- ============================================================
CREATE TABLE IF NOT EXISTS investigation_state (
    investigation_id TEXT PRIMARY KEY,
    state           TEXT NOT NULL DEFAULT 'received',
    alert_id        TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    graph_state     JSONB NOT NULL DEFAULT '{}',
    confidence      REAL NOT NULL DEFAULT 0.0,
    llm_calls       INTEGER NOT NULL DEFAULT 0,
    total_cost_usd  REAL NOT NULL DEFAULT 0.0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inv_state ON investigation_state (state);
CREATE INDEX IF NOT EXISTS idx_inv_tenant ON investigation_state (tenant_id);
CREATE INDEX IF NOT EXISTS idx_inv_alert ON investigation_state (alert_id);

-- ============================================================
-- Inference logs (for cost tracking and monitoring)
-- ============================================================
CREATE TABLE IF NOT EXISTS inference_logs (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    investigation_id TEXT,
    model_tier      TEXT NOT NULL,
    model_id        TEXT NOT NULL,
    input_tokens    INTEGER NOT NULL DEFAULT 0,
    output_tokens   INTEGER NOT NULL DEFAULT 0,
    cached_tokens   INTEGER NOT NULL DEFAULT 0,
    cost_usd        REAL NOT NULL DEFAULT 0.0,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    task_type       TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_inference_ts ON inference_logs (ts DESC);
CREATE INDEX IF NOT EXISTS idx_inference_tenant ON inference_logs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_inference_model ON inference_logs (model_tier);
