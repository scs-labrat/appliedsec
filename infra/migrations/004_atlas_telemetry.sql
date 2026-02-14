-- Story 9.3: ATLAS telemetry tables for detection rules
-- All tables: TIMESTAMPTZ ts, TEXT tenant_id, TIMESTAMPTZ ingested_at

-- 1. Orbital inference engine logs
CREATE TABLE IF NOT EXISTS orbital_inference_logs (
    ts              TIMESTAMPTZ NOT NULL,
    edge_node_id    TEXT NOT NULL,
    model_version   TEXT,
    input_hash      TEXT,
    output_hash     TEXT,
    physics_check_result TEXT,
    confidence_score DOUBLE PRECISION,
    inference_latency_ms DOUBLE PRECISION,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_inference_ts ON orbital_inference_logs (ts);
CREATE INDEX IF NOT EXISTS idx_inference_node_ts ON orbital_inference_logs (edge_node_id, ts);

-- 2. Physics validation oracle logs
CREATE TABLE IF NOT EXISTS orbital_physics_oracle (
    ts              TIMESTAMPTZ NOT NULL,
    edge_node_id    TEXT NOT NULL,
    constraint_id   TEXT,
    check_result    TEXT,
    latency_ms      DOUBLE PRECISION,
    error_state     TEXT,
    input_hash      TEXT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_oracle_ts ON orbital_physics_oracle (ts);
CREATE INDEX IF NOT EXISTS idx_oracle_node_ts ON orbital_physics_oracle (edge_node_id, ts);

-- 3. NL query interface logs
CREATE TABLE IF NOT EXISTS orbital_nl_query_logs (
    ts              TIMESTAMPTZ NOT NULL,
    user_id         TEXT NOT NULL,
    session_id      TEXT,
    query_text      TEXT,
    response_summary TEXT,
    tool_calls_made INT DEFAULT 0,
    safety_filter_triggered BOOLEAN DEFAULT FALSE,
    token_count     INT DEFAULT 0,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_nlquery_ts ON orbital_nl_query_logs (ts);
CREATE INDEX IF NOT EXISTS idx_nlquery_user_ts ON orbital_nl_query_logs (user_id, ts);

-- 4. API access logs
CREATE TABLE IF NOT EXISTS orbital_api_logs (
    ts              TIMESTAMPTZ NOT NULL,
    caller_ip       TEXT,
    caller_identity TEXT NOT NULL,
    endpoint        TEXT,
    method          TEXT,
    response_code   INT,
    request_payload_size INT DEFAULT 0,
    response_payload_size INT DEFAULT 0,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_ts ON orbital_api_logs (ts);
CREATE INDEX IF NOT EXISTS idx_api_caller_ts ON orbital_api_logs (caller_identity, ts);

-- 5. Edge node telemetry
CREATE TABLE IF NOT EXISTS edge_node_telemetry (
    ts              TIMESTAMPTZ NOT NULL,
    edge_node_id    TEXT NOT NULL,
    model_weight_hash TEXT,
    disk_integrity  TEXT,
    boot_attestation TEXT,
    active_connections INT DEFAULT 0,
    cpu_utilisation DOUBLE PRECISION DEFAULT 0,
    memory_utilisation DOUBLE PRECISION DEFAULT 0,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_edge_ts ON edge_node_telemetry (ts);
CREATE INDEX IF NOT EXISTS idx_edge_node_ts ON edge_node_telemetry (edge_node_id, ts);

-- 6. Databricks workspace audit logs
CREATE TABLE IF NOT EXISTS databricks_audit (
    ts              TIMESTAMPTZ NOT NULL,
    user_id         TEXT NOT NULL,
    action          TEXT NOT NULL,
    target_resource TEXT,
    source_ip       TEXT,
    workspace_id    TEXT,
    cluster_name    TEXT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_databricks_ts ON databricks_audit (ts);
CREATE INDEX IF NOT EXISTS idx_databricks_user_ts ON databricks_audit (user_id, ts);
CREATE INDEX IF NOT EXISTS idx_databricks_action_ts ON databricks_audit (action, ts);

-- 7. MLflow model registry events
CREATE TABLE IF NOT EXISTS model_registry (
    ts              TIMESTAMPTZ NOT NULL,
    user_id         TEXT NOT NULL,
    action          TEXT NOT NULL,
    model_name      TEXT,
    model_version   TEXT,
    model_hash      TEXT,
    stage           TEXT,
    approved_by     TEXT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_registry_ts ON model_registry (ts);
CREATE INDEX IF NOT EXISTS idx_registry_model_ts ON model_registry (model_name, ts);

-- 8. CI/CD pipeline audit
CREATE TABLE IF NOT EXISTS cicd_audit (
    ts              TIMESTAMPTZ NOT NULL,
    pipeline_id     TEXT NOT NULL,
    trigger_type    TEXT,
    commit_hash     TEXT,
    dependency_changes TEXT,
    tests_passed    INT DEFAULT 0,
    tests_failed    INT DEFAULT 0,
    deployer        TEXT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cicd_ts ON cicd_audit (ts);
CREATE INDEX IF NOT EXISTS idx_cicd_pipeline_ts ON cicd_audit (pipeline_id, ts);

-- 9. Partner integration API logs
CREATE TABLE IF NOT EXISTS partner_api_logs (
    ts              TIMESTAMPTZ NOT NULL,
    partner_id      TEXT NOT NULL,
    partner_name    TEXT,
    direction       TEXT,
    data_type       TEXT,
    payload_size    INT DEFAULT 0,
    response_code   INT,
    mtls_verified   BOOLEAN DEFAULT TRUE,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_partner_ts ON partner_api_logs (ts);
CREATE INDEX IF NOT EXISTS idx_partner_id_ts ON partner_api_logs (partner_id, ts);

-- 10. OPC-UA communication telemetry
CREATE TABLE IF NOT EXISTS opcua_telemetry (
    ts              TIMESTAMPTZ NOT NULL,
    edge_node_id    TEXT NOT NULL,
    sensor_count    INT DEFAULT 0,
    data_points_received INT DEFAULT 0,
    connection_state TEXT,
    auth_method     TEXT,
    protocol_violations INT DEFAULT 0,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_opcua_ts ON opcua_telemetry (ts);
CREATE INDEX IF NOT EXISTS idx_opcua_node_ts ON opcua_telemetry (edge_node_id, ts);
