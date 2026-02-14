-- ============================================================
-- ALUSKORT CTEM DDL Migration 002
-- CTEM Exposures, Validations, and Remediations tables.
-- ============================================================

CREATE TABLE IF NOT EXISTS ctem_exposures (
    id                  BIGSERIAL PRIMARY KEY,
    exposure_key        TEXT NOT NULL UNIQUE,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_tool         TEXT NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT,
    severity            TEXT NOT NULL,
    original_severity   TEXT NOT NULL,
    asset_id            TEXT NOT NULL,
    asset_type          TEXT NOT NULL,
    asset_zone          TEXT NOT NULL,
    exploitability_score REAL NOT NULL,
    physical_consequence TEXT NOT NULL,
    ctem_score          REAL NOT NULL,
    atlas_technique     TEXT DEFAULT '',
    attack_technique    TEXT DEFAULT '',
    threat_model_ref    TEXT DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'Open',
    assigned_to         TEXT DEFAULT '',
    sla_deadline        TIMESTAMPTZ,
    remediation_guidance TEXT DEFAULT '',
    evidence_url        TEXT DEFAULT '',
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ctem_exp_key ON ctem_exposures (exposure_key);
CREATE INDEX IF NOT EXISTS idx_ctem_exp_status ON ctem_exposures (status, severity);
CREATE INDEX IF NOT EXISTS idx_ctem_exp_sla ON ctem_exposures (sla_deadline)
    WHERE status IN ('Open', 'InProgress');
CREATE INDEX IF NOT EXISTS idx_ctem_exp_asset ON ctem_exposures (asset_id, asset_zone);

CREATE TABLE IF NOT EXISTS ctem_validations (
    id                      BIGSERIAL PRIMARY KEY,
    validation_id           TEXT NOT NULL UNIQUE,
    exposure_id             TEXT NOT NULL,
    campaign_id             TEXT NOT NULL,
    ts                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    validation_type         TEXT NOT NULL,
    exploitable             BOOLEAN NOT NULL DEFAULT FALSE,
    exploit_complexity      TEXT NOT NULL DEFAULT 'unknown',
    attack_path             TEXT,
    physical_consequence_demonstrated BOOLEAN NOT NULL DEFAULT FALSE,
    detection_evaded        BOOLEAN NOT NULL DEFAULT FALSE,
    detection_rules_tested  JSONB DEFAULT '[]',
    detection_gaps          JSONB DEFAULT '[]',
    tester                  TEXT DEFAULT '',
    evidence_url            TEXT DEFAULT '',
    tenant_id               TEXT NOT NULL DEFAULT 'default',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ctem_remediations (
    id                  BIGSERIAL PRIMARY KEY,
    remediation_id      TEXT NOT NULL UNIQUE,
    exposure_id         TEXT NOT NULL,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status              TEXT NOT NULL DEFAULT 'Assigned',
    assigned_to         TEXT NOT NULL,
    assigned_date       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sla_deadline        TIMESTAMPTZ,
    fix_deployed_date   TIMESTAMPTZ,
    verified_date       TIMESTAMPTZ,
    verified_by         TEXT DEFAULT '',
    sla_breached        BOOLEAN NOT NULL DEFAULT FALSE,
    escalation_level    TEXT DEFAULT '',
    fix_description     TEXT DEFAULT '',
    pull_request_url    TEXT DEFAULT '',
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
