-- ============================================================
-- ALUSKORT Core DDL Migration 001
-- Creates all Postgres tables, indexes, and constraints.
-- ============================================================

-- ============================================================
-- MITRE Techniques (from rag-design.md Section 2.3)
-- ============================================================
CREATE TABLE IF NOT EXISTS mitre_techniques (
    doc_id          TEXT PRIMARY KEY,
    doc_type        TEXT NOT NULL DEFAULT 'mitre_technique',
    technique_id    TEXT NOT NULL UNIQUE,
    technique_name  TEXT NOT NULL,
    parent_technique TEXT,
    tactic          TEXT[] NOT NULL,
    description     TEXT NOT NULL,
    detection       TEXT,
    platforms       TEXT[],
    data_sources    TEXT[],
    log_tables      TEXT[],
    kill_chain_phase TEXT,
    severity_baseline TEXT DEFAULT 'medium',
    groups_using    TEXT[],
    software_using  TEXT[],
    related_techniques TEXT[],
    attack_version  TEXT,
    last_updated    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mitre_technique_id ON mitre_techniques (technique_id);
CREATE INDEX IF NOT EXISTS idx_mitre_tactic ON mitre_techniques USING GIN (tactic);
CREATE INDEX IF NOT EXISTS idx_mitre_platforms ON mitre_techniques USING GIN (platforms);
CREATE INDEX IF NOT EXISTS idx_mitre_groups ON mitre_techniques USING GIN (groups_using);

-- ============================================================
-- MITRE Groups
-- ============================================================
CREATE TABLE IF NOT EXISTS mitre_groups (
    doc_id          TEXT PRIMARY KEY,
    doc_type        TEXT NOT NULL DEFAULT 'mitre_group',
    group_id        TEXT NOT NULL UNIQUE,
    group_name      TEXT NOT NULL,
    aliases         TEXT[],
    description     TEXT NOT NULL,
    techniques_used JSONB,
    software_used   TEXT[],
    target_sectors  TEXT[],
    references      TEXT[],
    last_updated    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Taxonomy IDs (for Context Gateway validation)
-- ============================================================
CREATE TABLE IF NOT EXISTS taxonomy_ids (
    technique_id    TEXT PRIMARY KEY,
    framework       TEXT NOT NULL,
    name            TEXT NOT NULL,
    is_subtechnique BOOLEAN DEFAULT FALSE,
    parent_id       TEXT,
    deprecated      BOOLEAN DEFAULT FALSE,
    last_updated    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Threat Intel IOCs (from rag-design.md Section 3.2)
-- ============================================================
CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    doc_id              TEXT PRIMARY KEY,
    indicator_type      TEXT NOT NULL,
    indicator_value     TEXT NOT NULL,
    confidence          INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    severity            TEXT,
    associated_campaigns TEXT[],
    associated_groups   TEXT[],
    mitre_techniques    TEXT[],
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    sources             TEXT[] NOT NULL,
    context             TEXT,
    expiry              TIMESTAMPTZ,
    tags                TEXT[],
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ti_ioc_value ON threat_intel_iocs (indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS idx_ti_ioc_campaigns ON threat_intel_iocs USING GIN (associated_campaigns);
CREATE INDEX IF NOT EXISTS idx_ti_ioc_techniques ON threat_intel_iocs USING GIN (mitre_techniques);
CREATE INDEX IF NOT EXISTS idx_ti_ioc_expiry ON threat_intel_iocs (expiry);

-- ============================================================
-- Playbooks (from rag-design.md Section 4.2)
-- ============================================================
CREATE TABLE IF NOT EXISTS playbooks (
    doc_id              TEXT PRIMARY KEY,
    title               TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity_applicable TEXT[] NOT NULL,
    trigger_conditions  JSONB,
    alert_products      TEXT[],
    mitre_techniques    TEXT[] NOT NULL,
    escalation_criteria JSONB,
    resolution_criteria JSONB,
    source              TEXT DEFAULT 'manual',
    version             TEXT DEFAULT '1.0',
    review_status       TEXT DEFAULT 'draft',
    approved_by         TEXT,
    last_updated        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS playbook_steps (
    playbook_id     TEXT NOT NULL REFERENCES playbooks(doc_id),
    step_number     INTEGER NOT NULL,
    action          TEXT NOT NULL,
    description     TEXT NOT NULL,
    queries         JSONB,
    automated       BOOLEAN DEFAULT FALSE,
    requires_approval BOOLEAN DEFAULT FALSE,
    approval_reason TEXT,
    assigned_agent  TEXT,
    PRIMARY KEY (playbook_id, step_number)
);

-- ============================================================
-- Incident Memory (from rag-design.md Section 5.2)
-- ============================================================
CREATE TABLE IF NOT EXISTS incident_memory (
    doc_id              TEXT PRIMARY KEY,
    incident_id         TEXT NOT NULL,
    alert_ids           TEXT[] NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL,
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    initial_classification TEXT,
    final_classification   TEXT,
    corrected_by          TEXT,
    correction_reason     TEXT,
    alert_product       TEXT,
    alert_name          TEXT NOT NULL,
    alert_source        TEXT NOT NULL,
    severity            TEXT NOT NULL,
    entities            JSONB NOT NULL,
    mitre_techniques    TEXT[],
    investigation_summary TEXT NOT NULL,
    decision_chain      JSONB,
    outcome             TEXT NOT NULL,
    analyst_feedback    JSONB,
    lessons_learned     TEXT,
    similar_to          TEXT[],
    tags                TEXT[],
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_timestamp ON incident_memory (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incident_tenant ON incident_memory (tenant_id);
CREATE INDEX IF NOT EXISTS idx_incident_techniques ON incident_memory USING GIN (mitre_techniques);
CREATE INDEX IF NOT EXISTS idx_incident_outcome ON incident_memory (outcome);

-- ============================================================
-- FP Patterns (from rag-design.md Section 5.5)
-- ============================================================
CREATE TABLE IF NOT EXISTS fp_patterns (
    pattern_id          TEXT PRIMARY KEY,
    pattern_name        TEXT NOT NULL,
    alert_names         TEXT[] NOT NULL,
    conditions          JSONB NOT NULL,
    confidence_threshold FLOAT NOT NULL DEFAULT 0.90,
    auto_close          BOOLEAN DEFAULT TRUE,
    occurrences         INTEGER DEFAULT 0,
    last_occurrence     TIMESTAMPTZ,
    approved_by         TEXT NOT NULL,
    approval_date       TIMESTAMPTZ NOT NULL,
    status              TEXT DEFAULT 'active',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fp_alert_names ON fp_patterns USING GIN (alert_names);

-- ============================================================
-- Org Context (from rag-design.md Section 6.2)
-- ============================================================
CREATE TABLE IF NOT EXISTS org_context (
    doc_id              TEXT PRIMARY KEY,
    entity_type         TEXT NOT NULL,
    entity_name         TEXT NOT NULL,
    criticality         TEXT DEFAULT 'medium',
    role                TEXT,
    network_segment     TEXT,
    owner               TEXT,
    business_unit       TEXT,
    maintenance_window  TEXT,
    normal_services     TEXT[],
    normal_admin_users  TEXT[],
    alert_suppression_rules JSONB,
    tags                TEXT[],
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    last_updated        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
