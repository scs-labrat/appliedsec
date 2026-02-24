-- ============================================================
-- ALUSKORT Audit DDL Migration 007 — Story 13.3
-- Creates audit_chain_state (per-tenant hash chain head)
-- and audit_verification_log (periodic integrity checks).
-- ============================================================

-- ============================================================
-- audit_chain_state — tracks per-tenant chain head
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_chain_state (
    tenant_id       TEXT PRIMARY KEY,
    last_sequence   BIGINT NOT NULL DEFAULT 0,
    last_hash       TEXT NOT NULL DEFAULT REPEAT('0', 64),
    last_timestamp  TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- audit_verification_log — records periodic chain checks
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_verification_log (
    id                BIGSERIAL PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    verified_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verification_type TEXT NOT NULL,
    records_checked   BIGINT NOT NULL,
    from_sequence     BIGINT NOT NULL,
    to_sequence       BIGINT NOT NULL,
    chain_valid       BOOLEAN NOT NULL,
    errors            JSONB DEFAULT '[]',
    duration_ms       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verify_tenant
    ON audit_verification_log (tenant_id, verified_at DESC);
