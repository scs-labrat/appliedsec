-- ============================================================
-- ALUSKORT Dashboard Sessions — Story 17-8
-- MVP simple token store for dashboard user sessions.
-- ============================================================

CREATE TABLE IF NOT EXISTS dashboard_sessions (
    session_id  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'analyst',
    tenant_id   TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON dashboard_sessions(user_id);
