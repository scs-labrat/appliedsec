-- 009_embedding_migration.sql — Story 14.6
-- Tracks embedding model migration progress with checkpoint/resume.

CREATE TABLE IF NOT EXISTS embedding_migration (
    id BIGSERIAL PRIMARY KEY,
    old_model TEXT NOT NULL,
    new_model TEXT NOT NULL,
    collection TEXT NOT NULL,
    last_point_id TEXT DEFAULT '',
    points_migrated BIGINT DEFAULT 0,
    points_total BIGINT DEFAULT 0,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status TEXT DEFAULT 'in_progress'
);
