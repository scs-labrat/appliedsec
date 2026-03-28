-- 013: LLM Provider / Model configuration
-- Stores provider credentials and model configurations for the LLM Router

CREATE TABLE IF NOT EXISTS llm_providers (
    provider_id     TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    api_base_url    TEXT NOT NULL DEFAULT '',
    api_key_enc     TEXT NOT NULL DEFAULT '',          -- encrypted or masked
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS llm_models (
    model_id        TEXT PRIMARY KEY,
    provider_id     TEXT NOT NULL REFERENCES llm_providers(provider_id) ON DELETE CASCADE,
    display_name    TEXT NOT NULL,
    model_name      TEXT NOT NULL,                     -- actual API model identifier
    tier            TEXT NOT NULL DEFAULT 'tier_1',    -- tier_0, tier_1, tier_1_plus, tier_2
    max_context     INTEGER NOT NULL DEFAULT 200000,
    max_tokens      INTEGER NOT NULL DEFAULT 8192,
    temperature     REAL NOT NULL DEFAULT 0.2,
    cost_input      REAL NOT NULL DEFAULT 0.0,         -- per 1M tokens
    cost_output     REAL NOT NULL DEFAULT 0.0,         -- per 1M tokens
    latency_slo     TEXT NOT NULL DEFAULT '30s',
    tasks           TEXT[] NOT NULL DEFAULT '{}',
    fallback_model  TEXT,                              -- model_id of fallback
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    extended_thinking BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_llm_models_provider ON llm_models (provider_id);
CREATE INDEX IF NOT EXISTS idx_llm_models_tier ON llm_models (tier);
