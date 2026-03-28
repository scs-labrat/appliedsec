-- 012: Connector configuration table for SIEM event ingestion
-- Stores connection settings per tenant for each adapter type.

CREATE TABLE IF NOT EXISTS connectors (
    connector_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    name            TEXT NOT NULL,
    adapter_type    TEXT NOT NULL,           -- elastic, splunk, sentinel
    connector_mode  TEXT NOT NULL DEFAULT 'polling', -- polling, webhook, eventhub
    config          JSONB NOT NULL DEFAULT '{}',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors (tenant_id);
CREATE INDEX IF NOT EXISTS idx_connectors_adapter ON connectors (adapter_type);
