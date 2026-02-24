-- 008_fp_governance.sql — Story 14.4
-- Adds governance columns to fp_patterns for two-person approval,
-- 90-day expiry, reaffirmation, and blast-radius scoping.

ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS approved_by_1 TEXT DEFAULT '';
ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS approved_by_2 TEXT DEFAULT '';
ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS expiry_date TIMESTAMPTZ;
ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS reaffirmed_date TIMESTAMPTZ;
ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS reaffirmed_by TEXT DEFAULT '';
ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS scope_rule_family TEXT DEFAULT '';
ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS scope_tenant_id TEXT DEFAULT '';
ALTER TABLE fp_patterns ADD COLUMN IF NOT EXISTS scope_asset_class TEXT DEFAULT '';
