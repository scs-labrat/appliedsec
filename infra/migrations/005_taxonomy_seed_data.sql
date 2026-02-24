-- ============================================================
-- ALUSKORT DDL Migration 005: Taxonomy Seed Data
-- Story 12.1 — Populate taxonomy_ids with ATT&CK + ATLAS IDs
-- ============================================================

-- Metadata: version tracking for taxonomy
-- The taxonomy_version can be queried by services to record
-- which ATT&CK/ATLAS version was active during each decision.

-- ============================================================
-- ATT&CK v16.1 Technique IDs (framework = 'attack')
-- Representative set for initial deployment. Full MITRE import
-- should be done via the batch scheduler's MITRE sync job.
-- ============================================================

INSERT INTO taxonomy_ids (technique_id, framework, name, is_subtechnique, parent_id, deprecated)
VALUES
  -- Execution
  ('T1059', 'attack', 'Command and Scripting Interpreter', FALSE, NULL, FALSE),
  ('T1059.001', 'attack', 'PowerShell', TRUE, 'T1059', FALSE),
  ('T1059.003', 'attack', 'Windows Command Shell', TRUE, 'T1059', FALSE),
  ('T1059.004', 'attack', 'Unix Shell', TRUE, 'T1059', FALSE),
  ('T1059.006', 'attack', 'Python', TRUE, 'T1059', FALSE),
  -- Persistence / Valid Accounts
  ('T1078', 'attack', 'Valid Accounts', FALSE, NULL, FALSE),
  ('T1078.001', 'attack', 'Default Accounts', TRUE, 'T1078', FALSE),
  ('T1078.002', 'attack', 'Domain Accounts', TRUE, 'T1078', FALSE),
  ('T1078.003', 'attack', 'Local Accounts', TRUE, 'T1078', FALSE),
  ('T1078.004', 'attack', 'Cloud Accounts', TRUE, 'T1078', FALSE),
  -- Initial Access / Phishing
  ('T1566', 'attack', 'Phishing', FALSE, NULL, FALSE),
  ('T1566.001', 'attack', 'Spearphishing Attachment', TRUE, 'T1566', FALSE),
  ('T1566.002', 'attack', 'Spearphishing Link', TRUE, 'T1566', FALSE),
  -- Credential Access
  ('T1003', 'attack', 'OS Credential Dumping', FALSE, NULL, FALSE),
  ('T1003.001', 'attack', 'LSASS Memory', TRUE, 'T1003', FALSE),
  -- Lateral Movement
  ('T1021', 'attack', 'Remote Services', FALSE, NULL, FALSE),
  ('T1021.001', 'attack', 'Remote Desktop Protocol', TRUE, 'T1021', FALSE),
  ('T1021.002', 'attack', 'SMB/Windows Admin Shares', TRUE, 'T1021', FALSE),
  -- Defense Evasion
  ('T1070', 'attack', 'Indicator Removal', FALSE, NULL, FALSE),
  ('T1070.001', 'attack', 'Clear Windows Event Logs', TRUE, 'T1070', FALSE),
  -- Exfiltration
  ('T1041', 'attack', 'Exfiltration Over C2 Channel', FALSE, NULL, FALSE),
  -- Impact
  ('T1486', 'attack', 'Data Encrypted for Impact', FALSE, NULL, FALSE),
  -- Collection
  ('T1005', 'attack', 'Data from Local System', FALSE, NULL, FALSE),
  -- Discovery
  ('T1087', 'attack', 'Account Discovery', FALSE, NULL, FALSE),
  ('T1087.001', 'attack', 'Local Account', TRUE, 'T1087', FALSE),
  ('T1087.002', 'attack', 'Domain Account', TRUE, 'T1087', FALSE)
ON CONFLICT (technique_id) DO NOTHING;


-- ============================================================
-- ATLAS Technique IDs (framework = 'atlas')
-- MITRE ATLAS v4.x — adversarial ML techniques
-- ============================================================

INSERT INTO taxonomy_ids (technique_id, framework, name, is_subtechnique, parent_id, deprecated)
VALUES
  ('AML.T0000', 'atlas', 'ML Model Access', FALSE, NULL, FALSE),
  ('AML.T0001', 'atlas', 'ML Attack Staging', FALSE, NULL, FALSE),
  ('AML.T0002', 'atlas', 'ML Supply Chain Compromise', FALSE, NULL, FALSE),
  ('AML.T0003', 'atlas', 'Data Collection', FALSE, NULL, FALSE),
  ('AML.T0004', 'atlas', 'Model Replication', FALSE, NULL, FALSE),
  ('AML.T0005', 'atlas', 'Create Proxy Model', FALSE, NULL, FALSE),
  ('AML.T0006', 'atlas', 'Active Scanning', FALSE, NULL, FALSE),
  ('AML.T0007', 'atlas', 'Discover ML Model Ontology', FALSE, NULL, FALSE),
  ('AML.T0010', 'atlas', 'ML Model Inference API Access', FALSE, NULL, FALSE),
  ('AML.T0011', 'atlas', 'User Execution', FALSE, NULL, FALSE),
  ('AML.T0012', 'atlas', 'Valid Accounts', FALSE, NULL, FALSE),
  ('AML.T0015', 'atlas', 'Evade ML Model', FALSE, NULL, FALSE),
  ('AML.T0016', 'atlas', 'Obtain Capabilities', FALSE, NULL, FALSE),
  ('AML.T0017', 'atlas', 'Develop Capabilities', FALSE, NULL, FALSE),
  ('AML.T0018', 'atlas', 'Backdoor ML Model', FALSE, NULL, FALSE),
  ('AML.T0019', 'atlas', 'Publish Poisoned Datasets', FALSE, NULL, FALSE),
  ('AML.T0020', 'atlas', 'Poison Training Data', FALSE, NULL, FALSE),
  ('AML.T0024', 'atlas', 'Exfiltration via ML Inference API', FALSE, NULL, FALSE),
  ('AML.T0025', 'atlas', 'Exfiltration via Cyber Means', FALSE, NULL, FALSE),
  ('AML.T0029', 'atlas', 'Denial of ML Service', FALSE, NULL, FALSE),
  ('AML.T0031', 'atlas', 'Erode ML Model Integrity', FALSE, NULL, FALSE),
  ('AML.T0034', 'atlas', 'Cost Harvesting', FALSE, NULL, FALSE),
  ('AML.T0035', 'atlas', 'ML Intellectual Property Theft', FALSE, NULL, FALSE),
  ('AML.T0036', 'atlas', 'Data Poisoning', FALSE, NULL, FALSE),
  ('AML.T0040', 'atlas', 'ML Model Inference API Access', FALSE, NULL, FALSE),
  ('AML.T0042', 'atlas', 'Verify Attack', FALSE, NULL, FALSE),
  ('AML.T0043', 'atlas', 'Craft Adversarial Data', FALSE, NULL, FALSE),
  ('AML.T0044', 'atlas', 'Full ML Model Access', FALSE, NULL, FALSE),
  ('AML.T0047', 'atlas', 'ML-Enabled Product or Service', FALSE, NULL, FALSE),
  ('AML.T0048', 'atlas', 'Pre-Trained Model', FALSE, NULL, FALSE),
  ('AML.T0050', 'atlas', 'Command and Scripting Interpreter', FALSE, NULL, FALSE),
  ('AML.T0051', 'atlas', 'LLM Prompt Injection', FALSE, NULL, FALSE),
  ('AML.T0052', 'atlas', 'Phishing', FALSE, NULL, FALSE),
  ('AML.T0053', 'atlas', 'Data from Information Repositories', FALSE, NULL, FALSE),
  ('AML.T0054', 'atlas', 'LLM Jailbreak', FALSE, NULL, FALSE)
ON CONFLICT (technique_id) DO NOTHING;


-- ============================================================
-- Version tracking metadata
-- Used by ContextGateway to populate taxonomy_version in
-- DecisionEntry and quarantine audit events.
-- ============================================================

CREATE TABLE IF NOT EXISTS taxonomy_metadata (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO taxonomy_metadata (key, value) VALUES
  ('attack_version', '16.1'),
  ('atlas_version', '4.5.2'),
  ('last_sync', NOW()::TEXT)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();
